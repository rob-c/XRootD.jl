using XRootD.Storage
using XRootD.Storage:
    storage_for,
    storage_open,
    storage_read,
    storage_write,
    storage_stat,
    StorageError,
    StorageReader,
    StorageWriter,
    LocalStream,
    RangeReader,
    PipeWriter,
    s3_part_size,
    S3_PART_SIZE,
    S3_MIN_PART_SIZE,
    S3_MAX_PARTS,
    WEB_PUT_SPILL
using HTTP: HTTP

"""
An object store over HTTP, recording what each `PUT` looked like on the wire.
The framing is the point of the streaming upload path, so it is asserted
rather than assumed: a `Content-Length` and no chunked encoding is what an
XrdHttp or WebDAV endpoint will accept.
"""
function stream_fixture(f::Function)
    store = Dict{String,Vector{UInt8}}()
    puts = Vector{NamedTuple{(:target, :cl, :te, :n),Tuple{String,String,String,Int}}}()
    refuse = Ref("")

    server = HTTP.serve!("127.0.0.1", 0; verbose=false) do req
        hdr(name) = something(HTTP.header(req, name, nothing), "")
        if req.method == "PUT"
            push!(
                puts,
                (
                    target=req.target,
                    cl=hdr("Content-Length"),
                    te=hdr("Transfer-Encoding"),
                    n=length(req.body),
                ),
            )
            req.target == refuse[] && return HTTP.Response(403, "")
            store[req.target] = copy(req.body)
            return HTTP.Response(201, "")
        elseif req.method == "HEAD"
            body = get(store, req.target, nothing)
            body === nothing && return HTTP.Response(404, "")
            # An endpoint serving the object chunked has no length to give;
            # `/nolength/` is this fixture's spelling of one.
            startswith(req.target, "/nolength/") && return HTTP.Response(200, "")
            # HTTP.jl's own server recomputes Content-Length for a body-less
            # HEAD, so the body travels and the server strips it.
            return HTTP.Response(200, body)
        elseif req.method == "GET"
            body = get(store, req.target, nothing)
            body === nothing && return HTTP.Response(404, "")
            m = match(r"bytes=(\d+)-(\d*)", hdr("Range"))
            m === nothing && return HTTP.Response(200, body)
            lo = parse(Int, m.captures[1]) + 1
            hi = m.captures[2] == "" ? length(body) : parse(Int, m.captures[2]) + 1
            lo > length(body) && return HTTP.Response(206, UInt8[])
            return HTTP.Response(206, body[lo:min(hi, length(body))])
        end
        return HTTP.Response(405, "")
    end
    try
        return f("http://127.0.0.1:$(HTTP.port(server))", store, puts, refuse)
    finally
        close(server)
    end
end

"Feed `data` through a `BufferStream` the way the copy engine feeds a backend."
function piped(data::Vector{UInt8}; chunks::Int=8)
    pipe = Base.BufferStream()
    step = cld(length(data), chunks)
    Threads.@spawn begin
        try
            for lo in 1:step:length(data)
                write(pipe, @view data[lo:min(lo + step - 1, length(data))])
            end
        finally
            close(pipe)
        end
    end
    return pipe
end

@testset "Storage streams" begin
    dir = mktempdir()

    @testset "local: the Base IO contract" begin
        path = joinpath(dir, "local.bin")
        data = rand(UInt8, 3 << 20)

        io = storage_open(path, "w")
        @test io isa StorageWriter{LocalStream}
        @test iswritable(io) && !isreadable(io) && isopen(io)
        @test write(io, data) == length(data)
        @test position(io) == length(data)
        close(io)
        @test !isopen(io)
        close(io)                                   # closing twice is a no-op
        @test read(path) == data

        storage_open(path) do r
            @test r isa StorageReader{LocalStream}
            @test isreadable(r) && !iswritable(r)
            @test position(r) == 0 && !eof(r)
            @test read(r, 10) == data[1:10]
            @test position(r) == 10
            @test read(r, UInt8) == data[11]
            seek(r, 1_000_000)
            @test read(r, 4) == data[1_000_001:1_000_004]
            skip(r, 6)
            @test read(r, 2) == data[1_000_011:1_000_012]
            seekend(r)
            @test eof(r) && position(r) == length(data)
            seekstart(r)
            @test read(r) == data
            @test eof(r)
            @test isempty(readavailable(r))
        end

        # readbytes! grows its buffer and reports what actually arrived.
        storage_open(path) do r
            b = UInt8[]
            @test readbytes!(r, b, 100) == 100
            @test b[1:100] == data[1:100]
            seek(r, length(data) - 10)
            @test readbytes!(r, b, 4096) == 10
            @test b[1:10] == data[(end - 9):end]
        end

        # `read(io, n)` answers short at the end, the way Base's does; a read
        # of something with a fixed width cannot, and raises.
        storage_open(path) do r
            seek(r, length(data) - 2)
            @test read(r, 8) == data[(end - 1):end]
            seek(r, length(data) - 2)
            @test_throws EOFError read(r, Int64)
        end

        # The standard text generics work because the byte ones do.
        txt = joinpath(dir, "lines.txt")
        storage_open(txt, "w") do w
            for i in 1:5
                println(w, "line $i")
            end
        end
        @test storage_open(readlines, txt) == ["line $i" for i in 1:5]
        @test storage_open(read, txt) == read(txt)

        # A writer can go back over what it has written, where the backend can.
        holes = joinpath(dir, "holes.bin")
        storage_open(holes, "w") do w
            write(w, fill(UInt8('a'), 1000))
            flush(w)
            seek(w, 100)
            write(w, fill(UInt8('b'), 10))
        end
        got = read(holes)
        @test length(got) == 1000
        @test all(==(UInt8('b')), got[101:110])
        @test got[100] == UInt8('a') && got[111] == UInt8('a')

        # An empty object is a legitimate object.
        empty_path = joinpath(dir, "empty.bin")
        storage_open(_ -> nothing, empty_path, "w")
        @test storage_open(read, empty_path) == UInt8[]
        @test storage_open(eof, empty_path)
    end

    @testset "local: what a stream refuses" begin
        path = joinpath(dir, "local.bin")

        err = try
            storage_open(joinpath(dir, "absent.bin"))
        catch e
            e
        end
        @test err isa StorageError
        @test occursin("open failed", sprint(showerror, err))

        @test_throws ArgumentError storage_open(path, "a")
        @test_throws ArgumentError storage_open(path, "r"; length=10)
        @test_throws StorageError storage_open(dir)   # a directory is not an object
        storage_open(path) do r
            @test_throws ArgumentError seek(r, -1)
        end

        # A closed stream says so rather than reading from a released handle.
        r = storage_open(path)
        close(r)
        @test_throws StorageError read(r, 1)
        w = storage_open(joinpath(dir, "closed.bin"), "w")
        close(w)
        @test_throws StorageError write(w, 0x01)

        # The URL in an error is redacted the way every other one is.
        e = StorageError("root://host:1094//f?authz=Bearer%20abc123", "read", "boom")
        msg = sprint(showerror, e)
        @test !occursin("abc123", msg)
        @test occursin("boom", msg)

        # `show` never prints the credential either.
        r = storage_open("$path")
        @test occursin("StorageReader", sprint(show, r))
        close(r)
        @test occursin("closed", sprint(show, r))
    end

    @testset "S3 part sizing" begin
        @test s3_part_size(nothing) == S3_PART_SIZE
        @test s3_part_size(0) == S3_PART_SIZE
        # Floored at what S3 accepts, whatever the object.
        @test s3_part_size(1024) == S3_MIN_PART_SIZE
        # A mid-size object no longer holds 64 MiB to upload 200 MiB.
        @test s3_part_size(200 * 1024^2) == S3_MIN_PART_SIZE
        @test s3_part_size(10 * 1024^3) == cld(10 * 1024^3, 1000)
        # And a large one is still capped at the default.
        @test s3_part_size(100 * 1024^3) == S3_PART_SIZE
        # Past the default's 640 GB ceiling the part has to grow, or the object
        # could not be sent at all.
        for total in (1024^4, 5 * 1024^4)
            @test cld(total, s3_part_size(total)) <= S3_MAX_PARTS
            @test s3_part_size(total) >= S3_MIN_PART_SIZE
        end
        @test s3_part_size(5 * 1024^4) > S3_PART_SIZE
    end

    stream_fixture() do base, store, puts, refuse
        @testset "web: a known length is framed with Content-Length" begin
            small = rand(UInt8, 1000)
            b = storage_for("$base/small.bin")
            @test storage_write(b, IOBuffer(small); length=length(small)) == :ok
            @test store["/small.bin"] == small
            @test last(puts).cl == "1000"
            @test isempty(last(puts).te)

            # Above the spill the body is streamed, and still framed by length.
            big = rand(UInt8, WEB_PUT_SPILL + 4096)
            @test storage_write(storage_for("$base/big.bin"), IOBuffer(big);
                                length=length(big)) == :ok
            @test store["/big.bin"] == big
            @test last(puts).cl == string(length(big))
            @test isempty(last(puts).te)

            # The same, fed from the pipe the copy engine uses — the case the
            # whole path exists for.
            @test storage_write(storage_for("$base/piped.bin"), piped(big);
                                length=length(big)) == :ok
            @test store["/piped.bin"] == big
            @test last(puts).cl == string(length(big))
        end

        @testset "web: without a length, only a large object goes chunked" begin
            # Small enough to hold: buffered, framed, and replayable.
            small = rand(UInt8, 4096)
            @test storage_write(storage_for("$base/nolen_small.bin"), piped(small)) == :ok
            @test store["/nolen_small.bin"] == small
            @test last(puts).cl == "4096"
            @test isempty(last(puts).te)

            big = rand(UInt8, WEB_PUT_SPILL + 4096)
            @test storage_write(storage_for("$base/nolen_big.bin"), piped(big)) == :ok
            @test store["/nolen_big.bin"] == big
            @test last(puts).te == "chunked"
            @test last(puts).n == length(big)
        end

        @testset "web: a broken promise fails the upload" begin
            # The header said how many bytes were coming; fewer arrived.
            b = storage_for("$base/short.bin")
            @test storage_write(b, piped(rand(UInt8, 4096));
                                length=WEB_PUT_SPILL + 4096) == :error
            @test b.lasterror !== nothing
            @test !haskey(store, "/short.bin")

            # A rejected streamed upload names the status it was rejected with.
            refuse[] = "/refused.bin"
            b2 = storage_for("$base/refused.bin")
            @test storage_write(b2, IOBuffer(rand(UInt8, WEB_PUT_SPILL + 16));
                                length=WEB_PUT_SPILL + 16) == :error
            @test occursin("403", something(b2.lasterror, ""))
            refuse[] = ""
        end

        @testset "web: streams over a remote object" begin
            data = rand(UInt8, 300_000)
            storage_open("$base/stream.bin", "w"; length=length(data)) do w
                write(w, data)
            end
            @test store["/stream.bin"] == data
            @test last(puts).cl == string(length(data))

            storage_open("$base/stream.bin") do r
                @test r isa StorageReader{<:RangeReader}
                @test read(r, 16) == data[1:16]
                seek(r, 200_000)
                @test read(r, 32) == data[200_001:200_032]
                seekstart(r)
                @test read(r) == data
                @test eof(r)
            end

            # No declared length: the writer's own pipe carries the object.
            other = rand(UInt8, 50_000)
            storage_open("$base/nolen_stream.bin", "w") do w
                @test w isa StorageWriter{<:PipeWriter}
                write(w, other)
            end
            @test store["/nolen_stream.bin"] == other

            # A pipe-backed writer uploads in one forward pass and says so.
            storage_open("$base/noseek.bin", "w") do w
                write(w, rand(UInt8, 16))
                @test_throws StorageError seek(w, 0)
            end
        end

        @testset "web: a failed upload is raised by close" begin
            refuse[] = "/rejected.bin"
            w = storage_open("$base/rejected.bin", "w")
            write(w, rand(UInt8, 32))
            @test_throws StorageError close(w)

            # And the `do` form lets the body's own exception out first.
            @test_throws ErrorException storage_open("$base/rejected.bin", "w") do io
                write(io, rand(UInt8, 32))
                error("the body failed")
            end
            refuse[] = ""
        end

        @testset "web: an endpoint that will not state a size" begin
            # `parse_content_length` answers zero both for an empty object and
            # for one whose size was never given; a reader that took the first
            # reading would hand back nothing and call it success.
            data = rand(UInt8, 40_000)
            store["/nolength/obj.bin"] = data
            code, info = storage_stat(storage_for("$base/nolength/obj.bin"))
            @test code == :ok && info.size == 0
            r = storage_open("$base/nolength/obj.bin")
            try
                @test !eof(r)
                @test read(r) == data
                @test eof(r)
                # Nothing said how far the end is, so there is no end to seek to.
                @test_throws StorageError seekend(r)
            finally
                close(r)
            end
            # An object that really is empty still reads as one.
            store["/nolength/empty.bin"] = UInt8[]
            @test storage_open(read, "$base/nolength/empty.bin") == UInt8[]
        end

        @testset "the copy engine passes the size on" begin
            src = joinpath(dir, "copysrc.bin")
            payload = rand(UInt8, 2 << 20)
            write(src, payload)
            ok, msg = XRootD.Tools.copyfile(src, "$base/copied.bin"; force=true)
            @test ok
            @test store["/copied.bin"] == payload
            # The destination was told what was coming, rather than being sent
            # a chunked body it might have refused.
            @test last(puts).cl == string(length(payload))
            @test isempty(last(puts).te)
        end
    end
end
