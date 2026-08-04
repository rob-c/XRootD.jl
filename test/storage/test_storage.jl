using XRootD.Storage
using XRootD.Storage:
    parse_url,
    storage_for,
    storage_stat,
    storage_read,
    storage_write,
    storage_list,
    storage_remove,
    storage_mkdir,
    storage_move,
    storage_copy,
    LocalBackend,
    WebBackend,
    S3Backend,
    S3Credentials,
    sigv4_headers,
    s3_object_url
using HTTP: HTTP
using Sockets: Sockets
using Dates: DateTime, datetime2unix
using SHA: sha256

"Look one header up case-insensitively, the way an HTTP peer must."
function header(headers, name::AbstractString)
    for (k, v) in headers
        lowercase(k) == lowercase(name) && return v
    end
    return nothing
end

@testset "Storage" begin
    @testset "URL parsing" begin
        u = parse_url("root://host:1094//data/file")
        @test u.scheme == "root" && u.host == "host" && u.port == 1094
        @test u.path == "/data/file"                 # double-slash collapsed

        u = parse_url("https://example.org/bucket/obj")
        @test u.scheme == "https" && u.port == 443 && u.tls
        @test u.path == "/bucket/obj"

        u = parse_url("s3://mybucket/key/name")
        @test u.scheme == "s3" && u.host == "mybucket" && u.path == "/key/name"

        u = parse_url("/local/path")
        @test u.scheme == "file" && u.path == "/local/path"

        u = parse_url("dav://[::1]:8080/x")
        @test u.host == "[::1]" && u.port == 8080
    end

    @testset "backend dispatch" begin
        @test storage_for("/tmp/x") isa LocalBackend
        @test storage_for("http://h/x") isa WebBackend
        @test storage_for("s3://b/k") isa S3Backend
        @test storage_for("file:///tmp/x") isa LocalBackend

        # A scheme this client does not speak is a typo, and answering it by
        # looking for a local directory of that name hides the typo behind a
        # "no such file or directory" about a path nobody wrote.
        err = try
            storage_for("rooot://host//data")
        catch e
            e
        end
        @test err isa ArgumentError
        @test occursin("rooot://", err.msg) && occursin("root://", err.msg)
        @test_throws ArgumentError storage_for("ftp://host/data")
    end

    @testset "local round trip" begin
        dir = mktempdir()
        src = joinpath(dir, "src.bin")
        data = rand(UInt8, 5000)
        write(src, data)

        b = storage_for(src)
        code, info = storage_stat(b)
        @test code == :ok && info.size == 5000

        sink = IOBuffer()
        @test storage_read(b, sink) == :ok
        @test take!(sink) == data

        # range read
        sink = IOBuffer()
        @test storage_read(b, sink; offset=10, length=20) == :ok
        @test take!(sink) == data[11:30]

        dst = storage_for(joinpath(dir, "dst.bin"))
        @test storage_write(dst, IOBuffer(data)) == :ok
        @test read(joinpath(dir, "dst.bin")) == data

        entries = storage_list(storage_for(dir))
        @test any(e -> e[1] == "src.bin", entries)
    end

    @testset "local backend mutation surface" begin
        dir = mktempdir()

        # mkdir is recursive and idempotent
        deep = joinpath(dir, "a", "b", "c")
        @test storage_mkdir(storage_for(deep)) == :ok
        @test isdir(deep)
        @test storage_mkdir(storage_for(deep)) == :ok
        # ... and reports failure rather than throwing when the path is barred
        # by an existing file.
        blocker = joinpath(dir, "blocker")
        write(blocker, "x")
        @test storage_mkdir(storage_for(joinpath(blocker, "sub"))) == :error

        # remove is force: a missing path is not an error (matches `rm -f`).
        victim = joinpath(dir, "victim.bin")
        write(victim, "gone")
        @test storage_remove(storage_for(victim)) == :ok
        @test !ispath(victim)
        @test storage_remove(storage_for(victim)) == :ok

        # move
        from = joinpath(dir, "from.bin")
        to = joinpath(dir, "to.bin")
        write(from, "payload")
        @test storage_move(storage_for(from), to) == :ok
        @test !ispath(from)
        @test read(to, String) == "payload"
        # onto an existing destination: refused unless overwrite is asked for
        write(from, "second")
        @test storage_move(storage_for(from), to) == :error
        @test read(to, String) == "payload"
        @test storage_move(storage_for(from), to; overwrite=true) == :ok
        @test read(to, String) == "second"
        # a missing source is an error, not an exception
        @test storage_move(storage_for(from), joinpath(dir, "nowhere.bin")) == :error
        # a move off the local filesystem is not a rename
        @test storage_move(storage_for(to), "root://h//x") == :unsupported

        # copy — same policy, and the source survives
        cdst = joinpath(dir, "copy.bin")
        @test storage_copy(storage_for(to), cdst) == :ok
        @test read(cdst, String) == "second"
        @test ispath(to)
        write(cdst, "existing")
        @test storage_copy(storage_for(to), cdst) == :error
        @test read(cdst, String) == "existing"
        @test storage_copy(storage_for(to), cdst; overwrite=true) == :ok
        @test read(cdst, String) == "second"
        @test storage_copy(storage_for(joinpath(dir, "absent")), cdst) == :error
        @test storage_copy(storage_for(to), "https://h/x") == :unsupported
    end

    @testset "S3 has no directories to make" begin
        # A key prefix exists as soon as an object uses it, so mkdir is a
        # no-op. Copy and move go to a destination at the same endpoint;
        # anything else is another service's problem.
        b = storage_for("s3://bucket/prefix/key")
        @test storage_mkdir(b) == :ok
        @test storage_move(b, "https://host/other") == :unsupported
        @test storage_copy(b, "file:///tmp/other") == :unsupported
        # An endpoint was configured for one bucket and cannot speak for
        # another; AWS serves each bucket on its own host, so there it can.
        pinned = storage_for("s3://bucket/key"; endpoint="http://minio:9000")
        @test storage_copy(pinned, "s3://elsewhere/key") == :unsupported
        @test XRootD.Storage.s3_destination(b, "s3://elsewhere/key") isa S3Backend
    end

    @testset "pump across a live pipe" begin
        # Every backend drains the copy engine's pipe through pump, so it has
        # to be exact while a producer is still writing to the far end. Reading
        # a BufferStream with `read(io, n)` is not: past 64 KiB the generic
        # bulk read races the writer and loses whole chunks.
        data = rand(UInt8, 3 * Storage.IO_CHUNK + 7)
        for trial in 1:5
            pipe = Base.BufferStream()
            producer = Threads.@spawn begin
                for off in 1:(Storage.IO_CHUNK):Base.length(data)
                    write(pipe, data[off:min(off + Storage.IO_CHUNK - 1, end)])
                end
                close(pipe)
            end
            out = IOBuffer()
            n = Storage.pump(pipe, out)
            wait(producer)
            @test n == Base.length(data)
            @test take!(out) == data
        end

        # A bounded pump stops at the count it was given and leaves the rest.
        pipe = Base.BufferStream()
        write(pipe, data)
        @test Storage.pump(pipe, IOBuffer(), 40) == 40
        @test bytesavailable(pipe) == Base.length(data) - 40
        close(pipe)
    end

    @testset "the transfer granularity is tunable" begin
        withenv("XRD_CPCHUNKSIZE" => nothing) do
            @test Storage.io_chunk() == Storage.IO_CHUNK
        end
        withenv("XRD_CPCHUNKSIZE" => "65536") do
            @test Storage.io_chunk() == 65536
        end
        # A chunk of no bytes is a loop that never advances, and a chunk of
        # "big" is a profile typo; neither may reach the read.
        for bad in ("0", "-1", "big", "")
            withenv("XRD_CPCHUNKSIZE" => bad) do
                @test Storage.io_chunk() == Storage.IO_CHUNK
            end
        end

        # The setting is what the transfer actually uses, not just what the
        # accessor reports: a small chunk still moves every byte exactly once.
        data = rand(UInt8, 5000)
        withenv("XRD_CPCHUNKSIZE" => "512") do
            pipe = Base.BufferStream()
            write(pipe, data)
            close(pipe)
            out = IOBuffer()
            @test Storage.pump(pipe, out) == Base.length(data)
            @test take!(out) == data
        end
    end

    @testset "a range answered with something else is not data" begin
        data = Vector{UInt8}(codeunits("0123456789"))
        # An endpoint that ignored Range: the object arrives from byte zero,
        # and the window has to be cut out of it here or the caller silently
        # gets the wrong bytes at the wrong offset.
        @test Storage.ranged_body(200, data, 4, 3) == (:ok, view(data, 5:7))
        @test Storage.ranged_body(200, data, 4, nothing) == (:ok, view(data, 5:10))
        @test first(Storage.ranged_body(200, data, 20, 2)) == :truncated

        # A body short of the range is a transfer that stopped, not an object
        # that ended — the one failure a bad network produces that looks
        # exactly like success.
        code, bytes = Storage.ranged_body(206, data, 0, 40)
        @test code == :truncated && Base.length(bytes) == 10

        # Honoured, and over-honoured: a generous server is clipped to what
        # was asked for rather than allowed to overrun the caller.
        @test Storage.ranged_body(206, data, 4, 10) == (:ok, view(data, 1:10))
        @test Storage.ranged_body(206, view(data, 1:4), 0, 4) == (:ok, view(data, 1:4))
        @test Storage.ranged_body(200, data, 0, nothing) == (:ok, view(data, 1:10))
    end

    @testset "HTTP reads survive an endpoint that answers awkwardly" begin
        body = Vector{UInt8}(codeunits("0123456789"))
        attempts = Dict{String,Int}()
        router = HTTP.Router()
        HTTP.register!(
            router,
            "GET",
            "/**",
            function (req)
                attempts[req.target] = get(attempts, req.target, 0) + 1
                req.target == "/whole" && return HTTP.Response(200, body)  # Range ignored
                req.target == "/short" && return HTTP.Response(206, body[1:4])
                if req.target == "/flaky"
                    # Down for the first attempt, up for the replay: the retry
                    # has to be invisible to the caller.
                    attempts[req.target] == 1 && return HTTP.Response(503)
                    return HTTP.Response(200, body)
                end
                return HTTP.Response(404)
            end,
        )
        HTTP.register!(
            router,
            "PROPFIND",
            "/**",
            function (req)
                attempts["propfind"] = get(attempts, "propfind", 0) + 1
                attempts["propfind"] == 1 && return HTTP.Response(503)
                return HTTP.Response(
                    207,
                    """<?xml version="1.0"?><multistatus xmlns="DAV:">
                       <response><href>/dir/child</href>
                       <propstat><prop><getcontentlength>3</getcontentlength>
                       </prop></propstat></response></multistatus>""",
                )
            end,
        )

        HTTP.register!(
            router, "DELETE", "/**", function (req)
                attempts["delete"] = get(attempts, "delete", 0) + 1
                return HTTP.Response(503)
            end
        )

        server = HTTP.serve!(router, "127.0.0.1", 0; verbose=false)
        port = HTTP.port(server)
        try
            b = storage_for("http://127.0.0.1:$port/whole")
            sink = IOBuffer()
            @test storage_read(b, sink; offset=4, length=3) == :ok
            @test String(take!(sink)) == "456"

            short = storage_for("http://127.0.0.1:$port/short")
            sink = IOBuffer()
            @test storage_read(short, sink; offset=0, length=10) == :truncated
            @test String(take!(sink)) == "0123"      # the prefix, reported as short

            # A 503 is the server saying *later*, and the retry budget is this
            # client's own — one knob for the xroot lane and the HTTP one.
            flaky = storage_for("http://127.0.0.1:$port/flaky")
            sink = IOBuffer()
            @test storage_read(flaky, sink) == :ok
            @test String(take!(sink)) == "0123456789"
            @test attempts["/flaky"] == 2

            # PROPFIND is idempotent by WebDAV's definition, which HTTP.jl's
            # policy has no way to know; this client tells it.
            dir = storage_for("http://127.0.0.1:$port/dir")
            entries = storage_list(dir)
            @test attempts["propfind"] == 2
            @test Base.length(entries) == 1 && first(entries)[1] == "child"

            # A DELETE is sent once, whatever HTTP.jl's own policy counts as
            # idempotent: the second one finds nothing to delete and answers
            # 404, which would report a removal that in fact happened as a
            # failure.
            @test storage_remove(storage_for("http://127.0.0.1:$port/doomed")) == :error
            @test attempts["delete"] == 1

            # Nothing listening: the reason is kept where a caller staring at
            # a bare `:error` can find it.
            withenv("XRDC_MAX_RETRIES" => "0") do
                gone = storage_for("http://127.0.0.1:1/obj")
                @test storage_read(gone, IOBuffer()) == :error
                @test gone.lasterror !== nothing
            end
        finally
            close(server)
        end
    end

    @testset "HTTP backend round trip (in-process server)" begin
        served = Dict{String,Vector{UInt8}}(
            "/hello.txt" => Vector{UInt8}(codeunits("hi there"))
        )
        router = HTTP.Router()
        HTTP.register!(
            router, "GET", "/**", function (req)
                data = get(served, req.target, nothing)
                data === nothing && return HTTP.Response(404)
                for (k, v) in req.headers
                    if lowercase(k) == "range"
                        m = match(r"bytes=(\d+)-(\d*)", v)
                        if m !== nothing
                            lo = parse(Int, m.captures[1]) + 1
                            hi = if m.captures[2] == ""
                                length(data)
                            else
                                parse(Int, m.captures[2]) + 1
                            end
                            return HTTP.Response(206, data[lo:hi])
                        end
                    end
                end
                return HTTP.Response(200, data)
            end
        )
        HTTP.register!(
            router,
            "HEAD",
            "/**",
            function (req)
                data = get(served, req.target, nothing)
                data === nothing && return HTTP.Response(404)
                return HTTP.Response(200, ["Content-Length" => string(length(data))])
            end,
        )
        HTTP.register!(router, "PUT", "/**", function (req)
            served[req.target] = req.body
            return HTTP.Response(201)
        end)

        server = HTTP.serve!(router, "127.0.0.1", 0; verbose=false)
        port = HTTP.port(server)
        try
            b = storage_for("http://127.0.0.1:$port/hello.txt")
            # HTTP.jl's in-process server recomputes Content-Length for a
            # body-less HEAD, so assert reachability here; Content-Length
            # parsing is unit-tested separately below.
            code, _ = storage_stat(b)
            @test code == :ok

            sink = IOBuffer()
            @test storage_read(b, sink) == :ok
            @test String(take!(sink)) == "hi there"

            sink = IOBuffer()
            @test storage_read(b, sink; offset=0, length=2) == :ok
            @test String(take!(sink)) == "hi"

            up = storage_for("http://127.0.0.1:$port/put.txt")
            @test storage_write(up, IOBuffer(codeunits("uploaded"))) == :ok
            @test String(served["/put.txt"]) == "uploaded"
        finally
            close(server)
        end
    end

    @testset "HTTP Content-Length / Last-Modified parsing" begin
        resp = HTTP.Response(
            200,
            [
                "Content-Length" => "1234",
                "Last-Modified" => "Sun, 06 Nov 1994 08:49:37 GMT",
            ],
        )
        @test XRootD.Storage.parse_content_length(resp) == 1234
        @test XRootD.Storage.parse_last_modified(resp) == 784111777

        # Missing, unparseable, or malformed headers report zero rather than
        # propagating a `nothing` into a StorageInfo.
        bare = HTTP.Response(200, Pair{String,String}[])
        @test XRootD.Storage.parse_content_length(bare) == 0
        @test XRootD.Storage.parse_last_modified(bare) == 0
        junk = HTTP.Response(
            200, ["content-length" => "not-a-number", "last-modified" => "yesterday"]
        )
        @test XRootD.Storage.parse_content_length(junk) == 0
        @test XRootD.Storage.parse_last_modified(junk) == 0
    end

    @testset "SigV4 matches the AWS GET example vector" begin
        # AWS "Signature Version 4" documented GET example.
        creds = S3Credentials(;
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="",
            region="us-east-1",
        )
        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hdrs = sigv4_headers(
            "GET",
            "https://examplebucket.s3.amazonaws.com/test.txt",
            creds;
            payload_hash=empty_hash,
            headers=["range" => "bytes=0-9"],
            now=DateTime(2013, 5, 24, 0, 0, 0),
        )
        auth = only(v for (k, v) in hdrs if k == "Authorization")
        @test occursin(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            auth,
        )
        @test occursin("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date", auth)
    end

    @testset "S3 object operations against an in-process endpoint" begin
        # An S3-compatible endpoint on the private network (MinIO, Ceph RGW) is
        # what makes this testable without AWS; the requests it receives are the
        # ones AWS would, signature included.
        seen = Tuple{String,String,Vector{Pair{String,String}},String}[]
        handler = function (req)
            push!(
                seen,
                (
                    req.method,
                    req.target,
                    collect(Pair{String,String}, req.headers),
                    String(req.body),
                ),
            )
            occursin("/missing", req.target) && return HTTP.Response(404)
            occursin("/denied", req.target) && return HTTP.Response(403)
            if req.method == "HEAD"
                return HTTP.Response(
                    200,
                    ["Last-Modified" => "Sun, 06 Nov 1994 08:49:37 GMT"],
                    "objectdata",
                )
            elseif req.method == "GET"
                any(kv -> lowercase(kv[1]) == "range", req.headers) &&
                    return HTTP.Response(206, "ject")
                return HTTP.Response(200, "objectdata")
            elseif req.method == "PUT"
                return HTTP.Response(200)
            elseif req.method == "DELETE"
                return HTTP.Response(204)
            end
            return HTTP.Response(405)
        end
        server = HTTP.serve!(handler, "127.0.0.1", 0; verbose=false)
        port = HTTP.port(server)
        creds = S3Credentials(;
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="",
            region="us-east-1",
        )
        endpoint = "http://127.0.0.1:$port"
        try
            b = storage_for("s3://bucket/data/obj.bin"; creds=creds, endpoint=endpoint)
            @test b.bucket == "bucket"
            @test b.key == "data/obj.bin"

            code, info = storage_stat(b)
            @test code == :ok
            @test info.size == 10
            @test info.mtime == 784111777
            method, target, hdrs, _ = last(seen)
            @test method == "HEAD" && target == "/data/obj.bin"
            # Every request is signed, and the signature names the credential
            # scope the endpoint would verify it under.
            auth = something(header(hdrs, "Authorization"), "")
            @test startswith(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
            @test occursin("/us-east-1/s3/aws4_request", auth)
            @test header(hdrs, "x-amz-date") !== nothing
            @test header(hdrs, "x-amz-content-sha256") == "UNSIGNED-PAYLOAD"
            @test header(hdrs, "x-amz-security-token") === nothing

            sink = IOBuffer()
            @test storage_read(b, sink) == :ok
            @test String(take!(sink)) == "objectdata"
            @test storage_read(b, sink; offset=2, length=4) == :ok
            @test String(take!(sink)) == "ject"
            @test header(last(seen)[3], "range") == "bytes=2-5"
            @test storage_read(b, sink; offset=6) == :ok
            @test header(last(seen)[3], "range") == "bytes=6-"

            @test storage_write(b, IOBuffer("uploaded")) == :ok
            method, _, hdrs, body = last(seen)
            @test method == "PUT" && body == "uploaded"
            # A PUT is signed over the payload itself, not UNSIGNED-PAYLOAD.
            @test header(hdrs, "x-amz-content-sha256") ==
                bytes2hex(sha256(Vector{UInt8}(codeunits("uploaded"))))

            @test storage_remove(b) == :ok
            @test last(seen)[1] == "DELETE"

            missing_obj = storage_for("s3://bucket/missing"; creds=creds, endpoint=endpoint)
            @test first(storage_stat(missing_obj)) == :notfound
            @test storage_read(missing_obj, IOBuffer()) == :error

            denied = storage_for("s3://bucket/denied"; creds=creds, endpoint=endpoint)
            @test first(storage_stat(denied)) == :error
            @test storage_write(denied, IOBuffer("x")) == :error
            @test storage_remove(denied) == :error

            # A session token is carried alongside the signature when there is
            # one — the endpoint needs it to resolve the temporary credential.
            temp = storage_for(
                "s3://bucket/data/obj.bin";
                creds=S3Credentials(;
                    access_key="ASIA", secret_key="s", session_token="tok", region="eu-1"
                ),
                endpoint=endpoint,
            )
            storage_stat(temp)
            @test header(last(seen)[3], "x-amz-security-token") == "tok"

            # A trailing slash on an endpoint is a typo, not a different object.
            @test XRootD.Storage.s3_object_url(
                storage_for("s3://bucket/k"; endpoint="$endpoint/")
            ) == "$endpoint/k"
            @test XRootD.Storage.s3_object_url(storage_for("s3://bucket/k")) ==
                "https://bucket.s3.amazonaws.com/k"
        finally
            close(server)
        end
    end

    @testset "S3 listing, server-side copy and multipart upload" begin
        # These three verbs are conversations, not single requests: a listing
        # is paged, a copy has to find its source at the endpoint, and a
        # multipart upload is opened, filled and assembled. The mock keeps
        # enough state to hold the client to all of it.
        objects = Dict{String,Vector{UInt8}}(
            "data/" => UInt8[],                          # a directory marker
            "data/a.bin" => Vector{UInt8}(codeunits("aaa")),
            "data/b.bin" => Vector{UInt8}(codeunits("bbbb")),
            "data/sub/deep.bin" => Vector{UInt8}(codeunits("deep")),
        )
        uploads = Dict{String,Vector{Pair{Int,Vector{UInt8}}}}()
        next_upload = Ref(0)
        seen = Tuple{String,String,Vector{Pair{String,String}},String}[]
        stamp = "2026-07-31T12:00:00.000Z"

        handler = function (req)
            body = String(req.body)
            push!(
                seen,
                (req.method, req.target, collect(Pair{String,String}, req.headers), body),
            )
            uri = HTTP.URI(req.target)
            q = HTTP.queryparams(uri)
            key = String(lstrip(uri.path, '/'))

            if haskey(q, "uploads")
                next_upload[] += 1
                id = "upload/$(next_upload[])"           # an id that has to be escaped
                uploads[id] = Pair{Int,Vector{UInt8}}[]
                return HTTP.Response(
                    200,
                    "<InitiateMultipartUploadResult><UploadId>$id" *
                    "</UploadId></InitiateMultipartUploadResult>",
                )
            elseif haskey(q, "uploadId")
                id = q["uploadId"]
                haskey(uploads, id) || return HTTP.Response(404)
                if req.method == "PUT"
                    n = parse(Int, q["partNumber"])
                    # One part the endpoint refuses, to see the upload abandoned.
                    (occursin("flaky", key) && n == 2) && return HTTP.Response(403)
                    push!(uploads[id], n => Vector{UInt8}(codeunits(body)))
                    return HTTP.Response(200, ["ETag" => "\"etag-$n\""])
                elseif req.method == "DELETE"
                    delete!(uploads, id)
                    return HTTP.Response(204)
                end
                parts = sort(uploads[id]; by=first)
                wanted = join(
                    "<Part><PartNumber>$n</PartNumber><ETag>\"etag-$n\"</ETag></Part>"
                    for (n, _) in parts
                )
                if !occursin(wanted, body)
                    return HTTP.Response(200, "<Error><Code>InvalidPart</Code></Error>")
                end
                objects[key] = reduce(vcat, (d for (_, d) in parts); init=UInt8[])
                delete!(uploads, id)
                return HTTP.Response(200, "<CompleteMultipartUploadResult/>")
            elseif get(q, "list-type", "") == "2"
                prefix = get(q, "prefix", "")
                after = get(q, "continuation-token", "")
                names, dirs = String[], Set{String}()
                for k in sort(collect(keys(objects)))
                    startswith(k, prefix) || continue
                    rest = k[(ncodeunits(prefix) + 1):end]
                    isempty(rest) && continue
                    cut = findfirst('/', rest)
                    if cut === nothing
                        push!(names, k)
                    else
                        push!(dirs, prefix * rest[1:cut])
                    end
                end
                # One key per page: a client that ignored the continuation
                # token would see a third of this bucket.
                left = if isempty(after)
                    names
                else
                    names[(findfirst(==(after), names) + 1):end]
                end
                page = left[1:min(1, end)]
                more = Base.length(left) > 1
                io = IOBuffer()
                print(io, "<?xml version=\"1.0\"?><ListBucketResult>")
                for k in page
                    print(
                        io,
                        "<Contents><Key>",
                        k,
                        "</Key><Size>",
                        Base.length(objects[k]),
                        "</Size><LastModified>",
                        stamp,
                        "</LastModified></Contents>",
                    )
                end
                if !more
                    for d in sort(collect(dirs))
                        print(io, "<CommonPrefixes><Prefix>", d, "</Prefix></CommonPrefixes>")
                    end
                end
                print(io, "<IsTruncated>", more ? "true" : "false", "</IsTruncated>")
                more && print(
                    io,
                    "<NextContinuationToken>",
                    page[end],
                    "</NextContinuationToken>",
                )
                print(io, "</ListBucketResult>")
                return HTTP.Response(200, String(take!(io)))
            end

            if req.method == "PUT"
                src = header(req.headers, "x-amz-copy-source")
                if src !== nothing
                    from = String(split(HTTP.unescapeuri(src), '/'; limit=3)[3])
                    haskey(objects, from) || return HTTP.Response(
                        404, "<Error><Code>NoSuchKey</Code></Error>"
                    )
                    objects[key] = copy(objects[from])
                    return HTTP.Response(200, "<CopyObjectResult/>")
                end
                objects[key] = Vector{UInt8}(codeunits(body))
                return HTTP.Response(200)
            elseif req.method == "HEAD"
                haskey(objects, key) || return HTTP.Response(404)
                return HTTP.Response(
                    200, ["Content-Length" => string(Base.length(objects[key]))]
                )
            elseif req.method == "GET"
                haskey(objects, key) || return HTTP.Response(404)
                return HTTP.Response(200, objects[key])
            elseif req.method == "DELETE"
                delete!(objects, key)
                return HTTP.Response(204)
            end
            return HTTP.Response(405)
        end

        server = HTTP.serve!(handler, "127.0.0.1", 0; verbose=false)
        creds = S3Credentials(;
            access_key="AKIA", secret_key="secret", session_token="", region="us-east-1"
        )
        endpoint = "http://127.0.0.1:$(HTTP.port(server))"
        at(key) = storage_for("s3://bucket/$key"; creds=creds, endpoint=endpoint)
        try
            @testset "listing one level of a prefix" begin
                entries = storage_list(at("data"))
                @test [n for (n, _) in entries] == ["a.bin", "b.bin", "sub"]
                @test [i.size for (_, i) in entries] == [3, 4, 0]
                @test [i.isdir for (_, i) in entries] == [false, false, true]
                @test entries[1][2].mtime ==
                    Int64(round(datetime2unix(DateTime("2026-07-31T12:00:00"))))
                # Three requests, because the token was followed and the
                # directory marker under the prefix is not an entry of itself.
                pages = [
                    t for (m, t, _, _) in seen if m == "GET" && occursin("list-type", t)
                ]
                @test Base.length(pages) == 2
                @test occursin("prefix=data%2F", pages[1])
                @test occursin("continuation-token=data%2Fa.bin", pages[2])
                # The signature covers the query string it was built from.
                @test occursin(
                    "SignedHeaders=host;x-amz-content-sha256;x-amz-date",
                    something(header(seen[end][3], "Authorization"), ""),
                )
                # A prefix nothing lives under is empty, not an error.
                @test isempty(storage_list(at("nowhere")))
            end

            @testset "a copy the endpoint makes for itself" begin
                @test storage_copy(at("data/a.bin"), "s3://bucket/data/copy.bin") == :ok
                @test objects["data/copy.bin"] == codeunits("aaa")
                _, target, hdrs, body = last(seen)
                @test target == "/data/copy.bin"
                @test header(hdrs, "x-amz-copy-source") == "/bucket/data/a.bin"
                @test occursin(
                    "x-amz-copy-source", something(header(hdrs, "Authorization"), "")
                )
                @test isempty(body)          # no bytes came through this client

                # A destination that is already there stands, unless asked.
                @test storage_copy(at("data/a.bin"), "s3://bucket/data/b.bin") == :error
                @test objects["data/b.bin"] == codeunits("bbbb")
                @test storage_copy(
                    at("data/a.bin"), "s3://bucket/data/b.bin"; overwrite=true
                ) == :ok
                @test objects["data/b.bin"] == codeunits("aaa")

                # A source that is not there is refused by the endpoint.
                @test storage_copy(at("data/absent"), "s3://bucket/data/z.bin") == :error
                @test !haskey(objects, "data/z.bin")
            end

            @testset "a move is a copy and then a delete" begin
                @test storage_move(at("data/copy.bin"), "s3://bucket/data/moved.bin") == :ok
                @test objects["data/moved.bin"] == codeunits("aaa")
                @test !haskey(objects, "data/copy.bin")
                # A copy that does not happen leaves the original where it was.
                @test storage_move(at("data/moved.bin"), "s3://bucket/data/a.bin") == :error
                @test haskey(objects, "data/moved.bin")
            end

            @testset "an upload larger than one part" begin
                empty!(seen)
                big = Vector{UInt8}(codeunits(repeat("multipart!", 500)))
                @test storage_write(at("data/big.bin"), IOBuffer(big); part_size=1024) ==
                    :ok
                @test objects["data/big.bin"] == big
                parts = [
                    t for (m, t, _, _) in seen if m == "PUT" && occursin("partNumber", t)
                ]
                @test Base.length(parts) == cld(Base.length(big), 1024)
                @test occursin("uploadId=upload%2F1", parts[1])
                @test isempty(uploads)     # nothing left half-uploaded

                # A known length stops the upload where the caller said it did.
                @test storage_write(
                    at("data/head.bin"), IOBuffer(big); length=3000, part_size=1024
                ) == :ok
                @test objects["data/head.bin"] == big[1:3000]
            end

            @testset "an upload that fits in one part is one PUT" begin
                empty!(seen)
                small = Vector{UInt8}(codeunits("small enough"))
                @test storage_write(at("data/small.bin"), IOBuffer(small); part_size=64) ==
                    :ok
                @test objects["data/small.bin"] == small
                # Exactly one part is still one PUT, not a multipart upload of one.
                @test storage_write(
                    at("data/exact.bin"), IOBuffer(small); part_size=Base.length(small)
                ) == :ok
                @test objects["data/exact.bin"] == small
                @test !any(t -> occursin("upload", t), (t for (_, t, _, _) in seen))
            end

            @testset "a part the endpoint refuses abandons the upload" begin
                empty!(seen)
                big = Vector{UInt8}(codeunits(repeat("x", 4096)))
                @test storage_write(at("flaky.bin"), IOBuffer(big); part_size=1024) ==
                    :error
                @test !haskey(objects, "flaky.bin")
                # The parts that did land are not left to be paid for.
                @test isempty(uploads)
                @test any(((m, t, _, _),) -> m == "DELETE" && occursin("uploadId", t), seen)
            end
        finally
            close(server)
        end
    end

    @testset "an S3 endpoint that is not there" begin
        # Nothing listening: every verb reports a transport failure instead of
        # throwing out of a copy that is halfway done.
        dead = storage_for("s3://bucket/key"; endpoint="http://127.0.0.1:1")
        @test first(storage_stat(dead)) == :error
        @test storage_read(dead, IOBuffer()) == :error
        @test storage_write(dead, IOBuffer("x")) == :error
        @test storage_remove(dead) == :error
    end
end
