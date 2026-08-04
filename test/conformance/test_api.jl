# The everyday API over `root://`, against the strict namespace server.
#
# test/api/test_api.jl pins the same verbs down over the local backend, where
# nothing can go wrong on a wire. This is where they meet a protocol: that a
# listing carries the server's own sizes and times, that a streamed write
# commits before the call returns, and that a failure reaches the user in the
# words the server used rather than as a symbol.

@testset "conformance: the everyday API over root://" begin
    srv, port = start_conf_fs([
        "/data/a.txt" => "hello\nworld\nagain\n",
        "/data/b.bin" => "second",
        "/data/sub/x.txt" => "nested",
        "/out/",
    ])
    host = "root://127.0.0.1:$port"
    data = StoragePath("$host//data")

    @testset "browsing a namespace" begin
        fsc_reset!(srv)
        @test isdir(data) && !isfile(data)
        a = joinpath(data, "a.txt")
        @test isfile(a) && !isdir(a)
        @test ispath(a) && !ispath(joinpath(data, "nope"))
        @test filesize(a) == 18
        @test XRootD.filesize("$host//data/b.bin") == 6
        @test XRootD.exists("$host//data") && !XRootD.exists("$host//nope")
        @test XRootD.isfile("$host//data/a.txt") && XRootD.isdir("$host//data")

        i = XRootD.info("$host//data/a.txt")
        @test i.size == 18 && i.mtime == FSC_MTIME && !i.isdir
        @test stat(a) == i
        @test mtime(a) == FSC_MTIME

        listing = XRootD.ls(data)
        @test [e.name for e in listing] == ["a.txt", "b.bin", "sub"]
        @test [isdir(e) for e in listing] == [false, false, true]
        # The sizes came back with the listing: asking an entry costs nothing.
        @test [filesize(e) for e in listing] == [18, 6, 0]
        before = fsc_op_count(srv, Wire.kXR_stat)
        @test all(e -> filesize(e) >= 0, listing)
        @test fsc_op_count(srv, Wire.kXR_stat) == before

        out = sprint(show, MIME("text/plain"), listing)
        @test occursin("(3 entries)", out)
        @test occursin("sub/", out) && occursin("18 B", out)
        @test occursin("2023-11-14 22:13", out)

        @test readdir(data) == ["a.txt", "b.bin", "sub"]
        @test readdir(data; join=true)[1] == "$host//data/a.txt"

        walked = collect(walkdir(data))
        @test [w[1].url for w in walked] == ["$host//data", "$host//data/sub"]
        @test walked[1][2] == ["sub"] && walked[1][3] == ["a.txt", "b.bin"]
        @test walked[2][3] == ["x.txt"]

        @test isempty(srv.violations)
    end

    @testset "reading a file where it lives" begin
        fsc_reset!(srv)
        a = joinpath(data, "a.txt")
        text = "hello\nworld\nagain\n"

        @test read(a, String) == text
        @test read(a) == Vector{UInt8}(text)
        @test read(a, 5) == Vector{UInt8}("hello")
        @test readlines(a) == ["hello", "world", "again"]
        @test collect(eachline(a)) == ["hello", "world", "again"]

        @test XRootD.read("$host//data/a.txt", String) == text
        @test XRootD.read("$host//data/a.txt"; offset=6, length=5) == Vector{UInt8}("world")

        # The stream is a stream: seek it, hand it to code that takes an `IO`.
        @test XRootD.open("$host//data/a.txt") do io
            seek(io, 6)
            return String(read(io, 5))
        end == "world"
        @test XRootD.open(countlines, "$host//data/a.txt") == 3

        # Nothing above may leave a file open on the server.
        @test isempty(srv.handles)
        @test isempty(srv.violations)
    end

    @testset "writing output back" begin
        fsc_reset!(srv)
        out = StoragePath("$host//out/summary.txt")
        @test write(out, "42 events\n") == 10
        @test srv.nodes["/out/summary.txt"].data == Vector{UInt8}("42 events\n")
        # An upload is only claimed once the server has acknowledged the close.
        names = fsc_op_names(srv)
        @test findlast(==("kXR_sync"), names) < findlast(==("kXR_close"), names)
        @test isempty(srv.handles)

        # A write replaces the object, it does not append to it.
        @test XRootD.write(out.url, "7 events\n") == 9
        @test srv.nodes["/out/summary.txt"].data == Vector{UInt8}("7 events\n")
        @test read(out, String) == "7 events\n"

        # Something larger than memory goes out a chunk at a time.
        payload = rand(UInt8, 300_000)
        XRootD.open("$host//out/big.bin", "w"; length=length(payload)) do io
            for chunk in Iterators.partition(payload, 65_536)
                write(io, chunk)
            end
        end
        @test srv.nodes["/out/big.bin"].data == payload
        @test read(StoragePath("$host//out/big.bin")) == payload

        @test isempty(srv.handles)
        @test isempty(srv.violations)
    end

    @testset "the namespace: mkdir, mv and rm" begin
        fsc_reset!(srv)
        made = XRootD.mkdir("$host//made/deep/deeper")
        @test made isa StoragePath && srv.nodes["/made/deep/deeper"].dir
        @test isdir(mkpath(StoragePath("$host//made/deep")))   # already there is fine

        # Within one endpoint a move is a rename: no bytes cross the wire.
        src = StoragePath("$host//made/deep/from.txt")
        write(src, "moved")
        fsc_reset!(srv)
        dst = mv(src, "$host//made/deep/to.txt")
        @test srv.nodes["/made/deep/to.txt"].data == Vector{UInt8}("moved")
        @test !haskey(srv.nodes, "/made/deep/from.txt")
        @test fsc_op_count(srv, Wire.kXR_mv) == 1
        @test fsc_op_count(srv, Wire.kXR_read) == 0

        # A destination that is there is not replaced without being told to.
        write(src, "second")
        @test_throws StorageError mv(src, dst)
        @test srv.nodes["/made/deep/to.txt"].data == Vector{UInt8}("moved")
        @test mv(src, dst; force=true) == dst
        @test srv.nodes["/made/deep/to.txt"].data == Vector{UInt8}("second")

        @test rm(dst) === nothing
        @test !haskey(srv.nodes, "/made/deep/to.txt")
        @test_throws StorageError XRootD.rm("$host//made/deep/to.txt")
        @test XRootD.rm("$host//made/deep/to.txt"; force=true) === nothing

        # A directory is not deleted by accident, and goes with its contents
        # when it is meant.
        write(StoragePath("$host//made/deep/keep.txt"), "x")
        @test_throws StorageError XRootD.rm("$host//made")
        @test XRootD.rm("$host//made"; recursive=true) === nothing
        @test !any(startswith(p, "/made") for p in keys(srv.nodes))

        @test isempty(srv.handles)
        @test isempty(srv.violations)
    end

    @testset "moving files on and off the server" begin
        fsc_reset!(srv)
        dir = mktempdir()

        # A destination directory keeps the object's own name.
        landed = XRootD.download("$host//data/a.txt", dir)
        @test landed == joinpath(dir, "a.txt")
        @test read(landed, String) == "hello\nworld\nagain\n"
        @test XRootD.download("$host//data/b.bin", joinpath(dir, "named")) ==
            joinpath(dir, "named")

        # Downloading again replaces it: a cell that is run twice must not
        # stop on the second run.
        @test XRootD.download("$host//data/a.txt", dir) == landed

        up = joinpath(dir, "up.bin")
        write(up, "uploaded")
        target = XRootD.upload(up, "$host//out/")
        @test target.url == "$host//out/up.bin"
        @test srv.nodes["/out/up.bin"].data == Vector{UInt8}("uploaded")
        # Verifying a remote destination is asked for, not assumed.
        @test XRootD.upload(up, "$host//out/verified.bin"; verify=true) isa StoragePath

        # `cp` works in either direction, and keeps Base's refusal to clobber.
        @test read(cp(StoragePath("$host//data/b.bin"), joinpath(dir, "cp.bin"))) ==
            Vector{UInt8}("second")
        @test_throws StorageError cp(
            StoragePath("$host//data/b.bin"), joinpath(dir, "cp.bin")
        )
        @test cp(joinpath(dir, "cp.bin"), StoragePath("$host//out/back.bin")) isa
            StoragePath
        @test srv.nodes["/out/back.bin"].data == Vector{UInt8}("second")

        # Progress is reported from the bytes that actually moved.
        seen = Tuple{Int64,Any}[]
        XRootD.copy(
            "$host//out/big.bin",
            joinpath(dir, "big.bin");
            progress=(done, total) -> push!(seen, (Int64(done), total)),
        )
        @test !isempty(seen)
        @test last(seen) == (300_000, 300_000)
        @test filesize(joinpath(dir, "big.bin")) == 300_000

        @test isempty(srv.handles)
        @test isempty(srv.violations)
    end

    @testset "a failure arrives in the server's own words" begin
        fsc_reset!(srv)
        err = try
            filesize(StoragePath("$host//data/nope"))
        catch e
            e
        end
        @test err isa StorageError
        @test err.op == "stat"
        # The server said which path and why; neither is invented here.
        @test occursin("no such file or directory", sprint(showerror, err))
        @test occursin("/data/nope", sprint(showerror, err))

        @test_throws StorageError XRootD.read("$host//data/nope")
        @test_throws StorageError XRootD.ls("$host//data/nope")
        err = try
            XRootD.ls("$host//data/a.txt")
        catch e
            e
        end
        @test occursin("this is a file, not a directory", err.detail)

        err = try
            XRootD.download("$host//data/nope", mktempdir())
        catch e
            e
        end
        @test err isa StorageError && err.op == "download"

        # An endpoint that is not there answers the same question with `false`
        # rather than an exception: `exists` is asked before going ahead.
        @test !XRootD.exists("root://127.0.0.1:1//x")
        @test !XRootD.isfile("root://127.0.0.1:1//x")

        @test isempty(srv.violations)
    end

    @testset "a path holds its connection until it is given back" begin
        fsc_reset!(srv)
        p = joinpath(data, "a.txt")
        for _ in 1:5
            @test filesize(p) == 18
        end
        # Five questions, one login.
        @test length(srv.logins) == 1
        @test fsc_op_count(srv, Wire.kXR_stat) == 5

        close(p)
        @test filesize(p) == 18          # still usable; it opens another
        @test length(srv.logins) == 2
        @test isempty(srv.violations)
    end
end
