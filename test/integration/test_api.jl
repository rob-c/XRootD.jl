# The everyday API against the real XRootD server — one working day, in order:
# make somewhere to put things, put a file there, look at what is there, read
# it where it lives, bring it back, and tidy up.
#
# The conformance suite proves the framing; this proves that a real xrootd
# answers the same way, which is the only thing a physicist at a terminal is
# going to find out.

@testset "the everyday API against a real server" begin
    base = "root://localhost:1094"
    work = StoragePath("$base//tmp/api_work")
    payload = rand(UInt8, 3 << 20)
    local_src = joinpath(mktempdir(), "run7.raw")
    write(local_src, payload)

    XRootD.rm(work; force=true, recursive=true)
    @test mkpath(work) == work
    @test isdir(work) && !isfile(work)

    @testset "put a file there and look at it" begin
        target = XRootD.upload(local_src, work.url)
        @test target.url == "$base//tmp/api_work/run7.raw"
        @test isfile(target)
        @test filesize(target) == length(payload)
        @test mtime(target) > 0
        @test read("/tmp/api_work/run7.raw") == payload

        XRootD.write(joinpath(work, "notes.txt"), "3 MB of nothing in particular\n")
        @test isdir(mkpath(joinpath(work, "sub")))
        XRootD.write(joinpath(work, "sub", "inner.txt"), "nested")

        listing = XRootD.ls(work)
        @test [e.name for e in listing] == ["notes.txt", "run7.raw", "sub"]
        @test [isdir(e) for e in listing] == [false, false, true]
        @test filesize(listing[2]) == length(payload)
        @test occursin("3.1 MB", sprint(show, MIME("text/plain"), listing))
        @test readdir(work) == ["notes.txt", "run7.raw", "sub"]

        walked = collect(walkdir(work))
        @test [w[1].url for w in walked] == [work.url, joinpath(work, "sub").url]
        @test walked[1][3] == ["notes.txt", "run7.raw"]
        @test walked[2][3] == ["inner.txt"]
    end

    @testset "read it where it lives" begin
        f = joinpath(work, "run7.raw")
        notes = joinpath(work, "notes.txt")

        @test read(f, 16) == payload[1:16]
        @test XRootD.read(f; offset=1 << 20, length=32) ==
            payload[((1 << 20) + 1):((1 << 20) + 32)]
        @test read(notes, String) == "3 MB of nothing in particular\n"
        @test readlines(notes) == ["3 MB of nothing in particular"]
        @test collect(eachline(notes)) == ["3 MB of nothing in particular"]

        # A file bigger than a chunk, read through the stream rather than
        # pulled into memory in one piece.
        @test open(f) do io
            seek(io, 2 << 20)
            return read(io, 64)
        end == payload[((2 << 20) + 1):((2 << 20) + 64)]
        @test XRootD.open(read, f.url) == payload
    end

    @testset "bring it back, and put it somewhere else" begin
        dir = mktempdir()
        landed = XRootD.download("$base//tmp/api_work/run7.raw", dir)
        @test landed == joinpath(dir, "run7.raw")
        @test read(landed) == payload

        # `:auto` verification checksums the local end after the copy; the
        # remote end is only re-read when it is asked for.
        @test XRootD.download(
            "$base//tmp/api_work/notes.txt", joinpath(dir, "notes.txt")
        ) == joinpath(dir, "notes.txt")
        @test XRootD.copy(
            "$base//tmp/api_work/notes.txt", "$base//tmp/api_work/copy.txt"; verify=true
        ) isa StoragePath
        @test read(StoragePath("$base//tmp/api_work/copy.txt"), String) ==
            "3 MB of nothing in particular\n"

        # A rename on the server moves no bytes.
        moved = mv(
            StoragePath("$base//tmp/api_work/copy.txt"), "$base//tmp/api_work/renamed.txt"
        )
        @test isfile(moved) && !ispath(StoragePath("$base//tmp/api_work/copy.txt"))
    end

    @testset "and tidy up" begin
        @test XRootD.rm("$base//tmp/api_work/renamed.txt") === nothing
        @test !XRootD.exists("$base//tmp/api_work/renamed.txt")
        # A directory with things in it needs saying so.
        @test_throws StorageError XRootD.rm(work)
        @test XRootD.rm(work; recursive=true) === nothing
        @test !XRootD.exists(work.url)
        @test !ispath("/tmp/api_work")
    end

    @testset "a failure says what the server said" begin
        err = try
            filesize(StoragePath("$base//tmp/api_no_such_file"))
        catch e
            e
        end
        @test err isa StorageError && err.op == "stat"
        @test !isempty(err.detail)
        @test_throws StorageError XRootD.read("$base//tmp/api_no_such_file")
        @test !XRootD.exists("$base//tmp/api_no_such_file")
    end
end
