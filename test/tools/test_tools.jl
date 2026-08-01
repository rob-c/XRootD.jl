using XRootD.Tools
using XRootD.Tools:
    adler32,
    crc64xz,
    copyfile,
    copytree,
    checksum_file,
    ensure_dir,
    CopySink,
    COPY_HIGH_WATER
using CRC32c: crc32c
using HTTP: HTTP

const Xrdcp = XRootD.Tools.Xrdcp
const Cksum = XRootD.Tools.Cksum

"""
Run a tool's `main` with both streams captured: `(stdout, stderr, exit code)`.
What a command-line tool writes, and to which stream, is as much its contract
as the code it exits with.
"""
function capture_main(f)
    outpath, errpath = tempname(), tempname()
    try
        # The streams are redirected to real files: a process's stdout is a file
        # descriptor, and only a descriptor can be put in its place.
        rc = open(outpath, "w") do out
            open(errpath, "w") do err
                redirect_stdout(out) do
                    redirect_stderr(err) do
                        return f()
                    end
                end
            end
        end
        return read(outpath, String), read(errpath, String), rc
    finally
        rm(outpath; force=true)
        rm(errpath; force=true)
    end
end

@testset "Tools" begin
    @testset "checksum algorithms" begin
        # Adler-32 of "Wikipedia" is 0x11E60398 (RFC 1950 worked example).
        @test adler32(Vector{UInt8}(codeunits("Wikipedia"))) == 0x11e60398
        # CRC-64/XZ of "123456789" is 0x995DC9BBDF1939FA (rocksoft/xz vector).
        @test crc64xz(Vector{UInt8}(codeunits("123456789"))) == 0x995dc9bbdf1939fa
    end

    @testset "checksum_file (local)" begin
        dir = mktempdir()
        path = joinpath(dir, "data.bin")
        data = Vector{UInt8}(codeunits("123456789"))
        write(path, data)
        @test checksum_file(path, :crc64) == "995dc9bbdf1939fa"
        @test checksum_file(path, :crc32c) == string(crc32c(data); base=16, pad=8)
        @test checksum_file(path, :adler32) == string(adler32(data); base=16, pad=8)
    end

    @testset "copyfile local→local" begin
        dir = mktempdir()
        src = joinpath(dir, "a.bin")
        dst = joinpath(dir, "b.bin")
        data = rand(UInt8, 4096)
        write(src, data)
        ok, _ = copyfile(src, dst; verify=true)
        @test ok
        @test read(dst) == data
        # without force, refuse to overwrite
        ok2, _ = copyfile(src, dst; force=false)
        @test !ok2
        ok3, _ = copyfile(src, dst; force=true)
        @test ok3
    end

    @testset "CopySink tees, hashes and counts" begin
        pipe = Base.BufferStream()
        sink = CopySink(pipe)
        data = rand(UInt8, 1000)
        @test isopen(sink)
        write(sink, data)
        write(sink, 0xff)
        flush(sink)                                      # forwarded to the pipe
        close(sink)
        @test !isopen(sink)
        @test sink.nbytes == 1001
        @test sink.crc == crc32c(vcat(data, 0xff))
        @test read(pipe) == vcat(data, 0xff)
    end

    @testset "copy backlog stays bounded" begin
        # The producer is held back once the destination falls COPY_HIGH_WATER
        # bytes behind, which is what keeps a copy's memory bounded by that
        # mark instead of by the size of the object.
        pipe = Base.BufferStream()
        sink = CopySink(pipe)
        chunk = zeros(UInt8, COPY_HIGH_WATER)
        write(sink, chunk)                      # exactly at the mark: no wait
        blocked = Threads.Atomic{Bool}(true)
        producer = Threads.@spawn begin
            write(sink, chunk)
            blocked[] = false
        end
        sleep(0.5)
        @test blocked[]
        read(pipe, COPY_HIGH_WATER + 1)         # drain back under the mark
        wait(producer)
        @test !blocked[]
        close(sink)
    end

    @testset "copyfile streams objects larger than the backlog" begin
        dir = mktempdir()
        src = joinpath(dir, "big.bin")
        dst = joinpath(dir, "big.copy")
        data = rand(UInt8, COPY_HIGH_WATER + (1 << 20))
        write(src, data)
        ok, msg = copyfile(src, dst; verify=true)
        @test ok
        @test occursin(string(length(data)), msg)
        @test read(dst) == data
    end

    @testset "verify catches a corrupted destination" begin
        stored = Dict{String,Vector{UInt8}}()
        handler = function (req)
            if req.method == "PUT"
                stored[req.target] = req.body
                return HTTP.Response(201)
            elseif req.method == "HEAD"
                haskey(stored, req.target) || return HTTP.Response(404)
                len = string(length(stored[req.target]))
                return HTTP.Response(200, ["Content-Length" => len])
            end
            data = copy(get(stored, req.target, UInt8[]))
            isempty(data) && return HTTP.Response(404)
            data[1] ⊻= 0x01          # a store that quietly returns other bytes
            return HTTP.Response(200, data)
        end
        server = HTTP.serve!(handler, "127.0.0.1", 0; verbose=false)
        port = HTTP.port(server)
        try
            dir = mktempdir()
            src = joinpath(dir, "v.bin")
            write(src, rand(UInt8, 2048))
            ok, msg = copyfile(src, "http://127.0.0.1:$port/v.bin"; verify=true)
            @test !ok
            @test msg == "checksum mismatch after copy"
            # Without verify the same copy is reported as a success — which is
            # exactly why verify exists.
            ok, _ = copyfile(src, "http://127.0.0.1:$port/v2.bin")
            @test ok
        finally
            close(server)
        end
    end

    @testset "copytree and ensure_dir" begin
        srcdir = mktempdir()
        mkpath(joinpath(srcdir, "sub"))
        write(joinpath(srcdir, "one.bin"), "1")
        write(joinpath(srcdir, "sub", "two.bin"), "22")
        dstdir = joinpath(mktempdir(), "out")

        ok, msg = copytree(srcdir, dstdir)
        @test ok
        @test occursin("2 entries", msg)
        @test read(joinpath(dstdir, "one.bin"), String) == "1"
        @test read(joinpath(dstdir, "sub", "two.bin"), String) == "22"

        # A source that lists nothing and is not a directory is a plain file:
        # copytree degrades to a single-file copy rather than reporting an
        # empty tree.
        lone = joinpath(srcdir, "one.bin")
        lonedst = joinpath(dstdir, "lone.bin")
        ok, _ = copytree(lone, lonedst)
        @test ok
        @test read(lonedst, String) == "1"

        # An empty directory is still part of the tree and is recreated.
        emptysrc = joinpath(srcdir, "hollow")
        mkpath(emptysrc)
        ok, msg = copytree(emptysrc, joinpath(dstdir, "hollow"))
        @test ok
        @test occursin("empty directory", msg)
        @test isdir(joinpath(dstdir, "hollow"))

        nested = joinpath(dstdir, "a", "b", "c")
        @test ensure_dir(nested) == :ok
        @test isdir(nested)
        @test ensure_dir(nested) == :ok                  # idempotent
        # An S3 prefix is not a directory and needs no creating.
        @test ensure_dir("s3://bucket/prefix") == :ok
    end

    @testset "xrdcp main (local)" begin
        dir = mktempdir()
        src = joinpath(dir, "s.bin")
        dst = joinpath(dir, "d.bin")
        write(src, "payload")
        @test Xrdcp.main(["-f", "--verify", src, dst]) == 0
        @test read(dst, String) == "payload"
        @test Xrdcp.main([src]) == 2                       # usage error
        @test Xrdcp.main(["--version"]) == 0
    end

    @testset "xrdcp credential and TPC flags" begin
        dir = mktempdir()
        src = joinpath(dir, "s.bin")
        dst = joinpath(dir, "d.bin")
        write(src, "payload")

        # One credential set serves every scheme: the options a backend has no
        # use for are dropped rather than rejected.
        @test Xrdcp.main([
            "--token",
            "t",
            "--cert",
            "c",
            "--key",
            "k",
            "--cafile",
            "f",
            "--insecure",
            "-f",
            src,
            dst,
        ]) == 0
        @test read(dst, String) == "payload"

        @test Xrdcp.main(["--tpc", "first", "-f", src, dst]) == 0
        @test Xrdcp.main(["--tpc", "only", "-f", src, dst]) == 1
        @test Xrdcp.main(["--tpc", "bogus", src, dst]) == 2
        @test Xrdcp.main(["-f", src, dst, "--token"]) == 2   # flag needs a value
        @test Xrdcp.main(["--bogus", src, dst]) == 2

        tree = mktempdir()
        write(joinpath(tree, "leaf.bin"), "leaf")
        @test Xrdcp.main(["-r", "-f", tree, joinpath(dir, "tree")]) == 0
        @test read(joinpath(dir, "tree", "leaf.bin"), String) == "leaf"
    end

    @testset "checksum tool mains (local)" begin
        dir = mktempdir()
        path = joinpath(dir, "c.bin")
        write(path, "123456789")
        @test Cksum.crc64_main([path]) == 0
        @test Cksum.adler32_main([path]) == 0
        @test Cksum.ckverify_main([path, "crc64", "995dc9bbdf1939fa"]) == 0
        @test Cksum.ckverify_main([path, "crc64", "deadbeef"]) == 1
        @test Cksum.ckverify_main([path]) == 2             # usage

        # What the tools print is their interface: xrdadler32 and friends emit
        # "<digest> <target>", one line per argument, in the order given.
        out, err, rc = capture_main(() -> Cksum.adler32_main([path]))
        @test rc == 0
        @test out == "091e01de $path\n"
        @test isempty(err)
        @test first(capture_main(() -> Cksum.crc32c_main([path]))) == "e3069283 $path\n"
        @test first(capture_main(() -> Cksum.crc64_main([path]))) ==
            "995dc9bbdf1939fa $path\n"

        # Several targets are several lines, and one that cannot be read fails
        # the run without stopping it — the digests that could be taken are.
        other = joinpath(dir, "d.bin")
        write(other, "123456789")
        out, err, rc = capture_main(
            () -> Cksum.crc32c_main([path, joinpath(dir, "absent.bin"), other])
        )
        @test rc == 1
        @test out == "e3069283 $path\ne3069283 $other\n"
        @test occursin("xrdcrc32c: $(joinpath(dir, "absent.bin"))", err)

        # Usage goes to stderr and exits 2; --version to stdout and exits 0.
        out, err, rc = capture_main(() -> Cksum.crc64_main(String[]))
        @test rc == 2
        @test isempty(out)
        @test occursin("usage: xrdcrc64 <path-or-url>", err)
        for (tool, name) in (
            (Cksum.adler32_main, "xrdadler32"),
            (Cksum.crc32c_main, "xrdcrc32c"),
            (Cksum.crc64_main, "xrdcrc64"),
            (Cksum.ckverify_main, "xrdckverify"),
        )
            out, _, rc = capture_main(() -> tool(["--version"]))
            @test rc == 0
            @test occursin("$name (XRootD.jl)", out)
        end

        # xrdckverify compares case-insensitively, says which side was which,
        # and reports an unreadable target as an error rather than a mismatch.
        out, _, rc = capture_main(
            () -> Cksum.ckverify_main([path, "crc64", "995DC9BBDF1939FA"])
        )
        @test rc == 0
        @test out == "OK $path 995dc9bbdf1939fa\n"
        _, err, rc = capture_main(() -> Cksum.ckverify_main([path, "crc64", "deadbeef"]))
        @test rc == 1
        @test occursin("MISMATCH $path: got 995dc9bbdf1939fa, expected deadbeef", err)
        _, err, rc = capture_main(() -> Cksum.ckverify_main([path, "md5", "00"]))
        @test rc == 1
        @test occursin("xrdckverify:", err)
        @test capture_main(() -> Cksum.ckverify_main([path, "crc64"]))[3] == 2
    end
end
