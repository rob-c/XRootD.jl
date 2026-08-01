# The layers above XrdCl, driven against the namespace conformance server:
# the storage backend, the copy engine and the two CLIs. These paths are
# otherwise only exercised against a real xrootd (the integration testset,
# which needs XRootD_jll), so a strict server is the only place their framing
# is actually checked.

using XRootD.XrdCl
using XRootD.Storage:
    storage_for,
    storage_stat,
    storage_read,
    storage_write,
    storage_list,
    storage_remove,
    storage_mkdir,
    storage_move
using XRootD.Tools: copyfile, copytree

const FsXrdfs = XRootD.Tools.Xrdfs
const FsXrdcp = XRootD.Tools.Xrdcp

"""
Run `f` with stdout captured and stderr discarded — the CLIs report failures
on stderr and it would otherwise land in the test log. Returns
`(return value of f, captured stdout)`.
"""
function fs_cli(f)
    return mktemp() do path, io
        result = redirect_stderr(devnull) do
            return redirect_stdout(f, io)
        end
        flush(io)
        return result, read(path, String)
    end
end

"Run `f` with stdin fed from `script` (`redirect_stdin` needs a real file)."
function fs_stdin(f, script::AbstractString)
    return mktemp() do path, io
        write(io, script)
        close(io)
        return open(handle -> redirect_stdin(f, handle), path, "r")
    end
end

@testset "conformance: tools and storage over the namespace server" begin
    srv, port = start_conf_fs([
        "/data/a.txt" => "hello",
        "/data/b.bin" => "second",
        "/data/sub/",
        "/tree/x.txt" => "xx",
        "/tree/sub/y.txt" => "yy",
        "/tree/hollow/",
        "/out/",
    ])
    host = "root://127.0.0.1:$port"

    @testset "the XRootD storage backend" begin
        fsc_reset!(srv)
        b = storage_for("$host//data/a.txt")
        code, info = storage_stat(b)
        @test code == :ok
        @test info.size == 5 && !info.isdir && info.mtime == FSC_MTIME

        sink = IOBuffer()
        @test storage_read(b, sink) == :ok
        @test take!(sink) == Vector{UInt8}("hello")

        sink = IOBuffer()
        @test storage_read(b, sink; offset=2, length=2) == :ok
        @test take!(sink) == Vector{UInt8}("ll")

        w = storage_for("$host//out/new.bin")
        @test storage_write(w, IOBuffer("written")) == :ok
        @test srv.nodes["/out/new.bin"].data == Vector{UInt8}("written")
        # The upload is only claimed once sync and close have both been
        # answered — the in-band signals that the bytes committed.
        names = fsc_op_names(srv)
        @test findlast(==("kXR_sync"), names) < findlast(==("kXR_close"), names)
        @test isempty(srv.handles)

        # A second write over the same object replaces it, it does not append.
        @test storage_write(w, IOBuffer("re")) == :ok
        @test srv.nodes["/out/new.bin"].data == Vector{UInt8}("re")

        listing = storage_list(storage_for("$host//data"))
        @test [n for (n, _) in listing] == ["a.txt", "b.bin", "sub"]
        @test [i.isdir for (_, i) in listing] == [false, false, true]
        @test [i.size for (_, i) in listing] == [5, 6, 0]

        @test storage_mkdir(storage_for("$host//made/deep")) == :ok
        @test srv.nodes["/made/deep"].dir
        @test storage_mkdir(storage_for("$host//made/deep")) == :ok   # idempotent

        @test storage_move(w, "$host//out/moved.bin") == :ok
        @test srv.nodes["/out/moved.bin"].data == Vector{UInt8}("re")
        # Moving across endpoints is not this backend's business, and it must
        # not be attempted as a same-server rename.
        @test storage_move(w, "root://elsewhere:1094//x") == :unsupported
        @test storage_move(w, "https://elsewhere/x") == :unsupported

        @test storage_remove(storage_for("$host//out/moved.bin")) == :ok
        @test !haskey(srv.nodes, "/out/moved.bin")
        @test storage_remove(storage_for("$host//out/moved.bin")) == :error

        code, _ = storage_stat(storage_for("$host//data/nope"))
        @test code == :error
        @test storage_read(storage_for("$host//data/nope"), IOBuffer()) == :error
        @test isempty(storage_list(storage_for("$host//data/nope")))
        @test isempty(srv.violations)
    end

    @testset "copyfile in both directions" begin
        fsc_reset!(srv)
        dir = mktempdir()
        down = joinpath(dir, "down.txt")
        @test first(copyfile("$host//data/a.txt", down))
        @test read(down, String) == "hello"

        # Without force an existing destination is refused, not overwritten.
        ok, msg = copyfile("$host//data/b.bin", down)
        @test !ok && occursin("destination exists", msg)
        @test read(down, String) == "hello"
        @test first(copyfile("$host//data/b.bin", down; force=true))
        @test read(down, String) == "second"

        up = joinpath(dir, "up.bin")
        write(up, "uploaded")
        @test first(copyfile(up, "$host//out/up.bin"))
        @test srv.nodes["/out/up.bin"].data == Vector{UInt8}("uploaded")
        # verify re-reads the destination and compares CRC32c end to end.
        @test first(copyfile(up, "$host//out/up.bin"; force=true, verify=true))

        ok, msg = copyfile("$host//data/nope", joinpath(dir, "missing"))
        @test !ok && occursin("read failed", msg)
        @test isempty(srv.violations)
    end

    @testset "copytree recreates the whole tree, empty directories included" begin
        fsc_reset!(srv)
        dir = joinpath(mktempdir(), "tree")
        ok, msg = copytree("$host//tree", dir)
        @test ok
        @test read(joinpath(dir, "x.txt"), String) == "xx"
        @test read(joinpath(dir, "sub", "y.txt"), String) == "yy"
        @test isdir(joinpath(dir, "hollow"))

        # ... and back up again, into a directory the server does not have yet.
        @test first(copytree(dir, "$host//out/tree"))
        @test srv.nodes["/out/tree/x.txt"].data == Vector{UInt8}("xx")
        @test srv.nodes["/out/tree/sub/y.txt"].data == Vector{UInt8}("yy")
        @test srv.nodes["/out/tree/hollow"].dir
        @test isempty(srv.violations)
    end

    @testset "xrdcp between the server and the local disk" begin
        fsc_reset!(srv)
        dir = mktempdir()
        down = joinpath(dir, "cp.txt")
        @test FsXrdcp.main(["$host//data/a.txt", down]) == 0
        @test read(down, String) == "hello"

        @test fs_cli(() -> FsXrdcp.main(["$host//data/a.txt", down]))[1] == 1
        @test FsXrdcp.main(["-f", "$host//data/a.txt", down]) == 0

        @test FsXrdcp.main(["-f", "--verify", down, "$host//out/cp.txt"]) == 0
        @test srv.nodes["/out/cp.txt"].data == Vector{UInt8}("hello")

        @test FsXrdcp.main(["-r", "-f", "$host//tree", joinpath(dir, "t")]) == 0
        @test read(joinpath(dir, "t", "sub", "y.txt"), String) == "yy"

        @test fs_cli(() -> FsXrdcp.main(["$host//data/nope", down]))[1] == 1
        @test fs_cli(() -> FsXrdcp.main(["$host//data/a.txt"]))[1] == 2
        @test fs_cli(() -> FsXrdcp.main(["--tpc", "sideways", "a", "b"]))[1] == 2
        @test isempty(srv.violations)
    end

    @testset "xrdfs commands" begin
        fsc_reset!(srv)
        code, out = fs_cli(() -> FsXrdfs.main([host, "ls", "/data"]))
        @test code == 0
        @test split(strip(out), '\n') == ["a.txt", "b.bin", "sub"]

        code, out = fs_cli(() -> FsXrdfs.main([host, "stat", "/data/a.txt"]))
        @test code == 0
        @test occursin("size=5", out) && occursin("mtime=$FSC_MTIME", out)

        code, out = fs_cli(() -> FsXrdfs.main([host, "cat", "/data/a.txt"]))
        @test code == 0 && out == "hello"

        code, out = fs_cli(() -> FsXrdfs.main([host, "statvfs", "/data"]))
        @test code == 0 && strip(out) == "2 1024 50 1 2048 25"

        code, out = fs_cli(() -> FsXrdfs.main([host, "query", "Config", "version"]))
        @test code == 0 && strip(out) == "5.2.0"

        code, out = fs_cli(() -> FsXrdfs.main([host, "query", "Checksum", "/data/a.txt"]))
        @test code == 0 && strip(out) == "adler32 062c0215"

        # A bare host:port is accepted as well as a full root:// URL.
        @test fs_cli(() -> FsXrdfs.main(["127.0.0.1:$port", "ls", "/data"]))[1] == 0

        @test fs_cli(() -> FsXrdfs.main([host, "mkdir", "/cli"]))[1] == 0
        @test srv.nodes["/cli"].dir
        @test fs_cli(() -> FsXrdfs.main([host, "mv", "/cli", "/cli2"]))[1] == 0
        @test haskey(srv.nodes, "/cli2") && !haskey(srv.nodes, "/cli")
        @test fs_cli(() -> FsXrdfs.main([host, "rmdir", "/cli2"]))[1] == 0
        @test !haskey(srv.nodes, "/cli2")

        @test fs_cli(() -> FsXrdfs.main([host, "rm", "/out/cp.txt"]))[1] == 0
        @test !haskey(srv.nodes, "/out/cp.txt")

        # A failed operation exits 1; only a malformed command line exits 2.
        @test fs_cli(() -> FsXrdfs.main([host, "stat", "/data/nope"]))[1] == 1
        @test fs_cli(() -> FsXrdfs.main([host, "ls", "/data/nope"]))[1] == 1
        @test fs_cli(() -> FsXrdfs.main([host, "rmdir", "/data"]))[1] == 1
        @test fs_cli(() -> FsXrdfs.main([host, "rm", "/data"]))[1] == 1
        @test fs_cli(() -> FsXrdfs.main([host, "cat", "/data/nope"]))[1] == 1
        @test fs_cli(() -> FsXrdfs.main([host, "mkdir", "/data"]))[1] == 1

        @test fs_cli(() -> FsXrdfs.main([host, "stat"]))[1] == 2
        @test fs_cli(() -> FsXrdfs.main([host, "mv", "/a"]))[1] == 2
        @test fs_cli(() -> FsXrdfs.main([host, "query", "Config"]))[1] == 2
        @test fs_cli(() -> FsXrdfs.main([host, "wat"]))[1] == 2
        @test fs_cli(() -> FsXrdfs.main(String[]))[1] == 2

        # Nothing above should have left a file open on the server.
        @test isempty(srv.handles)
        @test isempty(srv.violations)
    end

    @testset "the xrdfs shell runs commands until EOF" begin
        fsc_reset!(srv)
        code, out = fs_stdin("ls /data/sub\nstat /data/a.txt\n\nexit\n") do
            return fs_cli(() -> FsXrdfs.main([host]))
        end
        @test code == 0
        @test occursin("size=5", out)
        @test fsc_op_count(srv, Wire.kXR_dirlist) == 1
        @test fsc_op_count(srv, Wire.kXR_stat) == 1

        # A shell that reaches EOF without `exit` still exits cleanly, and a
        # failing command inside it does not abort the session.
        fsc_reset!(srv)
        code, out = fs_stdin("stat /data/nope\nls /data\n") do
            return fs_cli(() -> FsXrdfs.main([host]))
        end
        @test code == 0
        @test occursin("a.txt", out)
        @test isempty(srv.violations)
    end
end
