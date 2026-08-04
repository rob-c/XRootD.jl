# Namespace protocol conformance: every path-based operation is driven through
# the strict server in conformance/fs_server.jl, which parses the client's
# frames the way stock XrdXrootd does and keeps a real namespace. Each testset
# asserts three things: the operation's own result, the state the SERVER ended
# up in, and that the server logged no protocol violation.

using XRootD.XrdCl
using XRootD.XrdCl: dirlist_stat, statvfs, checksum, prepare
# The vendor link operations are XrdCl functions of their own, not Base
# methods: name them explicitly so they do not resolve to Base's.
using XRootD.XrdCl: symlink, hardlink, readlink

"""
The namespace every testset starts from. Mutating testsets work under their
own root so that the order of the file does not decide the outcome.
"""
const FS_SEED = [
    "/data/a.txt" => "hello",
    "/data/b.bin" => UInt8[0x00, 0x01, 0x02, 0x03],
    "/data/sub/deep/c.dat" => "cc",
    "/empty/",
]

@testset "conformance: namespace over a strict server" begin
    srv, port = start_conf_fs(FS_SEED)
    fs = conf_fs(port)

    @testset "bring-up, ping and kXR_protocol" begin
        fsc_reset!(srv)
        st, _ = ping(fs)
        @test isOK(st)
        @test fsc_op_names(srv) == ["kXR_ping"]

        st, p = protocol(fs)
        @test isOK(st) && p.version == 0x0520 && p.hostinfo == 0x00000001
        @test isempty(srv.violations)
    end

    @testset "kXR_dirlist: names" begin
        fsc_reset!(srv)
        st, names = readdir(fs, "/data")
        @test isOK(st) && names == ["a.txt", "b.bin", "sub"]
        @test fsc_op_count(srv, Wire.kXR_dirlist) == 1   # one round trip, no per-entry stat
        @test fsc_op_count(srv, Wire.kXR_stat) == 0

        st, names = readdir(fs, "/empty")
        @test isOK(st) && isempty(names)

        st, names = readdir(fs, "/data"; join=true, sort=true)
        @test isOK(st) && names == ["/data/a.txt", "/data/b.bin", "/data/sub"]

        st, names = readdir(fs, "/nope")
        @test isError(st) && st.code == FSC_NotFound && names === nothing

        st, names = readdir(fs, "/data/a.txt")          # a file is not a directory
        @test isError(st) && st.code == FSC_NotFile && names === nothing
        @test isempty(srv.violations)
    end

    @testset "kXR_dirlist: kXR_dstat carries the stat info" begin
        fsc_reset!(srv)
        st, names, stats = dirlist_stat(fs, "/data")
        @test isOK(st) && names == ["a.txt", "b.bin", "sub"]
        @test [s.size for s in stats] == [5, 4, 0]
        @test [isdir(s) for s in stats] == [false, false, true]
        @test [s.modtime for s in stats] == fill(FSC_MTIME, 3)
        @test isfile(stats[1]) && isreadable(stats[1]) && iswritable(stats[1])
        @test fsc_op_count(srv, Wire.kXR_stat) == 0     # the listing answered it all
        @test isempty(srv.violations)
    end

    @testset "a server that ignores kXR_dstat: per-entry kXR_stat fallback" begin
        fsc_reset!(srv)
        srv.no_stat = true
        st, names, stats = dirlist_stat(fs, "/data")
        @test isOK(st) && names == ["a.txt", "b.bin", "sub"]
        @test [s.size for s in stats] == [5, 4, 0]
        @test fsc_op_names(srv) == ["kXR_dirlist", "kXR_stat", "kXR_stat", "kXR_stat"]
        @test srv.paths[2:4] == ["/data/a.txt", "/data/b.bin", "/data/sub"]
        srv.no_stat = false
        @test isempty(srv.violations)
    end

    @testset "a listing split across kXR_oksofar chunks" begin
        fsc_reset!(srv)
        srv.chunk_dirlist = 7                            # splits mid-line on purpose
        st, names, stats = dirlist_stat(fs, "/data")
        @test isOK(st) && names == ["a.txt", "b.bin", "sub"]
        @test [s.size for s in stats] == [5, 4, 0]
        srv.chunk_dirlist = 0
        @test isempty(srv.violations)
    end

    @testset "kXR_stat: path form, handle form and kXR_vfs" begin
        fsc_reset!(srv)
        st, si = stat(fs, "/data/a.txt")
        @test isOK(st) && si.size == 5 && isfile(si) && si.modtime == FSC_MTIME

        st, si = stat(fs, "/data/sub")
        @test isOK(st) && isdir(si) && isExecutable(si) && !isOffline(si)

        st, si = stat(fs, "/data/nope")
        @test isError(st) && st.code == FSC_NotFound && si === nothing

        f = fs_file(port, "/data/a.txt")
        @test f isa File
        st, si = stat(f)                                 # the handle form names no path
        @test isOK(st) && si.size == 5
        close(f)

        st, vfs = statvfs(fs, "/data")
        @test isOK(st)
        @test vfs.nodes == 2 && vfs.free_kb == 1024 && vfs.utilization == 50
        @test vfs.raw == "2 1024 50 1 2048 25"
        @test isempty(srv.violations)
    end

    @testset "kXR_open: creation, exclusivity and truncation" begin
        fsc_reset!(srv)
        # Reading a file that is not there creates nothing.
        st, _ = open(File(), "root://127.0.0.1:$port//open/missing.dat", OpenFlags.Read)
        @test isError(st) && st.code == FSC_NotFound
        @test !haskey(srv.nodes, "/open/missing.dat")

        # kXR_mkpath brings the parent directory with it.
        f = fs_file(
            port, "/open/keep.dat", OpenFlags.Update | OpenFlags.New | OpenFlags.MakePath
        )
        @test f isa File
        st, _ = write(f, "0123456789")
        @test isOK(st)
        close(f)
        @test haskey(srv.nodes, "/open")
        @test srv.nodes["/open/keep.dat"].data == Vector{UInt8}("0123456789")

        # kXR_new is exclusive.
        st, _ = open(
            File(),
            "root://127.0.0.1:$port//open/keep.dat",
            OpenFlags.Update | OpenFlags.New,
        )
        @test isError(st) && st.code == FSC_ItExists

        # kXR_delete truncates on open.
        f = fs_file(port, "/open/keep.dat", OpenFlags.Update | OpenFlags.Delete)
        @test f isa File
        close(f)
        @test isempty(srv.nodes["/open/keep.dat"].data)

        # A directory is not openable.
        st, _ = open(File(), "root://127.0.0.1:$port//data/sub", OpenFlags.Read)
        @test isError(st) && st.code == FSC_isDirectory
        @test isempty(srv.violations)
    end

    @testset "kXR_open with kXR_retstat returns the stat line" begin
        fsc_reset!(srv)
        conn = XRootD.XrdCl.connection!(fs)
        hdr, body = XRootD.Session.roundtrip(
            conn,
            Wire.OpenRequest(
                "/data/a.txt"; options=(Wire.kXR_open_read | Wire.kXR_retstat)
            ),
        )
        @test hdr.status == Wire.kXR_ok
        opened = Wire.decode_open(body)
        @test opened.cpsize == 0                         # no compression descriptor
        @test opened.stat !== nothing && opened.stat.size == 5
        XRootD.Session.roundtrip(conn, Wire.CloseRequest(opened.fhandle))
        @test isempty(srv.violations)
    end

    @testset "kXR_mkdir and kXR_mkdirpath" begin
        fsc_reset!(srv)
        st, _ = mkdir(fs, "/mk")
        @test isOK(st) && srv.nodes["/mk"].dir

        st, _ = mkdir(fs, "/mk")                         # already there
        @test isError(st) && st.code == FSC_ItExists

        st, _ = mkdir(fs, "/mk/a/b")                     # missing intermediate
        @test isError(st) && st.code == FSC_NotFound
        @test !haskey(srv.nodes, "/mk/a")

        st, _ = mkdir(fs, "/mk/a/b"; mkpath=true)
        @test isOK(st) && srv.nodes["/mk/a"].dir && srv.nodes["/mk/a/b"].dir

        st, _ = mkdir(fs, "/mk/mode", 0o700)
        @test isOK(st) && srv.nodes["/mk/mode"].mode == 0o700
        @test isempty(srv.violations)
    end

    @testset "kXR_mv renames a whole subtree" begin
        fsc_reset!(srv)
        @test isOK(mkdir(fs, "/mv/from/inner"; mkpath=true)[1])
        f = fs_file(port, "/mv/from/inner/leaf", OpenFlags.Update | OpenFlags.New)
        @test f isa File
        write(f, "leaf")
        close(f)

        st, _ = mv(fs, "/mv/from", "/mv/to")
        @test isOK(st)
        @test !haskey(srv.nodes, "/mv/from") && !haskey(srv.nodes, "/mv/from/inner")
        @test srv.nodes["/mv/to"].dir
        @test srv.nodes["/mv/to/inner/leaf"].data == Vector{UInt8}("leaf")

        st, _ = mv(fs, "/mv/nowhere", "/mv/elsewhere")
        @test isError(st) && st.code == FSC_NotFound

        st, _ = mv(fs, "/mv/to", "/mv/to")                # the destination exists
        @test isError(st) && st.code == FSC_ItExists
        @test isempty(srv.violations)
    end

    @testset "kXR_chmod changes the mode the server reports" begin
        fsc_reset!(srv)
        @test isOK(mkdir(fs, "/chmod"; mkpath=true)[1])
        f = fs_file(port, "/chmod/f", OpenFlags.Update | OpenFlags.New)
        close(f)

        st, _ = chmod(fs, "/chmod/f", 0o400)
        @test isOK(st) && srv.nodes["/chmod/f"].mode == 0o400
        st, si = stat(fs, "/chmod/f")
        @test isOK(st) && isreadable(si) && !iswritable(si)

        st, _ = chmod(fs, "/chmod/f", Access.UR | Access.UW | Access.UX)
        @test isOK(st) && srv.nodes["/chmod/f"].mode == 0o700
        st, si = stat(fs, "/chmod/f")
        @test isOK(st) && iswritable(si) && isExecutable(si)

        st, _ = chmod(fs, "/chmod/nope", 0o644)
        @test isError(st) && st.code == FSC_NotFound
        @test isempty(srv.violations)
    end

    @testset "kXR_rm and kXR_rmdir are not interchangeable" begin
        fsc_reset!(srv)
        @test isOK(mkdir(fs, "/del/sub"; mkpath=true)[1])
        f = fs_file(port, "/del/sub/f", OpenFlags.Update | OpenFlags.New)
        close(f)

        st, _ = rm(fs, "/del/sub")                       # rm on a directory
        @test isError(st) && st.code == FSC_isDirectory
        st, _ = rmdir(fs, "/del/sub/f")                  # rmdir on a file
        @test isError(st) && st.code == FSC_NotFile
        st, _ = rmdir(fs, "/del/sub")                    # not empty
        @test isError(st) && st.code == FSC_ItExists
        @test haskey(srv.nodes, "/del/sub/f")

        st, _ = rm(fs, "/del/sub/f")
        @test isOK(st) && !haskey(srv.nodes, "/del/sub/f")
        st, _ = rmdir(fs, "/del/sub")
        @test isOK(st) && !haskey(srv.nodes, "/del/sub")

        st, _ = rm(fs, "/del/sub/f")                     # gone for good
        @test isError(st) && st.code == FSC_NotFound
        @test isempty(srv.violations)
    end

    @testset "kXR_truncate by path and by handle" begin
        fsc_reset!(srv)
        @test isOK(mkdir(fs, "/trunc"; mkpath=true)[1])
        f = fs_file(port, "/trunc/f", OpenFlags.Update | OpenFlags.New)
        write(f, "0123456789")
        close(f)

        st, _ = truncate(fs, "/trunc/f", Int64(4))
        @test isOK(st) && srv.nodes["/trunc/f"].data == Vector{UInt8}("0123")

        st, _ = truncate(fs, "/trunc/f", Int64(6))       # growing zero-fills
        @test isOK(st)
        @test srv.nodes["/trunc/f"].data == vcat(Vector{UInt8}("0123"), 0x00, 0x00)

        f = fs_file(port, "/trunc/f", OpenFlags.Update)
        st, _ = truncate(f, 2)                           # the handle form
        @test isOK(st) && srv.nodes["/trunc/f"].data == Vector{UInt8}("01")
        close(f)

        st, _ = truncate(fs, "/trunc", Int64(0))         # a directory has no length
        @test isError(st) && st.code == FSC_isDirectory
        @test isempty(srv.violations)
    end

    @testset "kXR_fattr: get, set, list and delete" begin
        fsc_reset!(srv)
        st, names = listxattr(fs, "/data/a.txt")
        @test isOK(st) && isempty(names)

        st, _ = setxattr(fs, "/data/a.txt", "user.one", Vector{UInt8}("first"))
        @test isOK(st)
        st, _ = setxattr(fs, "/data/a.txt", "user.two", UInt8[0x00, 0xff])
        @test isOK(st)
        @test srv.nodes["/data/a.txt"].xattr["user.one"] == Vector{UInt8}("first")

        st, value = getxattr(fs, "/data/a.txt", "user.one")
        @test isOK(st) && value == Vector{UInt8}("first")
        st, value = getxattr(fs, "/data/a.txt", "user.two")
        @test isOK(st) && value == UInt8[0x00, 0xff]     # values are binary, not text

        st, names = listxattr(fs, "/data/a.txt")
        @test isOK(st) && names == ["user.one", "user.two"]

        # A missing attribute fails per attribute; the request itself is a success,
        # so a client that only reads the request status reports a phantom hit.
        st, value = getxattr(fs, "/data/a.txt", "user.absent")
        @test isError(st) && st.code == FSC_AttrNotFound && value === nothing
        st, _ = removexattr(fs, "/data/a.txt", "user.absent")
        @test isError(st) && st.code == FSC_AttrNotFound

        st, _ = removexattr(fs, "/data/a.txt", "user.one")
        @test isOK(st) && !haskey(srv.nodes["/data/a.txt"].xattr, "user.one")
        st, names = listxattr(fs, "/data/a.txt")
        @test isOK(st) && names == ["user.two"]
        @test isOK(removexattr(fs, "/data/a.txt", "user.two")[1])

        st, _ = getxattr(fs, "/data/nope", "user.one")
        @test isError(st) && st.code == FSC_NotFound
        @test isempty(srv.violations)
    end

    @testset "kXR_query: checksum, config and unsupported codes" begin
        fsc_reset!(srv)
        # The digest is the adler32 of "hello", computed by the server and known
        # independently of either side's checksum code.
        st, cks = checksum(fs, "/data/a.txt")
        @test isOK(st) && cks == "adler32 062c0215"

        st, cks = checksum(fs, "/data/nope")
        @test isError(st) && st.code == FSC_NotFound

        st, cfg = query(fs, QueryCode.Config, "version")
        @test isOK(st) && strip(cfg) == "5.2.0"
        st, cfg = query(fs, QueryCode.Config, "role sitename")
        @test isOK(st) && split(strip(cfg), '\n') == ["server", "conformance"]
        st, cfg = query(fs, QueryCode.Config, "no.such.key")
        @test isOK(st) && strip(cfg) == "0"

        st, sp = query(fs, QueryCode.Space, "/data")
        @test isOK(st) && sp == "oss.space=1024&oss.free=512"

        st, _ = query(fs, QueryCode.Prepare, "/data")
        @test isError(st) && st.code == FSC_Unsupported
        @test isempty(srv.violations)

        # kXR_Qvisa names an open handle, so the path form reaches the server
        # as a query about no file at all — which is a protocol breach the
        # server is entitled to flag.
        fsc_reset!(srv)
        st, _ = query(fs, QueryCode.Visa, "/data")
        @test isError(st) && st.code == FSC_FileNotOpen
        @test !isempty(srv.violations)
        fsc_reset!(srv)
    end

    @testset "kXR_locate" begin
        fsc_reset!(srv)
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && length(locs) == 2
        @test locs[1].address == "127.0.0.1:1094"
        @test locs[1].node == 'S' && locs[1].access == 'r'
        @test locs[2].address == "127.0.0.2:1094"
        @test locs[2].node == 'M' && locs[2].access == 'w'

        st, locs = locate(fs, "/nope", 0)
        @test isError(st) && st.code == FSC_NotFound && locs === nothing
        @test isempty(srv.violations)
    end

    @testset "kXR_prepare" begin
        fsc_reset!(srv)
        st, handle = prepare(fs, ["/data/a.txt", "/data/b.bin"])
        @test isOK(st) && handle == "prep-0001"
        @test srv.paths == ["/data/a.txt", "/data/b.bin"]   # one request, both paths

        fsc_reset!(srv)
        st, _ = prepare(fs, ["/data/a.txt"]; stage=false, cancel=true, evict=true)
        @test isOK(st)
        @test fsc_op_names(srv) == ["kXR_prepare"]
        @test isempty(srv.violations)
    end

    @testset "symlink, hardlink and readlink" begin
        fsc_reset!(srv)
        @test isOK(mkdir(fs, "/link"; mkpath=true)[1])

        st, _ = symlink(fs, "/data/a.txt", "/link/soft")
        @test isOK(st) && srv.nodes["/link/soft"].link == "/data/a.txt"
        st, target = readlink(fs, "/link/soft")
        @test isOK(st) && target == "/data/a.txt"

        st, _ = symlink(fs, "/data/a.txt", "/link/soft")    # the link name is taken
        @test isError(st) && st.code == FSC_ItExists

        st, _ = hardlink(fs, "/data/a.txt", "/link/hard")
        @test isOK(st)
        @test srv.nodes["/link/hard"] === srv.nodes["/data/a.txt"]   # the same node
        st, _ = hardlink(fs, "/data/sub", "/link/dir")
        @test isError(st) && st.code == FSC_isDirectory

        st, target = readlink(fs, "/link/hard")             # a hard link has no target
        @test isError(st) && st.code == FSC_ArgInvalid && target === nothing
        st, _ = readlink(fs, "/link/nope")
        @test isError(st) && st.code == FSC_NotFound
        @test isempty(srv.violations)
    end

    @testset "kXR_setattr carries the 44-byte prefix" begin
        fsc_reset!(srv)
        conn = XRootD.XrdCl.connection!(fs)
        hdr, body = XRootD.Session.roundtrip(
            conn,
            Wire.SetattrRequest(
                "/data/a.txt";
                flags=(Wire.kXR_sa_times | Wire.kXR_sa_owner),
                atime=(1_700_000_001, 0),
                mtime=(1_700_000_002, 0),
                uid=1000,
                gid=1000,
            ),
        )
        @test hdr.status == Wire.kXR_ok && isempty(body)
        @test fsc_op_names(srv) == ["kXR_setattr"]
        @test srv.paths == ["/data/a.txt"]
        @test isempty(srv.violations)
    end

    @testset "walkdir visits every directory, in order" begin
        fsc_reset!(srv)
        top = collect(walkdir(fs, "/data"))
        @test [t[1] for t in top] == ["/data", "/data/sub", "/data/sub/deep"]
        @test top[1][2] == ["sub"] && top[1][3] == ["a.txt", "b.bin"]
        @test top[3][3] == ["c.dat"]

        bottom = collect(walkdir(fs, "/data"; topdown=false))
        @test [t[1] for t in bottom] == ["/data/sub/deep", "/data/sub", "/data"]

        # An unreadable root closes the channel rather than yielding an empty walk.
        @test_throws Exception collect(walkdir(fs, "/nope"))
        @test isempty(srv.violations)
    end

    @testset "copy pumps the bytes the server ends up holding" begin
        fsc_reset!(srv)
        st, _ = copy(fs, "/data/a.txt", "/copy/out.txt")
        @test isOK(st)
        @test srv.nodes["/copy/out.txt"].data == Vector{UInt8}("hello")

        st, _ = copy(fs, "/data/a.txt", "/copy/out.txt")     # kXR_new refuses
        @test isError(st) && st.code == FSC_ItExists

        st, _ = copy(fs, "/data/b.bin", "/copy/out.txt"; force=true)
        @test isOK(st)
        @test srv.nodes["/copy/out.txt"].data == UInt8[0x00, 0x01, 0x02, 0x03]

        st, _ = copy(fs, "/data/nope", "/copy/never.txt")
        @test isError(st) && st.code == FSC_NotFound
        @test !haskey(srv.nodes, "/copy/never.txt")

        # A copy that cannot reach its endpoint at all reports a status
        # rather than throwing out of the connect.
        st, _ = copy(FileSystem("root://127.0.0.1:1"), "/a", "/b")
        @test isError(st)
        @test isempty(srv.violations)
    end

    @testset "every namespace request closed its file handles" begin
        @test isempty(srv.handles)
    end
end
