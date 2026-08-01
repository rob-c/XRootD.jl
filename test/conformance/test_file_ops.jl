# The File handle's own contract, driven against the namespace conformance
# server: what an open handle is, what happens to one that is closed or was
# never opened, and that bytes written through it are what the server ends up
# holding. The open *modes* are conformance-tested in test_fs.jl; this file is
# about the lifecycle around them.
#
# The rules mirror the ones the reference clients are held to: a handle that
# is not open answers with a status rather than reaching the wire, a second
# open on the same handle is refused instead of leaking the first, and a read
# at or past the end of a file is an empty read, not an error.

using XRootD.XrdCl
using XRootD: Wire

@testset "conformance: the File handle's contract" begin
    srv, port = start_conf_fs([
        "/f/data.bin" => "0123456789", "/f/empty.bin", "/f/text" => "one\ntwo\n", "/f/sub/"
    ])
    furl(path) = "root://127.0.0.1:$port/$path"

    @testset "isopen follows the handle, and a second open is refused" begin
        fsc_reset!(srv)
        f = File()
        @test !isopen(f)

        st, _ = open(f, furl("/f/data.bin"), OpenFlags.Read)
        @test isOK(st) && isopen(f)

        # Opening again would leak the handle the server already issued, so
        # the client refuses it without asking.
        st2, _ = open(f, furl("/f/empty.bin"), OpenFlags.Read)
        @test isError(st2) && occursin("already open", st2.message)
        @test fsc_op_count(srv, Wire.kXR_open) == 1

        # ... and the first handle is untouched by the refusal.
        st, data = read(f, 4, 0)
        @test isOK(st) && String(copy(data)) == "0123"

        close(f)
        @test !isopen(f)
        @test isempty(srv.handles)

        # A closed handle is reusable: it is a handle, not a file.
        st, _ = open(f, furl("/f/text"), OpenFlags.Read)
        @test isOK(st) && isopen(f)
        close(f)
        @test isempty(srv.violations)
    end

    @testset "closing twice is a no-op, and the second close sends nothing" begin
        fsc_reset!(srv)
        f = fs_file(port, "/f/data.bin")
        @test f isa File
        st, _ = close(f)
        @test isOK(st)
        st, _ = close(f)
        @test isOK(st)
        @test fsc_op_count(srv, Wire.kXR_close) == 1
        @test isempty(srv.handles)
        @test isempty(srv.violations)
    end

    @testset "every operation on a handle that is not open is a status" begin
        fsc_reset!(srv)
        f = File()
        buf = Vector{UInt8}(undef, 4)
        cases = [
            ("read", () -> read(f, 4)),
            ("read at offset", () -> read(f, 4, 2)),
            ("readline", () -> readline(f)),
            ("readlines", () -> readlines(f)),
            ("write", () -> write(f, "x")),
            ("write bytes", () -> write(f, buf, 4)),
            ("stat", () -> stat(f)),
            ("truncate", () -> truncate(f, 0)),
            ("sync", () -> sync(f)),
            ("readv", () -> readv(f, [(0, 4)])),
            ("writev", () -> writev(f, [(0, buf)])),
            ("pgread", () -> pgread(f, 4)),
            ("pgwrite", () -> pgwrite(f, buf)),
        ]
        for (name, call) in cases
            st, result = call()
            @test isError(st)
            @test occursin("not open", st.message)
            # `unsafe_read` reports a byte count, everything else a value.
            @test result === nothing || result == 0
        end
        st, n = unsafe_read(f, pointer(buf), 4)
        @test isError(st) && n == 0

        # None of that reached the server: a closed handle is a local answer.
        @test isempty(srv.ops)
        @test isempty(srv.violations)
    end

    @testset "a read at or past the end of the file is empty, not an error" begin
        fsc_reset!(srv)
        f = fs_file(port, "/f/data.bin")
        @test f isa File

        st, data = read(f, 4, 6)                 # the last four bytes
        @test isOK(st) && String(copy(data)) == "6789"

        st, data = read(f, 100, 5)               # more than is there
        @test isOK(st) && String(copy(data)) == "56789"

        st, data = read(f, 10, 10)               # exactly at the end
        @test isOK(st) && isempty(data)
        @test eof(f)

        st, data = read(f, 10, 4096)             # far past it
        @test isOK(st) && isempty(data)

        # An empty file is all end: the first read is already empty.
        close(f)
        f = fs_file(port, "/f/empty.bin")
        @test eof(f)
        st, data = read(f, 16)
        @test isOK(st) && isempty(data)
        close(f)
        @test isempty(srv.violations)
    end

    @testset "the size captured at open is the one eof compares against" begin
        fsc_reset!(srv)
        f = fs_file(port, "/f/data.bin")
        @test f.filesize == 10
        @test !eof(f)

        # readline advances the cursor; read does not.
        close(f)
        f = fs_file(port, "/f/text")
        st, line = readline(f)
        @test isOK(st) && line == "one\n"
        @test f.currentOffset == 4
        st, _ = read(f, 3)
        @test isOK(st) && f.currentOffset == 4
        st, line = readline(f)
        @test isOK(st) && line == "two\n" && eof(f)
        st, line = readline(f)
        @test isOK(st) && line == ""             # EOF is an empty line, not an error
        close(f)
        @test isempty(srv.violations)
    end

    @testset "bytes written through a handle survive sync, close and reopen" begin
        fsc_reset!(srv)
        f = fs_file(port, "/f/new.bin", OpenFlags.Update | OpenFlags.New)
        @test f isa File
        st, _ = write(f, "hello world")
        @test isOK(st)
        st, _ = sync(f)
        @test isOK(st)
        # The server holds the bytes before the close, not because of it.
        @test srv.nodes["/f/new.bin"].data == Vector{UInt8}("hello world")
        close(f)

        f = fs_file(port, "/f/new.bin")
        @test f.filesize == 11
        st, data = read(f, 11)
        @test isOK(st) && String(copy(data)) == "hello world"

        # A write inside the file replaces those bytes and nothing else.
        close(f)
        f = fs_file(port, "/f/new.bin", OpenFlags.Update)
        st, _ = write(f, "HELLO", 6)
        @test isOK(st)
        close(f)
        @test String(copy(srv.nodes["/f/new.bin"].data)) == "hello HELLO"

        # Truncating by handle is what the next open sees.
        f = fs_file(port, "/f/new.bin", OpenFlags.Update)
        st, _ = truncate(f, 5)
        @test isOK(st)
        st, si = stat(f)
        @test isOK(st) && si.size == 5
        close(f)
        f = fs_file(port, "/f/new.bin")
        @test f.filesize == 5
        st, data = read(f, 16)
        @test isOK(st) && String(copy(data)) == "hello"
        close(f)

        @test isempty(srv.handles)
        @test isempty(srv.violations)
    end

    @testset "stat by handle agrees with stat by path" begin
        fsc_reset!(srv)
        fs = conf_fs(port)
        f = fs_file(port, "/f/data.bin")
        st, byhandle = stat(f)
        @test isOK(st)
        st, bypath = stat(fs, "/f/data.bin")
        @test isOK(st)
        @test byhandle.size == bypath.size == 10
        @test byhandle.flags == bypath.flags
        @test byhandle.modtime == bypath.modtime == FSC_MTIME
        @test isfile(byhandle) && !isdir(byhandle)
        close(f)

        # The handle form carries no path, so the namespace is not consulted:
        # the server saw one path-bearing request, the open.
        @test srv.paths == ["/f/data.bin", "/f/data.bin"]
        @test isempty(srv.violations)
    end
end
