# Read/write protocol conformance: every operation is driven through the
# strict server in conformance/server.jl, which parses the client's frames the
# way stock XrdXrootd does and keeps a real in-memory file. Each testset
# asserts three things: the operation's own result, the bytes the SERVER ended
# up holding, and that the server logged no protocol violation.

using XRootD.XrdCl
using XRootD.XrdCl: sync, readv, writev, pgread, pgwrite

@testset "conformance: read/write over a strict server" begin
    srv, port = start_conf_server(CONF_CONTENT)

    @testset "bring-up and open" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        @test f isa File
        @test f.fhandle == CONF_FHANDLE
        st, si = stat(f)
        @test isOK(st) && si.size == length(CONF_CONTENT)
        close(f)
        @test isempty(srv.violations)
        @test Wire.kXR_close in srv.ops
    end

    @testset "kXR_read: ranges, EOF and the cursor contract" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        st, buf = read(f, length(CONF_CONTENT))
        @test isOK(st) && buf == CONF_CONTENT

        st, buf = read(f, 1000, 4096)                    # explicit offset
        @test isOK(st) && buf == CONF_CONTENT[4097:5096]
        @test f.currentOffset == 4096                    # read does not advance

        st, buf = read(f, 500)                           # re-reads at the cursor
        @test isOK(st) && buf == CONF_CONTENT[4097:4596]

        st, buf = read(f, 4096, length(CONF_CONTENT) - 10)   # short at EOF
        @test isOK(st) && buf == CONF_CONTENT[(end - 9):end]

        st, buf = read(f, 100, length(CONF_CONTENT))     # entirely past EOF
        @test isOK(st) && isempty(buf)

        close(f)
        @test isempty(srv.violations)
    end

    @testset "kXR_read: reply shapes the client must reassemble" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)

        srv.read_chunk = 997                             # kXR_oksofar chunking
        st, buf = read(f, length(CONF_CONTENT), 0)
        @test isOK(st) && buf == CONF_CONTENT
        srv.read_chunk = 0

        srv.wait_once = true                             # kXR_wait then the data
        t0 = time()
        st, buf = read(f, 16, 0)
        @test isOK(st) && buf == CONF_CONTENT[1:16]
        @test time() - t0 >= 0.9

        srv.async_read = true                            # kXR_attn/kXR_asynresp
        st, buf = read(f, 32, 64)
        @test isOK(st) && buf == CONF_CONTENT[65:96]

        srv.unsolicited = true                           # a frame for no streamid
        st, buf = read(f, 8, 128)
        @test isOK(st) && buf == CONF_CONTENT[129:136]

        close(f)
        @test isempty(srv.violations)
    end

    @testset "unsafe_read fills a caller buffer" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        buf = zeros(UInt8, 256)
        st, n = GC.@preserve buf unsafe_read(f, pointer(buf), 256, 1024)
        @test isOK(st) && n == 256
        @test buf == CONF_CONTENT[1025:1280]
        @test f.currentOffset == 0                       # independent of the cursor
        close(f)
        @test isempty(srv.violations)
    end

    @testset "readline / readlines walk a text file" begin
        text, tport = start_conf_server(Vector{UInt8}(codeunits("alpha\nbeta\ngamma")))
        f = conf_file(tport, OpenFlags.Read)
        st, lines = readlines(f)
        @test isOK(st) && lines == ["alpha\n", "beta\n", "gamma"]
        @test eof(f)
        close(f)
        @test isempty(text.violations)
    end

    @testset "kXR_write: the server holds exactly what was sent" begin
        wsrv, wport = start_conf_server()
        f = conf_file(wport)

        st, _ = write(f, "hello world", 0)
        @test isOK(st)
        @test wsrv.data == Vector{UInt8}(codeunits("hello world"))

        st, _ = write(f, collect(0x00:0xff), 256, 1024)  # sparse: a hole is zeros
        @test isOK(st)
        @test length(wsrv.data) == 1280
        @test wsrv.data[1025:1280] == collect(0x00:0xff)
        @test all(iszero, wsrv.data[12:1024])

        st, _ = write(f, collect(0xf0:0xff), 4, 0)       # only `size` bytes go out
        @test isOK(st)
        @test wsrv.data[1:4] == UInt8[0xf0, 0xf1, 0xf2, 0xf3]

        st, _ = truncate(f, 8)
        @test isOK(st) && length(wsrv.data) == 8
        st, _ = sync(f)
        @test isOK(st)

        close(f)
        @test isempty(wsrv.violations)
        @test op_names(wsrv)[(end - 1):end] == ["kXR_sync", "kXR_close"]
    end

    @testset "kXR_readv: segments come back in request order" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        chunks = [(0, 16), (4096, 32), (9990, 10), (123, 1)]
        st, got = readv(f, chunks)
        @test isOK(st)
        @test length(got) == 4
        for (i, (off, len)) in enumerate(chunks)
            @test got[i] == CONF_CONTENT[(off + 1):(off + len)]
        end

        st, got = readv(f, [(9995, 100)])                # clipped at EOF
        @test isOK(st) && got[1] == CONF_CONTENT[9996:end]

        close(f)
        @test isempty(srv.violations)
    end

    @testset "kXR_writev: dlen frames the descriptors, data trails outside" begin
        wsrv, wport = start_conf_server()
        f = conf_file(wport)
        # The server reads sum(wlen) trailing bytes after a dlen == N*16 frame;
        # any other framing desynchronizes it, so landing the right bytes here
        # is the conformance proof for the trailer layout.
        segs = [
            (0, Vector{UInt8}(codeunits("first"))),
            (100, Vector{UInt8}(codeunits("second"))),
            (4090, collect(0x01:0x10)),
        ]
        st, _ = writev(f, segs; do_sync=true)
        @test isOK(st)
        @test wsrv.data[1:5] == Vector{UInt8}(codeunits("first"))
        @test wsrv.data[101:106] == Vector{UInt8}(codeunits("second"))
        @test wsrv.data[4091:4106] == collect(0x01:0x10)
        @test length(wsrv.data) == 4106

        st, _ = writev(f, [(0, UInt8[0xaa])])            # single segment, no sync
        @test isOK(st) && wsrv.data[1] == 0xaa

        close(f)
        @test isempty(wsrv.violations)
    end

    @testset "kXR_pgread: CRC-verified pages, aligned and not" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)

        st, data = pgread(f, 10, 0)                      # inside one page
        @test isOK(st) && data == CONF_CONTENT[1:10]

        st, data = pgread(f, 2 * CONF_PAGE, 0)           # exactly two pages
        @test isOK(st) && data == CONF_CONTENT[1:(2 * CONF_PAGE)]

        st, data = pgread(f, 5000, 100)                  # unaligned start
        @test isOK(st) && data == CONF_CONTENT[101:5100]

        st, data = pgread(f, length(CONF_CONTENT), 0)    # whole file, 3 pages
        @test isOK(st) && data == CONF_CONTENT

        st, data = pgread(f, 64, length(CONF_CONTENT))   # past EOF
        @test isOK(st) && isempty(data)

        close(f)
        @test isempty(srv.violations)
    end

    @testset "kXR_pgwrite: page units the server can verify" begin
        wsrv, wport = start_conf_server()
        f = conf_file(wport)

        payload = CONF_CONTENT[1:6000]
        st, _ = pgwrite(f, payload, 0)                   # spans a page boundary
        @test isOK(st) && wsrv.data[1:6000] == payload

        st, _ = pgwrite(f, CONF_CONTENT[1:5000], 100)    # unaligned: short first page
        @test isOK(st) && wsrv.data[101:5100] == CONF_CONTENT[1:5000]

        st, _ = pgwrite(f, UInt8[0x42], CONF_PAGE - 1)   # last byte of a page
        @test isOK(st) && wsrv.data[CONF_PAGE] == 0x42

        close(f)
        @test isempty(wsrv.violations)                   # every CRC32c checked out
    end

    @testset "kXR_pgwrite: a corrupt page is resent with kXR_pgRetry" begin
        wsrv, wport = start_conf_server()
        f = conf_file(wport)
        payload = CONF_CONTENT[1:(CONF_PAGE + 500)]
        wsrv.bad_once = Set([0, CONF_PAGE])              # both pages, once each
        st, _ = pgwrite(f, payload, 0)
        @test isOK(st)
        @test wsrv.data[1:length(payload)] == payload
        # the original write plus one retry per reported page
        @test count(==(Wire.kXR_pgwrite), wsrv.ops) == 3
        close(f)
        @test isempty(wsrv.violations)                   # retries were single pages
    end
end
