# Fail-closed conformance: a server that stops, over-answers, or corrupts must
# never be reported as success. Each case drives the strict server from
# conformance/server.jl into a specific misbehaviour and asserts the client
# fails with a diagnosable status instead of returning plausible bytes.

using XRootD.XrdCl
using XRootD.XrdCl: sync, readv, pgread, pgwrite
using XRootD.Storage: storage_for, storage_read, storage_write

@testset "conformance: fail-closed against a misbehaving server" begin
    srv, port = start_conf_server(CONF_CONTENT)

    @testset "a read answered with more than was asked for is refused" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        srv.over_answer = 8
        st, buf = read(f, 64, 0)
        @test isError(st)
        @test buf === nothing
        @test occursin("exceeds the 64-byte cap", st.message)
        srv.over_answer = 0
        st, buf = read(f, 64, 0)                       # the connection survives
        @test isOK(st) && buf == CONF_CONTENT[1:64]
        close(f)
    end

    @testset "a body past DLEN_MAX is refused before it is allocated" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        srv.huge_dlen = true
        st, _ = read(f, 16, 0)
        @test isError(st)
        @test occursin("lost", st.message)             # reader refused, link torn down
        close(f)
    end

    @testset "pgread integrity failures are not returned as data" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)

        srv.corrupt_page = true
        st, data = pgread(f, 5000, 0)                  # CRC32c mismatch on page 1
        @test isError(st) && data === nothing
        @test occursin("integrity failure", st.message)

        srv.short_pgdlen = true
        st, data = pgread(f, 5000, 0)                  # page unit cut off
        @test isError(st) && data === nothing
        @test occursin("integrity failure", st.message)

        st, data = pgread(f, 64, 0)                    # still usable afterwards
        @test isOK(st) && data == CONF_CONTENT[1:64]
        close(f)
    end

    @testset "a readv reply missing a segment is a failure, not a short read" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        srv.drop_readv = Set([4096])
        st, got = readv(f, [(0, 16), (4096, 16), (8192, 16)])
        @test isError(st) && got === nothing
        @test occursin("2 of 3 segments", st.message)
        empty!(srv.drop_readv)
        st, got = readv(f, [(0, 16), (4096, 16)])
        @test isOK(st) && length(got) == 2
        close(f)
    end

    @testset "pgwrite gives up on a page that never checksums" begin
        wsrv, wport = start_conf_server()
        f = conf_file(wport)
        wsrv.bad_always = Set([0])
        st, _ = pgwrite(f, CONF_CONTENT[1:100], 0)
        @test isError(st)
        @test occursin("still corrupt after $(Wire.PGW_MAX_RETRY) retries", st.message)
        # the initial write plus exactly the retry budget, no more
        @test count(==(Wire.kXR_pgwrite), wsrv.ops) == 1 + Wire.PGW_MAX_RETRY
        close(f)
        @test isempty(wsrv.violations)
    end

    @testset "XRDC_STALL_DEADLINE_MS configures the deadline" begin
        c = withenv("XRDC_STALL_DEADLINE_MS" => "1234") do
            return Session.connect("127.0.0.1", port)
        end
        @test c.stall_deadline_ms == 1234
        close(c)
        c = withenv("XRDC_STALL_DEADLINE_MS" => "not-a-number") do
            return Session.connect("127.0.0.1", port)
        end
        @test c.stall_deadline_ms == Session.DEFAULT_STALL_DEADLINE_MS
        close(c)
    end

    @testset "the stall deadline bounds a server that stops answering" begin
        f = conf_file(port, OpenFlags.Read; stall_ms=300)
        conf_reset!(srv)
        srv.stall = true
        t0 = time()
        st, _ = read(f, 64, 0)
        @test isError(st)
        @test occursin("stall deadline", st.message)
        @test time() - t0 < 5.0
        srv.stall = false
        close(f)
    end

    @testset "storage_read reports a stopped transfer as :truncated" begin
        tsrv, tport = start_conf_server(CONF_CONTENT)
        b = storage_for("root://127.0.0.1:$tport//conf")
        sink = IOBuffer()
        @test storage_read(b, sink) == :ok
        @test take!(sink) == CONF_CONTENT

        tsrv.read_limit = 4096                          # server stops mid-object
        sink = IOBuffer()
        @test storage_read(b, sink) == :truncated
        @test length(take!(sink)) == 4096               # the prefix is not a result
        @test isempty(tsrv.violations)
    end

    @testset "storage_write publishes only when sync and close both succeed" begin
        wsrv, wport = start_conf_server()
        b = storage_for("root://127.0.0.1:$wport//conf")
        payload = CONF_CONTENT[1:2048]

        @test storage_write(b, IOBuffer(payload)) == :ok
        @test wsrv.data == payload
        names = op_names(wsrv)
        @test "kXR_sync" in names && "kXR_close" in names
        @test findlast(==("kXR_sync"), names) < findlast(==("kXR_close"), names)

        wsrv.fail_sync = true
        @test storage_write(b, IOBuffer(payload)) == :error
        wsrv.fail_sync = false

        wsrv.fail_close = true
        @test storage_write(b, IOBuffer(payload)) == :error
        wsrv.fail_close = false

        @test storage_write(b, IOBuffer(payload)) == :ok
        @test isempty(wsrv.violations)
    end
end
