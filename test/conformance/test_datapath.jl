# kXR_bind conformance: a second connection joins an existing session and
# carries the bulk bytes for it. The strict server in conformance/server.jl
# refuses to guess — a read answered on the wrong link, a write whose data was
# left in the control frame, or a bind that names a session it never issued
# all land in `srv.violations`.

using XRootD.XrdCl
using XRootD.XrdCl: bind_data_path!

@testset "conformance: kXR_bind data paths" begin
    srv, port = start_conf_server(CONF_CONTENT)

    @testset "a bind attaches a second link to the session" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        st, pathid = bind_data_path!(f)
        @test isOK(st)
        @test pathid != 0x00
        @test f.pathid == pathid
        @test Session.has_data_path(f.conn, pathid)
        @test Session.data_paths(f.conn) == [pathid]
        # The bind presented the session id the login reply gave out — the
        # server flags any other — and did NOT log in a second time.
        @test length(srv.logins) == 1
        @test Wire.kXR_bind in srv.ops
        close(f)
        @test isempty(srv.violations)
    end

    @testset "reads come back on the path they asked for" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        st, _ = bind_data_path!(f)
        @test isOK(st)

        st, buf = read(f, length(CONF_CONTENT), 0)
        @test isOK(st) && buf == CONF_CONTENT

        # Reassembly over the path is the same problem as over the control
        # link: chunked replies still have to be stitched back together.
        srv.read_chunk = 997
        st, buf = read(f, length(CONF_CONTENT), 0)
        @test isOK(st) && buf == CONF_CONTENT
        srv.read_chunk = 0

        # A kXR_wait arrives on the control link while the data is routed;
        # both are matched by the same streamid.
        srv.wait_once = true
        st, buf = read(f, 16, 0)
        @test isOK(st) && buf == CONF_CONTENT[1:16]

        # An explicit offset repositions the cursor, path or no path.
        st, buf = read(f, 1000, 4096)
        @test isOK(st) && buf == CONF_CONTENT[4097:5096]
        @test f.currentOffset == 4096

        close(f)
        @test isempty(srv.violations)
    end

    @testset "writes put their data on the path and nowhere else" begin
        conf_reset!(srv)
        srv.data = copy(CONF_CONTENT)
        f = conf_file(port, OpenFlags.Update)
        st, _ = bind_data_path!(f)
        @test isOK(st)

        payload = Vector{UInt8}(codeunits("bound-path payload"))
        st, _ = write(f, payload, length(payload), 100)
        @test isOK(st)
        @test srv.data[101:(100 + length(payload))] == payload

        # The control link is still usable for everything else — which is the
        # entire point of moving the data off it.
        st, si = stat(f)
        @test isOK(st) && si.size == length(srv.data)

        close(f)
        @test isempty(srv.violations)
    end

    @testset "the control link and the data path interleave" begin
        conf_reset!(srv)
        srv.data = copy(CONF_CONTENT)
        f = conf_file(port, OpenFlags.Update)
        st, _ = bind_data_path!(f)
        @test isOK(st)

        # Concurrent reads and stats on one session: every reply must find its
        # own streamid whichever socket it came in on.
        results = Vector{Any}(undef, 8)
        @sync for i in 1:8
            Threads.@spawn begin
                results[i] = if isodd(i)
                    st, buf = read(f, 512, 512 * i)
                    isOK(st) && buf == srv.data[(512i + 1):(512i + 512)]
                else
                    st, si = stat(f)
                    isOK(st) && si.size == length(srv.data)
                end
            end
        end
        @test all(results)
        close(f)
        @test isempty(srv.violations)
    end

    @testset "a path that dies costs only what it was carrying" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        st, pathid = bind_data_path!(f)
        @test isOK(st)
        conn = f.conn

        close(srv.paths[pathid])
        delete!(srv.paths, pathid)
        # The reader Task notices at its own pace; the session stays up.
        for _ in 1:200
            Session.has_data_path(conn, pathid) || break
            sleep(0.01)
        end
        @test !Session.has_data_path(conn, pathid)
        @test isopen(conn)

        # A file that lost its path falls back to the control link rather than
        # naming an id the server no longer knows.
        @test XRootD.XrdCl.data_pathid(f) == 0x00
        st, buf = read(f, 64, 0)
        @test isOK(st) && buf == CONF_CONTENT[1:64]

        close(f)
        @test isempty(srv.violations)
    end

    @testset "a refused bind leaves the session as it was" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        srv.refuse_bind = true
        st, pathid = bind_data_path!(f)
        srv.refuse_bind = false
        @test isError(st)
        @test pathid == 0x00
        @test isempty(Session.data_paths(f.conn))
        # The control link never noticed.
        st, buf = read(f, 32, 0)
        @test isOK(st) && buf == CONF_CONTENT[1:32]
        close(f)
        @test isempty(srv.violations)
    end

    @testset "path id 0 is refused" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        srv.bind_zero = true
        st, pathid = bind_data_path!(f)
        srv.bind_zero = false
        @test isError(st)
        @test pathid == 0x00
        @test occursin("path id 0", st.message)
        @test isempty(Session.data_paths(f.conn))
        close(f)
        @test isempty(srv.violations)
    end

    @testset "closing the session closes the paths it bound" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        st, pathid = bind_data_path!(f)
        @test isOK(st)
        conn = f.conn
        sock = srv.paths[pathid]
        close(f)
        # From the server's side a closed peer shows as EOF, not as a closed
        # socket: nothing has read the FIN yet.
        gone = Threads.@spawn eof(sock)
        @test timedwait(() -> istaskdone(gone), 5.0) === :ok
        @test fetch(gone)
        @test isempty(Session.data_paths(conn))
    end

    @testset "an unbound path id is refused before anything is sent" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        conn = f.conn
        hdr, body = Session.roundtrip(
            conn, Wire.ReadRequest(f.fhandle, Int64(0), Int32(16); pathid=0x7f)
        )
        @test hdr.status == Wire.kXR_error
        @test occursin("no data path 127", String(copy(body[5:end])))
        # Nothing reached the server, so the session is still in step.
        st, buf = read(f, 16, 0)
        @test isOK(st) && buf == CONF_CONTENT[1:16]
        close(f)
        @test isempty(srv.violations)
    end
end
