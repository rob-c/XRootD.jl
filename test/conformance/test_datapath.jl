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
        @test f.pathids == [pathid]
        @test Session.has_data_path(f.conn, pathid)
        @test Session.data_paths(f.conn) == [pathid]
        # The bind presented the session id the login reply gave out — the
        # server flags any other — and did NOT log in a second time.
        @test length(srv.logins) == 1
        @test Wire.kXR_bind in srv.ops
        close(f)
        @test isempty(srv.violations)
    end

    @testset "open binds the default data streams by itself" begin
        # The library default is one extra data stream, so a plain open — the
        # way a caller who set nothing gets — comes back already bound, and its
        # reads and writes ride the data path with no explicit bind call.
        conf_reset!(srv)
        withenv("XRDC_DATA_STREAMS" => nothing, "XRD_SUBSTREAMSPERCHANNEL" => nothing) do
            f = XRootD.XrdCl.File("root://127.0.0.1:$port//conf", OpenFlags.Read)
            @test length(f.pathids) == 1
            @test XRootD.XrdCl.data_pathid(f) == f.pathids[1]
            st, buf = read(f, length(CONF_CONTENT), 0)
            @test isOK(st) && buf == CONF_CONTENT
            close(f)
        end
        @test Wire.kXR_bind in srv.ops
        @test length(srv.logins) == 1        # the data path bound, it did not re-login
        @test isempty(srv.violations)

        # data_streams=0 keeps everything on the control link: no bind, no path.
        conf_reset!(srv)
        f0 = XRootD.XrdCl.File("root://127.0.0.1:$port//conf", OpenFlags.Read; data_streams=0)
        @test isempty(f0.pathids)
        @test XRootD.XrdCl.data_pathid(f0) == 0x00
        @test !(Wire.kXR_bind in srv.ops)
        close(f0)
        @test isempty(srv.violations)

        # Several streams bind several links and hand requests out round-robin.
        conf_reset!(srv)
        f3 = XRootD.XrdCl.File("root://127.0.0.1:$port//conf", OpenFlags.Read; data_streams=3)
        @test length(f3.pathids) == 3
        @test allunique(f3.pathids)
        seq = [XRootD.XrdCl.data_pathid(f3) for _ in 1:6]
        @test seq == vcat(f3.pathids, f3.pathids)   # two full cycles of the three
        close(f3)
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

    @testset "a server that answers the substreams probe gets whole frames" begin
        # BriX's whole-frame mode: a server that answers the kXR_Qconfig
        # "brix.substreams" probe with "=rw" takes complete request frames on
        # the bound path — header, data and all — instead of the split
        # header-on-control, data-on-path framing. A stock server just echoes
        # the unknown key back, which reads as "no".
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        st, _ = bind_data_path!(f)
        @test isOK(st)
        @test Wire.kXR_query in srv.ops     # the probe was asked at bind time
        @test f.conn.substreams_rw === false
        @test isempty(srv.path_ops)
        close(f)
        @test isempty(srv.violations)

        conf_reset!(srv)
        srv.data = copy(CONF_CONTENT)
        srv.substreams_rw = true
        f = conf_file(port, OpenFlags.Update)
        st, _ = bind_data_path!(f)
        @test isOK(st)
        @test f.conn.substreams_rw === true

        st, buf = read(f, 512, 0)
        @test isOK(st) && buf == CONF_CONTENT[1:512]
        payload = Vector{UInt8}(codeunits("whole-frame payload"))
        st, _ = write(f, payload, length(payload), 200)
        @test isOK(st)
        @test srv.data[201:(200 + length(payload))] == payload
        # Both rode the path whole — the server flags a whole-frame request
        # that still names a path id, so an empty violation list means the
        # re-encoding dropped it as it must.
        @test srv.path_ops == [Wire.kXR_read, Wire.kXR_write]

        # The control link still carries everything that is not bulk data.
        st, si = stat(f)
        @test isOK(st) && si.size == length(srv.data)
        @test !(Wire.kXR_stat in srv.path_ops)

        close(f)
        @test isempty(srv.violations)
    end

    @testset "a refused routed write latches back to the control link" begin
        # The case BriX documents: a proxy binds paths happily but answers a
        # path-routed kXR_write with kXR_Unsupported. The client retries that
        # write inline and stops routing writes for the file — reads keep the
        # path, and no further refusal round-trips are paid.
        conf_reset!(srv)
        srv.data = copy(CONF_CONTENT)
        srv.refuse_routed_write = true
        f = conf_file(port, OpenFlags.Update)
        st, _ = bind_data_path!(f)
        @test isOK(st)

        payload = Vector{UInt8}(codeunits("latched payload"))
        st, _ = write(f, payload, length(payload), 100)
        @test isOK(st)
        @test srv.routed_write_refusals == 1
        @test srv.data[101:(100 + length(payload))] == payload

        st, _ = write(f, payload, length(payload), 400)
        @test isOK(st)
        @test srv.routed_write_refusals == 1    # went inline first time
        @test srv.data[401:(400 + length(payload))] == payload

        st, buf = read(f, 64, 0)
        @test isOK(st) && buf == srv.data[1:64]

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
