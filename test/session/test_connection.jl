using Sockets
using CRC32c: crc32c
using XRootD: Wire, Session

# Byte helpers for scripting the mock server.
function resp_hdr(sid::UInt16, status::UInt16, dlen::Integer)
    h = zeros(UInt8, 8)
    Wire.set_u16!(h, 1, sid)
    Wire.set_u16!(h, 3, status)
    Wire.set_u32!(h, 5, UInt32(dlen))
    return h
end

be32(v::Integer) = Wire.set_u32!(zeros(UInt8, 4), 1, UInt32(v))

"One complete kXR_status wire frame: hdr(dlen=24) + CRC'd body + page trailer."
function status_frame(sid::UInt16, resptype::UInt8, offset::Integer, pages::Vector{UInt8})
    sb = zeros(UInt8, 24)
    Wire.set_u16!(sb, 5, sid)
    sb[7] = 0x1e                          # requestid echo (pgread - 3000)
    sb[8] = resptype
    Wire.set_u32!(sb, 13, UInt32(length(pages)))
    Wire.set_u64!(sb, 17, UInt64(offset))
    Wire.set_u32!(sb, 1, crc32c(sb[5:24]))
    return vcat(resp_hdr(sid, Wire.kXR_status, 24), sb, pages)
end

req_sid(frame::Vector{UInt8}) = Wire.get_u16(frame, 1)
req_id(frame::Vector{UInt8}) = Wire.get_u16(frame, 3)

"Read one client request; returns (24-byte header, payload bytes)."
function read_request(sock)
    frame = read(sock, 24)
    dlen = Wire.get_u32(frame, 21)
    payload = dlen > 0 ? read(sock, Int(dlen)) : UInt8[]
    return frame, payload
end

"Serve the scripted bring-up: handshake + protocol + anonymous login."
function serve_bringup(sock)
    read(sock, 20)                                        # client hello
    write(sock, vcat(resp_hdr(0x0000, Wire.kXR_ok, 8), be32(0x310), be32(1)))
    preq, _ = read_request(sock)                          # kXR_protocol
    @assert req_id(preq) == Wire.kXR_protocol
    write(sock, vcat(resp_hdr(req_sid(preq), Wire.kXR_ok, 8), be32(0x520), be32(1)))
    lreq, _ = read_request(sock)                          # kXR_login or kXR_bind
    if req_id(lreq) == Wire.kXR_bind
        # This mock has no data-path plumbing: refuse the extra stream a
        # default open asks for, and the file stays on its control link.
        body = vcat(be32(3000), Vector{UInt8}(codeunits("no data paths here")))
        write(sock, vcat(resp_hdr(req_sid(lreq), Wire.kXR_error, length(body)), body))
        close(sock)
        throw(EOFError())
    end
    @assert req_id(lreq) == Wire.kXR_login
    write(sock, vcat(resp_hdr(req_sid(lreq), Wire.kXR_ok, 16), UInt8.(1:16)))
    return nothing
end

"18 bytes of mock file content served by kXR_open/read handles."
const MOCK_CONTENT = Vector{UInt8}(codeunits("Hello\nWorld\nFolks!"))

"A pgwrite checksum-error trailer naming the single page at `offset`."
function cse_trailer(offset::Integer)
    return vcat(zeros(UInt8, 8), Wire.set_u64!(zeros(UInt8, 8), 1, UInt64(offset)))
end

"Payload of the most recent kXR_pgwrite the mock handled (for assertions)."
const PGWRITE_LAST = Ref(UInt8[])

"A readv segment at this file offset is dropped from the reply."
const MOCK_DROP_OFFSET = 4096

function serve_client(sock)
    try
        serve_bringup(sock)
        stat_waited = false
        while isopen(sock)
            frame, payload = read_request(sock)
            sid, rid = req_sid(frame), req_id(frame)
            if rid == Wire.kXR_ping
                write(sock, resp_hdr(sid, Wire.kXR_ok, 0))
            elseif rid == Wire.kXR_dirlist
                chunk1 = Vector{UInt8}(codeunits("a\n"))
                write(sock, vcat(resp_hdr(sid, Wire.kXR_oksofar, 2), chunk1))
                chunk2 = Vector{UInt8}(codeunits("b\0"))
                write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, 2), chunk2))
            elseif rid == Wire.kXR_stat && isempty(payload)
                # fhandle-based stat: the mock file
                line = Vector{UInt8}(codeunits("7 $(length(MOCK_CONTENT)) 51 1700000000"))
                write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, length(line)), line))
            elseif rid == Wire.kXR_stat && !stat_waited
                stat_waited = true
                write(sock, vcat(resp_hdr(sid, Wire.kXR_wait, 4), be32(1)))
            elseif rid == Wire.kXR_stat
                line = Vector{UInt8}(codeunits("7 13 51 1700000000"))
                write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, length(line)), line))
            elseif rid == Wire.kXR_rm
                body = vcat(be32(3011), Vector{UInt8}(codeunits("not found")))
                write(sock, vcat(resp_hdr(sid, Wire.kXR_error, length(body)), body))
            elseif rid == Wire.kXR_open
                if String(copy(payload)) == "/nonexisting"
                    body = vcat(be32(3011), Vector{UInt8}(codeunits("no such file")))
                    write(sock, vcat(resp_hdr(sid, Wire.kXR_error, length(body)), body))
                else
                    write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, 4), UInt8[9, 9, 9, 9]))
                end
            elseif rid == Wire.kXR_read
                offset = Int(reinterpret(Int64, Wire.get_u64(frame, 9)))
                rlen = Int(reinterpret(Int32, Wire.get_u32(frame, 17)))
                lo = offset + 1
                hi = min(offset + rlen, length(MOCK_CONTENT))
                data = lo <= hi ? MOCK_CONTENT[lo:hi] : UInt8[]
                write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, length(data)), data))
            elseif rid in (Wire.kXR_write, Wire.kXR_truncate, Wire.kXR_close, Wire.kXR_sync)
                write(sock, resp_hdr(sid, Wire.kXR_ok, 0))
            elseif rid == Wire.kXR_pgread
                # two status frames: Partial ("Hello" @0), Final ("World" @5)
                p1 = Wire.encode_pages(Vector{UInt8}(codeunits("Hello")), Int64(0))
                write(sock, status_frame(sid, Wire.kXR_PartialResult, 0, p1))
                p2 = Wire.encode_pages(Vector{UInt8}(codeunits("World")), Int64(5))
                write(sock, status_frame(sid, Wire.kXR_FinalResult, 5, p2))
            elseif rid == Wire.kXR_pgwrite
                # Page at file offset 0 is reported corrupt once and accepted
                # on the kXR_pgRetry resend; the page at 8192 stays corrupt
                # forever, exercising the bounded retry budget.
                offset = Int(reinterpret(Int64, Wire.get_u64(frame, 9)))
                retry = (frame[18] & Wire.kXR_pgRetry) != 0
                PGWRITE_LAST[] = copy(payload)
                cse = retry && offset == 0 ? UInt8[] : cse_trailer(offset)
                write(sock, status_frame(sid, Wire.kXR_FinalResult, offset, cse))
            elseif rid == Wire.kXR_readv
                # Echo one 16-byte header + the requested bytes per segment.
                # A segment at MOCK_DROP_OFFSET is silently omitted, modelling
                # a server that stops short of the requested vector.
                out = UInt8[]
                nseg = length(payload) ÷ 16
                for i in 1:nseg
                    off = 16 * (i - 1)
                    rlen = Int(reinterpret(Int32, Wire.get_u32(payload, off + 5)))
                    foff = Int(reinterpret(Int64, Wire.get_u64(payload, off + 9)))
                    foff == MOCK_DROP_OFFSET && continue
                    lo, hi = foff + 1, min(foff + rlen, length(MOCK_CONTENT))
                    data = lo <= hi ? MOCK_CONTENT[lo:hi] : UInt8[]
                    hdr = copy(payload[(off + 1):(off + 16)])
                    Wire.set_u32!(hdr, 5, UInt32(length(data)))
                    append!(out, hdr)
                    append!(out, data)
                end
                write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, length(out)), out))
            elseif rid == Wire.kXR_query
                # never answered — exercises close() failing pending requests
            end
        end
    catch
        # client hung up — done
    end
    return nothing
end

"""
Serve a bring-up that fails at `stage` (`:handshake`, `:protocol` or
`:login`): every earlier step succeeds and that one answers `kXR_error`.
"""
function serve_bad_bringup(sock, stage::Symbol)
    refuse(sid) =
        let body = vcat(be32(3010), Vector{UInt8}(codeunits("go away")))
            vcat(resp_hdr(sid, Wire.kXR_error, length(body)), body)
        end
    read(sock, 20)                                        # client hello
    stage === :handshake && return write(sock, refuse(0x0000))
    write(sock, vcat(resp_hdr(0x0000, Wire.kXR_ok, 8), be32(0x310), be32(1)))
    preq, _ = read_request(sock)
    stage === :protocol && return write(sock, refuse(req_sid(preq)))
    write(sock, vcat(resp_hdr(req_sid(preq), Wire.kXR_ok, 8), be32(0x520), be32(1)))
    lreq, _ = read_request(sock)
    return write(sock, refuse(req_sid(lreq)))
end

"Serve a login refused with kXR_TLSRequired: the server insists on encryption."
function serve_tls_required(sock)
    read(sock, 20)                                        # client hello
    write(sock, vcat(resp_hdr(0x0000, Wire.kXR_ok, 8), be32(0x310), be32(1)))
    preq, _ = read_request(sock)
    write(sock, vcat(resp_hdr(req_sid(preq), Wire.kXR_ok, 8), be32(0x520), be32(1)))
    lreq, _ = read_request(sock)
    body = vcat(be32(Int(Wire.kXR_TLSRequired)), Vector{UInt8}(codeunits("TLS required")))
    return write(sock, vcat(resp_hdr(req_sid(lreq), Wire.kXR_error, length(body)), body))
end

"Start a server that runs `handler(sock)` per connection; returns (server, port)."
function start_server(handler)
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async try
            handler(sock)
        catch
            # the client hung up mid-script, which is the point of the test
        end
    end
    return server, Int(port)
end

"""
A transport that claims to be open and fails every write: the state a peer
that has gone away without the socket noticing leaves behind, and the one the
resilience paths are written for.
"""
struct DeadTransport <: IO end

Base.isopen(::DeadTransport) = true
Base.close(::DeadTransport) = nothing
function Base.unsafe_write(::DeadTransport, ::Ptr{UInt8}, ::UInt)
    return throw(Base.IOError("write: broken pipe (EPIPE)", -32))
end

"A `Connection` over `sock` assembled without a bring-up, for the dead paths."
function dead_connection(sock::IO=DeadTransport())
    return Session.Connection(
        sock,
        "127.0.0.1",
        1094,
        "tester",
        UInt32(0x520),
        UInt32(0),
        UInt8.(1:16),
        Dict{UInt16,Channel{Session.Frame}}(),
        ReentrantLock(),
        ReentrantLock(),
        UInt16(4),
        nothing,
        false,
        0,
        0x00,
        Dict{UInt16,UInt8}(),
        nothing,
        UInt64(0),
        time(),
        nothing,
        0,
        Dict{UInt8,Session.DataPath}(),
        Dict{UInt16,UInt8}(),
        nothing,
    )
end

"Start a mock server accepting any number of connections; returns the port."
function start_mock_server()
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async serve_client(sock)
    end
    return port
end

@testset "Session" begin
    port = start_mock_server()
    conn = Session.connect("127.0.0.1", port; username="tester")

    @testset "bring-up state" begin
        @test conn.protover == 0x00000520
        @test conn.sessid == UInt8.(1:16)
        @test isopen(conn)
    end

    @testset "simple roundtrip" begin
        hdr, body = Session.roundtrip(conn, Wire.PingRequest())
        @test hdr.status == Wire.kXR_ok
        @test isempty(body)
    end

    @testset "oksofar accumulation" begin
        hdr, body = Session.roundtrip(conn, Wire.DirlistRequest("/x"; options=0x00))
        @test hdr.status == Wire.kXR_ok
        @test Wire.parse_dirlist(body).entries == ["a", "b"]
    end

    @testset "wait retry" begin
        t0 = time()
        hdr, body = Session.roundtrip(conn, Wire.StatRequest("/x"))
        @test hdr.status == Wire.kXR_ok
        @test time() - t0 >= 0.9                     # honored the 1s kXR_wait
        @test Wire.parse_stat_line(String(copy(body))).size == 13
    end

    @testset "error passthrough" begin
        hdr, body = Session.roundtrip(conn, Wire.RmRequest("/x"))
        @test hdr.status == Wire.kXR_error
        err = Wire.decode_error(body)
        @test err.errnum == 3011
        @test err.message == "not found"
    end

    @testset "paged-io status framing" begin
        fh = (0x00, 0x00, 0x00, 0x00)
        hdr, body = Session.roundtrip(conn, Wire.PgReadRequest(fh, Int64(0), Int32(10)))
        @test hdr.status == Wire.kXR_status
        # body = two concatenated (24-byte status body + pages) frames
        s1 = Wire.decode_status_body(body[1:24])
        @test s1.resptype == Wire.kXR_PartialResult
        @test s1.offset == 0
        d1 = Wire.decode_pages(body[25:(24 + s1.pgdlen)], s1.offset)
        cursor = 24 + Int(s1.pgdlen)
        s2 = Wire.decode_status_body(body[(cursor + 1):(cursor + 24)])
        @test s2.resptype == Wire.kXR_FinalResult
        @test s2.offset == 5
        d2 = Wire.decode_pages(body[(cursor + 25):end], s2.offset)
        @test String(vcat(d1, d2)) == "HelloWorld"
    end

    @testset "reply cap refuses an over-answering server" begin
        fh = (0x09, 0x09, 0x09, 0x09)
        req = Wire.ReadRequest(fh, Int64(0), Int32(length(MOCK_CONTENT)))
        hdr, body = Session.roundtrip(conn, req; maxbytes=4)
        @test hdr.status == Wire.kXR_error
        @test occursin("exceeds the 4-byte cap", Wire.decode_error(body).message)
        # the connection stays usable afterwards
        @test Session.roundtrip(conn, Wire.PingRequest())[1].status == Wire.kXR_ok
    end

    @testset "stall deadline bounds a silent server" begin
        stalled = Session.connect("127.0.0.1", port; username="tester")
        stalled.stall_deadline_ms = 200
        try
            t0 = time()
            hdr, body = Session.roundtrip(stalled, Wire.QueryRequest(Wire.kXR_QStats, "x"))
            @test hdr.status == Wire.kXR_error
            @test occursin("stall deadline", Wire.decode_error(body).message)
            @test time() - t0 < 5.0
        finally
            close(stalled)
        end
    end

    @testset "connect by URL" begin
        # root://[user@]host[:port] is the same bring-up, with the account
        # named in the URL.
        byurl = Session.connect("root://alice@127.0.0.1:$port")
        try
            @test byurl.username == "alice"
            @test byurl.host == "127.0.0.1"
            @test byurl.port == Int(port)
            @test isopen(byurl)
            # an explicit keyword still wins over the URL's account
            other = Session.connect("root://alice@127.0.0.1:$port"; username="bob")
            @test other.username == "bob"
            close(other)
        finally
            close(byurl)
        end

        # roots:// asks for TLS, and a server that does not offer it fails the
        # session rather than continuing in cleartext.
        @test_throws ErrorException Session.connect("roots://127.0.0.1:$port")
    end

    @testset "a bring-up the server refuses" begin
        for stage in (:handshake, :protocol, :login)
            server, badport = start_server(sock -> serve_bad_bringup(sock, stage))
            try
                err = try
                    Session.connect("127.0.0.1", badport; username="tester")
                    nothing
                catch e
                    e
                end
                @test err isa ErrorException
                @test occursin(string(Wire.kXR_error), err.msg)
                @test occursin(stage === :handshake ? "handshake" : "kXR_$(stage)", err.msg)
            finally
                close(server)
            end
        end
    end

    @testset "a login refused for want of TLS is retried with TLS" begin
        # The mock refuses the cleartext login with kXR_TLSRequired. The
        # client's answer is a fresh connection asking for TLS — which this
        # mock cannot offer, so the failure reported is the TLS-availability
        # error from the SECOND bring-up, not the login refusal from the
        # first. That second message is the proof the retry happened.
        server, tlsport = start_server(serve_tls_required)
        try
            err = try
                Session.connect("127.0.0.1", tlsport; username="tester")
                nothing
            catch e
                e
            end
            @test err isa ErrorException
            @test occursin("TLS required but the server", err.msg)
        finally
            close(server)
        end
    end

    @testset "sign_frame follows the armed contract" begin
        # White-box: the signing gate as transmit() consults it.
        c = dead_connection()
        fh = (0x09, 0x09, 0x09, 0x09)
        frame = Wire.encode(Wire.WriteRequest(fh, Int64(0), UInt8[1, 2, 3]), UInt16(7))
        # A level without a key signs nothing: there is nothing to encrypt with.
        c.sec_level = 2
        @test Session.sign_frame(c, frame) === nothing
        # Key + level 2: the write is signed, the seqno advances, and the
        # prefix reuses the covered request's streamid.
        c.signing_key = collect(0x01:0x20)
        sig = Session.sign_frame(c, frame)
        @test sig !== nothing
        @test Wire.get_u16(sig, 1) == 0x0007
        @test Wire.get_u16(sig, 3) == Wire.kXR_sigver
        @test Wire.get_u16(sig, 5) == Wire.kXR_write
        @test Wire.get_u64(sig, 9) == 1
        @test c.sig_seqno == 1
        @test Wire.get_u32(sig, 21) == 36            # bf32(32-byte hash)
        # Without kXR_secOData a write's payload stays out of the hash…
        @test sig[8] == Wire.kXR_nodata_sig
        # …and with data coverage demanded it goes in.
        c.sec_opts = Wire.kXR_secOData
        sig2 = Session.sign_frame(c, frame)
        @test sig2 !== nothing && sig2[8] == 0x00
        @test c.sig_seqno == 2
        # A stat is outside the level-2 set — until the secvec says Needed.
        sframe = Wire.encode(Wire.StatRequest("/x"), UInt16(8))
        @test Session.sign_frame(c, sframe) === nothing
        c.sec_overrides[Wire.kXR_stat] = Wire.kXR_signNeeded
        @test Session.sign_frame(c, sframe) !== nothing
    end

    @testset "streamid allocation skips 0 and anything in flight" begin
        # White-box: the allocator must never hand out 0 (which the protocol
        # reserves for unsolicited frames) nor a streamid still awaiting a
        # reply, however the counter happens to have wrapped.
        c = dead_connection()
        c.nextsid = 0x0000
        c.pending[0x0001] = Channel{Session.Frame}(1)
        c.pending[0x0002] = Channel{Session.Frame}(1)
        sid, _ = Session.register!(c)
        @test sid == 0x0003
        @test c.nextsid == 0x0004
        Session.unregister!(c, sid)
        @test !haskey(c.pending, sid)
    end

    @testset "a lost data path fails only what it was carrying" begin
        # White-box: the second socket dying must cost the requests routed
        # over it and nothing else — the control link is a separate socket and
        # everything not naming the path is still answerable on it.
        c = dead_connection()
        path = Session.DataPath(
            DeadTransport(), 0x02, ReentrantLock(), Ref{Union{Task,Nothing}}(nothing)
        )
        c.datapaths[0x02] = path
        routed, ch_routed = Session.register!(c)
        _, ch_control = Session.register!(c)
        c.routed[routed] = 0x02

        Session.fail_routed!(c, path, Base.IOError("read: connection reset", -104))
        @test !Session.has_data_path(c, 0x02)
        @test isopen(c)
        hdr, body = take!(ch_routed)
        @test hdr.status == Wire.kXR_error
        @test hdr.streamid == routed
        @test occursin("data path 2", Wire.decode_error(body).message)
        @test !isready(ch_control)
    end

    @testset "keepalive survives a dead peer" begin
        # The ping is best-effort: a transport that has gone away must not
        # take the timer task down with it.
        c = dead_connection()
        c.last_activity = time() - 10
        Session.start_keepalive!(c, 0.05)
        sleep(0.4)
        @test c.keepalive isa Task
        @test !istaskdone(c.keepalive)
        c.closed = true
        sleep(0.2)
        @test istaskdone(c.keepalive)
    end

    @testset "close fails pending requests" begin
        pending = @async Session.roundtrip(conn, Wire.QueryRequest(Wire.kXR_QStats, "x"))
        sleep(0.3)
        close(conn)
        hdr, body = fetch(pending)
        @test hdr.status == Wire.kXR_error
        @test occursin("lost", Wire.decode_error(body).message)
        @test !isopen(conn)
    end
end
