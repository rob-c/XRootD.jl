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
    lreq, _ = read_request(sock)                          # kXR_login
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
