# Peers that are alive and unhelpful: they complete the TCP handshake and then
# stop talking, or dribble a reply out one byte at a time. Neither shows up as
# a broken socket — nothing is closed, nothing is reset, TCP keepalive sees a
# healthy peer — so the only thing standing between the caller and a permanent
# block is a deadline. Every test here asserts that the call comes back.
#
# The second half covers the opposite fault — links that fail loudly in the
# middle of a conversation — where the requirement is not a deadline but that
# the loss reaches every caller waiting on that link, at once.
#
# Reuses resp_hdr/be32/serve_bringup/read_request from test_connection.jl.

using XRootD.XrdCl

"A mock that accepts, reads the client hello, and then says nothing at all."
function start_mute_server(stage::Symbol)
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async begin
            try
                read(sock, 20)                                   # client hello
                if stage !== :hello
                    write(
                        sock, vcat(resp_hdr(0x0000, Wire.kXR_ok, 8), be32(0x310), be32(1))
                    )
                    preq, _ = read_request(sock)                 # kXR_protocol
                    write(
                        sock,
                        vcat(resp_hdr(req_sid(preq), Wire.kXR_ok, 8), be32(0x520), be32(1)),
                    )
                    lreq, _ = read_request(sock)                 # kXR_login
                    if stage === :auth
                        # A login trailer offering unix, so the client owes one
                        # kXR_auth round — which is then never answered.
                        body = vcat(UInt8.(1:16), Vector{UInt8}(codeunits("&P=unix\0")))
                        write(
                            sock,
                            vcat(resp_hdr(req_sid(lreq), Wire.kXR_ok, length(body)), body),
                        )
                        read_request(sock)                       # kXR_auth
                    end
                end
                while isopen(sock)
                    sleep(0.1)                                   # hold it open, mute
                end
            catch
            end
        end
    end
    return server, Int(port)
end

"""
A mock that logs in, then answers `kXR_stat` with a header promising 4 KiB and
delivers it one byte at a time — a reply that never ends but never idles for
long enough to look stopped either.
"""
function start_dribbling_server(interval=0.05)
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async begin
            try
                serve_bringup(sock)
                while isopen(sock)
                    frame, _ = read_request(sock)
                    write(sock, resp_hdr(req_sid(frame), Wire.kXR_ok, 4096))
                    while isopen(sock)
                        write(sock, UInt8('4'))
                        flush(sock)
                        sleep(interval)
                    end
                end
            catch
            end
        end
    end
    return server, Int(port)
end

"A mock that logs in and then never answers anything."
function start_deaf_server()
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async begin
            try
                serve_bringup(sock)
                while isopen(sock)
                    read_request(sock)                           # swallowed
                end
            catch
            end
        end
    end
    return server, Int(port)
end

"""
A mock that logs in, answers one `kXR_open`, and then stops reading its socket
altogether — the peer whose receive window shuts and never reopens.
"""
function start_unreading_server()
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async begin
            try
                serve_bringup(sock)
                frame, _ = read_request(sock)                # kXR_open
                body = vcat(UInt8[1, 0, 0, 0], zeros(UInt8, 4))  # fhandle, no extras
                write(sock, vcat(resp_hdr(req_sid(frame), Wire.kXR_ok, length(body)), body))
                flush(sock)
                while isopen(sock)
                    sleep(0.1)                               # never read again
                end
            catch
            end
        end
    end
    return server, Int(port)
end

@testset "peers that stop talking" begin
    @testset "bring-up is bounded at every step" begin
        for (stage, phase) in (
            :hello => "the protocol reply",
            :login => "the login reply",
            :auth => "the unix auth reply",
        )
            server, port = start_mute_server(stage)
            try
                t0 = time()
                err = try
                    Session.connect("127.0.0.1", port; connect_timeout=0.5)
                    nothing
                catch e
                    e
                end
                @test err isa Session.BringUpTimeout
                @test err.phase == phase
                @test time() - t0 < 5.0
                @test occursin("timed out", sprint(showerror, err))
            finally
                close(server)
            end
        end
    end

    @testset "a healthy bring-up outlives its watchdog" begin
        # The watchdog closes the socket it is guarding, so a timer left armed
        # past the end of bring-up would kill a working session a moment later.
        port = start_stat_server()
        conn = Session.connect("127.0.0.1", port; connect_timeout=0.4)
        sleep(1.0)                                       # well past the window
        @test isopen(conn)
        hdr, _ = Session.roundtrip(conn, Wire.StatRequest("/x"))
        @test hdr.status == Wire.kXR_ok
        close(conn)
    end

    @testset "the default stall deadline is the request timeout" begin
        # Not disabled: an operation nobody bounded is an operation a mute peer
        # owns forever.
        @test Session.stall_deadline_ms() == Session.max_wait_ms()
        @test Session.stall_deadline_ms() > 0
        withenv("XRD_REQUESTTIMEOUT" => "42") do
            @test Session.stall_deadline_ms() == 42_000
        end
    end

    @testset "a request to a peer that went quiet is bounded by default" begin
        server, port = start_deaf_server()
        try
            withenv("XRD_REQUESTTIMEOUT" => "1", "XRDC_MAX_RETRIES" => "0") do
                fs = FileSystem("root://127.0.0.1:$port")
                t0 = time()
                st, _ = stat(fs, "/x")
                @test isError(st)
                @test occursin("stall deadline", st.message)
                @test time() - t0 < 5.0
            end
        finally
            close(server)
        end
    end

    @testset "a write to a peer that stopped reading is bounded" begin
        # The other direction, and the one no reply deadline can reach: the
        # caller is blocked in `write`, so it never gets as far as waiting for
        # an answer that the stall timer could synthesize.
        server, port = start_unreading_server()
        try
            withenv("XRD_REQUESTTIMEOUT" => "1", "XRDC_MAX_RETRIES" => "0") do
                f = File()
                st, _ = open(f, "root://127.0.0.1:$port//x", OpenFlags.Update)
                @test isOK(st)
                payload = zeros(UInt8, 32 << 20)   # past every buffer on the path
                t0 = time()
                st, _ = write(f, payload, length(payload), 0)
                @test isError(st)
                @test occursin("stall deadline", st.message)
                @test time() - t0 < 10.0
            end
        finally
            close(server)
        end
    end

    @testset "a reply dribbled out a byte at a time is bounded too" begin
        # The case a per-frame idle timeout cannot catch: bytes keep arriving,
        # so the read never idles, and the frame still never completes.
        server, port = start_dribbling_server()
        try
            withenv("XRD_REQUESTTIMEOUT" => "1", "XRDC_MAX_RETRIES" => "0") do
                fs = FileSystem("root://127.0.0.1:$port")
                t0 = time()
                st, _ = stat(fs, "/x")
                @test isError(st)
                @test occursin("stall deadline", st.message)
                @test time() - t0 < 5.0
            end
        finally
            close(server)
        end
    end
end

"""
A mock that logs in, answers `kXR_stat` with a header promising 4 KiB, sends
100 bytes of it, and hangs up — a transfer cut off mid-body, which is what a
NAT table eviction or a load balancer recycling a backend looks like on the
wire.
"""
function start_truncating_server()
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async begin
            try
                serve_bringup(sock)
                frame, _ = read_request(sock)
                write(sock, resp_hdr(req_sid(frame), Wire.kXR_ok, 4096))
                write(sock, zeros(UInt8, 100))
                flush(sock)
                sleep(0.2)
                close(sock)
            catch
            end
        end
    end
    return server, Int(port)
end

"""
A mock that logs in and then shuts down only its *write* side: the client sees
EOF on a socket it can still write to. Half-open connections outlive one
direction of a broken path routinely, and a client that only notices failures
on write would sit there sending into a link nothing will ever answer on.
"""
function start_halfopen_server()
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async begin
            try
                serve_bringup(sock)
                ccall(:shutdown, Cint, (Cint, Cint), Base.cconvert(Cint, Base._fd(sock)), 1)
                while isopen(sock)
                    sleep(0.1)                       # still reading, never answering
                end
            catch
            end
        end
    end
    return server, Int(port)
end

@testset "links that die mid-conversation" begin
    @testset "a reply cut off mid-body fails its caller" begin
        server, port = start_truncating_server()
        try
            withenv("XRDC_MAX_RETRIES" => "0") do
                fs = FileSystem("root://127.0.0.1:$port")
                t0 = time()
                st, _ = stat(fs, "/x")
                @test isError(st)
                @test occursin("lost", st.message)
                @test time() - t0 < 5.0
            end
        finally
            close(server)
        end
    end

    @testset "a half-closed link is noticed on the read side" begin
        server, port = start_halfopen_server()
        try
            withenv("XRDC_MAX_RETRIES" => "0") do
                fs = FileSystem("root://127.0.0.1:$port")
                t0 = time()
                st, _ = stat(fs, "/x")
                @test isError(st)
                @test time() - t0 < 5.0            # not the stall deadline: EOF
            end
        finally
            close(server)
        end
    end

    @testset "every request in flight learns the link is gone" begin
        # One socket, many streamids: the reply the server never sent belongs
        # to one of them, and the requests behind it must not be left waiting
        # for frames that can no longer arrive.
        server, port = start_truncating_server()
        try
            withenv("XRDC_MAX_RETRIES" => "0") do
                fs = FileSystem("root://127.0.0.1:$port")
                stat(fs, "/warm")                   # one connection, shared below
                t0 = time()
                tasks = [Threads.@spawn(stat(fs, "/x$i")) for i in 1:4]
                @test all(isError(fetch(t)[1]) for t in tasks)
                @test time() - t0 < 5.0
            end
        finally
            close(server)
        end
    end
end
