# Resilience: redirect following and reconnect-with-replay, driven by mock
# servers. Reuses resp_hdr/be32/serve_bringup/read_request from
# test_connection.jl (included earlier in the same testset run).

using XRootD.XrdCl

"A mock that answers every kXR_stat with a redirect to `target_port`."
function start_redirecting_server(target_port::Integer)
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async begin
        try
            sock = accept(server)
            serve_bringup(sock)
            while isopen(sock)
                frame, _ = read_request(sock)
                if req_id(frame) == Wire.kXR_stat
                    host = "127.0.0.1"
                    body = vcat(be32(Int(target_port)), Vector{UInt8}(codeunits(host)))
                    write(
                        sock,
                        vcat(
                            resp_hdr(req_sid(frame), Wire.kXR_redirect, length(body)), body
                        ),
                    )
                end
            end
        catch
        finally
            close(server)
        end
    end
    return port
end

"A mock that answers kXR_stat with a valid stat line."
function start_stat_server()
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async begin
        try
            sock = accept(server)
            serve_bringup(sock)
            while isopen(sock)
                frame, _ = read_request(sock)
                if req_id(frame) == Wire.kXR_stat
                    line = Vector{UInt8}(codeunits("42 99 51 1700000000"))
                    write(
                        sock,
                        vcat(resp_hdr(req_sid(frame), Wire.kXR_ok, length(line)), line),
                    )
                end
            end
        catch
        finally
            close(server)
        end
    end
    return port
end

"A mock that serves one stat then drops the connection, then serves normally."
function start_flaky_server()
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    attempts = Ref(0)
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
                    if req_id(frame) == Wire.kXR_stat
                        attempts[] += 1
                        if attempts[] == 1
                            close(sock)            # sever mid-operation
                            break
                        end
                        line = Vector{UInt8}(codeunits("7 13 51 1700000000"))
                        write(
                            sock,
                            vcat(resp_hdr(req_sid(frame), Wire.kXR_ok, length(line)), line),
                        )
                    end
                end
            catch
            end
        end
    end
    return port, attempts
end

"A mock that counts kXR_ping requests (for the keepalive test)."
function start_ping_counting_server()
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    pings = Ref(0)
    @async begin
        try
            sock = accept(server)
            serve_bringup(sock)
            while isopen(sock)
                frame, _ = read_request(sock)
                if req_id(frame) == Wire.kXR_ping
                    pings[] += 1
                    write(sock, resp_hdr(req_sid(frame), Wire.kXR_ok, 0))
                end
            end
        catch
        finally
            close(server)
        end
    end
    return port, pings
end

@testset "resilience" begin
    @testset "redirect following" begin
        target = start_stat_server()
        redirector = start_redirecting_server(target)
        fs = FileSystem("root://127.0.0.1:$redirector")
        st, si = stat(fs, "/somewhere")
        @test isOK(st)
        @test si.size == 99                          # answered by the redirect target
        @test fs.port == target                      # connection moved to the target
    end

    @testset "reconnect and replay on transport loss" begin
        port, attempts = start_flaky_server()
        fs = FileSystem("root://127.0.0.1:$port")
        st, si = stat(fs, "/x")                       # 1st attempt severed, 2nd succeeds
        @test isOK(st)
        @test si.size == 13
        @test attempts[] >= 2
    end

    @testset "idle keepalive pings" begin
        port, pings = start_ping_counting_server()
        conn = Session.connect("127.0.0.1", port; keepalive_s=0.3)
        sleep(1.0)                                    # ~3 keepalive intervals
        close(conn)
        @test pings[] >= 2
    end
end
