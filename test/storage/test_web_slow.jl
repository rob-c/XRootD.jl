# The HTTP lane against endpoints that answer slowly rather than badly: a body
# dribbled out under any idle timeout, and a body cut short of the length its
# own header promised. Both are what a saturated or mis-buffering path between
# a job and a storage element looks like from inside the client.
#
# The mocks are raw sockets, not HTTP.jl servers: the whole point is to send
# responses no correct server would send.

using XRootD.Storage: storage_for, storage_read
using XRootD.Storage: http_idle_timeout_s, http_request_timeout_s
using XRootD.Session: max_wait_ms
using Sockets: Sockets, listen, accept, getsockname, @ip_str

"""
An endpoint that promises `total` bytes and then sends one every `interval`
seconds, forever — a gap short enough that the read never idles out, and a body
that never arrives.
"""
function start_slowloris_endpoint(total=1 << 20, interval=0.05)
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
                method = first(split(readline(sock), ' '))
                while !isempty(readline(sock))
                end
                write(sock, "HTTP/1.1 200 OK\r\nContent-Length: $total\r\n\r\n")
                flush(sock)
                if method == "GET"
                    while isopen(sock)
                        write(sock, UInt8('x'))
                        flush(sock)
                        sleep(interval)
                    end
                end
                close(sock)
            catch
            end
        end
    end
    return server, Int(port)
end

"An endpoint that promises `total` bytes, sends `sent` of them, and hangs up."
function start_truncating_endpoint(total=1 << 20, sent=1024)
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
                readline(sock)
                while !isempty(readline(sock))
                end
                write(sock, "HTTP/1.1 200 OK\r\nContent-Length: $total\r\n\r\n")
                write(sock, rand(UInt8, sent))
                flush(sock)
                close(sock)
            catch
            end
        end
    end
    return server, Int(port)
end

@testset "HTTP endpoints that answer slowly" begin
    @testset "the request deadline defaults to the client's request timeout" begin
        @test http_request_timeout_s() == max_wait_ms() / 1000
        withenv("XRD_REQUESTTIMEOUT" => "42") do
            @test http_request_timeout_s() == 42
        end
        withenv("XRDC_HTTP_REQUEST_TIMEOUT_S" => "7") do
            @test http_request_timeout_s() == 7
        end
        withenv("XRDC_HTTP_REQUEST_TIMEOUT_S" => "0") do
            @test http_request_timeout_s() == 0        # off, for a caller that means it
        end
    end

    @testset "a slowloris body is cut off by the request deadline" begin
        # The idle timeout is deliberately much longer than the deadline: an
        # endpoint that keeps sending is never idle, so only a whole-request
        # deadline ends this.
        server, port = start_slowloris_endpoint()
        try
            withenv(
                "XRDC_HTTP_IDLE_TIMEOUT_S" => "30",
                "XRDC_HTTP_REQUEST_TIMEOUT_S" => "1",
                "XRDC_MAX_RETRIES" => "0",
            ) do
                b = storage_for("http://127.0.0.1:$port/big.bin")
                t0 = time()
                @test storage_read(b, IOBuffer()) === :error
                @test time() - t0 < 10.0
                @test b.lasterror !== nothing
            end
        finally
            close(server)
        end
    end

    @testset "a body cut short of its Content-Length is an error, not a short read" begin
        server, port = start_truncating_endpoint()
        try
            withenv("XRDC_MAX_RETRIES" => "0") do
                b = storage_for("http://127.0.0.1:$port/big.bin")
                sink = IOBuffer()
                @test storage_read(b, sink) === :error
                @test position(sink) == 0              # nothing partial written out
            end
        finally
            close(server)
        end
    end
end
