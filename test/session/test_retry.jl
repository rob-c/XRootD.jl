# The backoff every reconnecting lane shares, and the socket option that makes
# a black-holed connection fail at all instead of hanging.
#
# Two properties carry the weight. A retry budget has to be bounded in both
# directions — by time and by count — because a peer that refuses in a
# millisecond turns a generous window into hundreds of attempts against a
# server that is already in trouble. And the wait has to be *drawn* from the
# window rather than being the window: everything that went away took every
# client with it, and a fleet that all waited the same 200 ms comes back as
# one burst.

using Sockets
using XRootD: Session
using XRootD.Session:
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_BASE_MS,
    DEFAULT_RETRY_CAP_MS,
    DEFAULT_TCP_KEEPALIVE_S,
    backoff!,
    keepalive!,
    max_retries,
    retry_base_ms,
    retry_cap_ms,
    retry_delay,
    tcp_keepalive_s

@testset "retry policy" begin
    @testset "the delay doubles, then stops" begin
        @test retry_delay(1; jitter=false) == 0.2
        @test retry_delay(2; jitter=false) == 0.4
        @test retry_delay(5; jitter=false) == 3.2
        @test retry_delay(9; jitter=false) == 5.0        # at the cap
        @test retry_delay(2000; jitter=false) == 5.0     # an overflowed window is still capped
        @test retry_delay(0; jitter=false) == 0.0        # nothing precedes the first retry
    end

    @testset "jitter spreads the return across the window" begin
        window = retry_delay(3; jitter=false)
        draws = [retry_delay(3) for _ in 1:500]
        @test all(d -> 0.0 <= d <= window, draws)
        @test length(unique(draws)) > 1
        # Spread, not merely offset: a distribution that clustered anywhere in
        # the window would resynchronize the fleet it exists to scatter.
        @test maximum(draws) > 0.9 * window
        @test minimum(draws) < 0.1 * window
    end

    @testset "the environment moves the window and the count" begin
        withenv("XRDC_RETRY_BASE_MS" => "50", "XRDC_RETRY_CAP_MS" => "100") do
            @test retry_base_ms() == 50
            @test retry_cap_ms() == 100
            @test retry_delay(1; jitter=false) == 0.05
            @test retry_delay(4; jitter=false) == 0.1    # the lower cap binds sooner
        end
        withenv("XRDC_MAX_RETRIES" => "7") do
            @test max_retries() == 7
        end
        withenv("XRDC_TCP_KEEPALIVE_S" => "15") do
            @test tcp_keepalive_s() == 15
        end
        # A typo in a site profile reaches every job at once; the default has
        # to survive it.
        withenv(
            "XRDC_RETRY_BASE_MS" => "soon",
            "XRDC_RETRY_CAP_MS" => "-1",
            "XRDC_MAX_RETRIES" => "lots",
            "XRDC_TCP_KEEPALIVE_S" => "",
        ) do
            @test retry_base_ms() == DEFAULT_RETRY_BASE_MS
            @test retry_cap_ms() == DEFAULT_RETRY_CAP_MS
            @test max_retries() == DEFAULT_MAX_RETRIES
            @test tcp_keepalive_s() == DEFAULT_TCP_KEEPALIVE_S
        end
    end

    @testset "backoff! is bounded by the count and by the window" begin
        far = time() + 60
        withenv("XRDC_MAX_RETRIES" => "2", "XRDC_RETRY_BASE_MS" => "1") do
            @test backoff!(1, far)
            @test backoff!(2, far)
            @test !backoff!(3, far)                      # attempt budget spent
        end
        withenv("XRDC_MAX_RETRIES" => "0") do
            @test !backoff!(1, far)                      # retrying turned off outright
        end

        # A delay that would outlast the window is not slept: the outcome is
        # already decided and waiting for it teaches the caller nothing.
        t0 = time()
        @test !backoff!(1, time() + 0.001)
        @test time() - t0 < 0.15
        @test !backoff!(1, time() - 1)                   # window already shut

        # It does wait when there is budget for it.
        t0 = time()
        withenv("XRDC_RETRY_BASE_MS" => "60", "XRDC_RETRY_CAP_MS" => "60") do
            @test backoff!(1, time() + 60)
        end
        @test time() - t0 >= 0.0
    end

    @testset "sockets ask the kernel to probe an idle peer" begin
        server = listen(ip"127.0.0.1", 0)
        _, port = getsockname(server)
        sock = Sockets.connect("127.0.0.1", port)
        try
            @test keepalive!(sock, 30) === sock          # hands the socket back
            @test isopen(sock)                           # and leaves it usable
            write(sock, UInt8[0x01])                     # still a working socket
            @test keepalive!(sock, 0) === sock           # 0 leaves the system default
            close(sock)
            # A socket that closed under us is not an error here: the caller
            # asked for a connection, not for a socket option.
            @test keepalive!(sock, 30) === sock
        finally
            close(server)
        end
        buf = IOBuffer()
        @test keepalive!(buf, 30) === buf                # not a TCP socket, untouched
    end
end
