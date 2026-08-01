# The parts of the protocol where the reply does not simply follow the request
# on the same stream: a server may defer the answer (`kXR_waitresp`, then the
# reply as an unsolicited `kXR_attn`/`kXR_asynresp` on the original streamid),
# and it may talk to the client between replies (`kXR_asyncms` notices).
#
# A third-party copy is deferred this way, so "the caller blocks until the real
# answer arrives, and the request is not sent twice" is a correctness property,
# not a nicety: a re-sent request is a second copy.

using XRootD.XrdCl
using XRootD: Wire

@testset "conformance: deferred and unsolicited replies" begin
    srv, port = start_info_server()
    fs = info_fs(port)

    @testset "a deferred reply is unwrapped and given to its caller" begin
        info_reset!(srv)
        srv.async = true
        info_reply!(srv, "v5.2.0")
        st, text = query(fs, QueryCode.Config, "version")
        @test isOK(st) && text == "v5.2.0"
        @test srv.ops == [Wire.kXR_query]

        # The connection is no worse for it: the next call is answered plainly.
        info_reset!(srv)
        info_reply!(srv, "sitename")
        st, text = query(fs, QueryCode.Config, "sitename")
        @test isOK(st) && text == "sitename"
        @test isempty(srv.violations)
    end

    @testset "a failure can be deferred too, and still reads as a failure" begin
        info_reset!(srv)
        srv.async = true
        info_error!(srv, 3011, "no such file")
        st, si = stat(fs, "/p")
        @test isError(st) && st.code == 3011 && st.message == "no such file"
        @test si === nothing
        @test isempty(srv.violations)
    end

    @testset "kXR_waitresp parks the caller instead of re-sending" begin
        info_reset!(srv)
        srv.waitresp_secs = 3            # "ask again in 3s" would be a kXR_wait
        srv.async = true
        info_reply!(srv, "deferred")
        elapsed = @elapsed ((st, text) = query(fs, QueryCode.Config, "version"))
        @test isOK(st) && text == "deferred"
        # One request on the wire: a deferral is not a retry. And the client
        # did not sleep out the advised delay — the reply ended the wait.
        @test srv.ops == [Wire.kXR_query]
        @test elapsed < 3
        @test isempty(srv.violations)
    end

    @testset "a deferred reply that arrives on the stream is taken as well" begin
        # Stock servers send the deferred answer as an attn; a server that
        # simply answers late on the same stream is answering the same request.
        info_reset!(srv)
        srv.waitresp_secs = 5
        info_reply!(srv, "late but plain")
        st, text = query(fs, QueryCode.Config, "version")
        @test isOK(st) && text == "late but plain"
        @test srv.ops == [Wire.kXR_query]
        @test isempty(srv.violations)
    end

    @testset "unsolicited frames between replies are not mistaken for one" begin
        info_reset!(srv)
        srv.notice = "the server is going down at 18:00"
        info_reply!(srv, "v5.2.0")
        st, text = query(fs, QueryCode.Config, "version")
        @test isOK(st) && text == "v5.2.0"

        # An attn too short to name an action, and a deferred reply for a
        # stream nobody is waiting on: both are dropped, and the caller's own
        # answer is unaffected.
        info_reset!(srv)
        srv.short_attn = true
        srv.stray_attn = true
        info_reply!(srv, "still fine")
        st, text = query(fs, QueryCode.Config, "version")
        @test isOK(st) && text == "still fine"

        # ... and the connection stays usable afterwards.
        info_reset!(srv)
        st, _ = ping(fs)
        @test isOK(st)
        @test srv.ops == [Wire.kXR_ping]
        @test isempty(srv.violations)
    end

    @testset "a deferred reply reaches a file handle too" begin
        info_reset!(srv)
        srv.body = collect(CONF_FHANDLE)
        f = File()
        st, _ = open(f, "root://127.0.0.1:$port//p")
        @test isOK(st) && isopen(f)

        srv.async = true
        srv.waitresp_secs = 2
        srv.body = Vector{UInt8}(codeunits("0123456789"))
        st, data = read(f, 10, 0)
        @test isOK(st) && String(copy(data)) == "0123456789"

        srv.async = false
        srv.waitresp_secs = 0
        st, _ = close(f)
        @test isOK(st)
        @test isempty(srv.violations)
    end
end
