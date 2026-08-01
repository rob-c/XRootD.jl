# TLS negotiation: what the client says it can do, and what it does when the
# server answers. The whole exchange is three fields — the capability byte in
# `kXR_protocol`, the flag word in the reply, and the client's next move — and
# every interesting property of it is a property of that move.
#
# The one that matters most is negative: a server that demands TLS and cannot
# supply it must not get a cleartext login instead. A silent downgrade is the
# failure mode operators watch for (libxrdc's doctor reports it in red), and
# it is invisible from a session that came up "fine".

using XRootD.XrdCl
using XRootD: Wire, Session

@testset "conformance: TLS negotiation" begin
    @testset "the client says what it can do before it is asked" begin
        srv, port = start_tls_server(; flags=UInt32(1))
        conn, err = tls_bringup(port; username="tester", x509=false)
        @test err === nothing
        @test tls_await_move(srv) == "login"

        # kXR_secreqs asks for the security trailer that drives authentication;
        # kXR_ableTLS says an upgrade is possible. Neither claims it is needed.
        @test srv.asked == [Wire.kXR_secreqs | Wire.kXR_ableTLS]
        @test (srv.asked[1] & Wire.kXR_wantTLS) == 0
        @test srv.logins == ["tester"]
        @test conn.sock isa Sockets.TCPSocket
        @test conn.flags == UInt32(1)
        @test conn.protover == Wire.kXR_PROTOCOLVERSION
        @test isempty(srv.violations)
    end

    @testset "a server that offers TLS is not a server that requires it" begin
        # kXR_haveTLS alone is an offer. A client that has not asked for TLS
        # stays in cleartext, which is what a plain root:// URL means.
        srv, port = start_tls_server(; flags=Wire.kXR_haveTLS | UInt32(1))
        conn, err = tls_bringup(port; username="tester", x509=false)
        @test err === nothing
        @test tls_await_move(srv) == "login"
        @test conn.sock isa Sockets.TCPSocket
        @test isempty(srv.violations)
    end

    @testset "asking for TLS is said in the request, not implied" begin
        srv, port = start_tls_server(; flags=Wire.kXR_haveTLS | UInt32(1))
        _, err = tls_bringup(port; username="tester", want_tls=true, x509=false)

        # The upgrade was attempted — against a server that speaks no TLS, so
        # it could only fail, and failing is how we know it was tried.
        @test tls_await_move(srv) == "tls"
        @test err !== nothing
        @test srv.asked == [Wire.kXR_secreqs | Wire.kXR_ableTLS | Wire.kXR_wantTLS]
        @test isempty(srv.logins)
        @test isempty(srv.violations)
    end

    @testset "every demand the server can raise stops the client" begin
        # Three flags name a phase of the session itself, and each of them
        # obliges the client to upgrade before it sends its login.
        for flag in (Wire.kXR_gotoTLS, Wire.kXR_tlsLogin, Wire.kXR_tlsSess)
            srv, port = start_tls_server(; flags=Wire.kXR_haveTLS | flag | UInt32(1))
            _, err = tls_bringup(port; username="tester", x509=false)
            @test tls_await_move(srv) == "tls"
            @test err !== nothing
            @test isempty(srv.logins)          # no cleartext login slipped out
            @test isempty(srv.violations)
        end
    end

    @testset "a flag that qualifies one request is not a demand on the session" begin
        # These three bind requests this session does not carry: file data on
        # a data connection, gpfile, and a third-party copy. A server that
        # means to bind the session says kXR_tlsSess.
        for flag in (Wire.kXR_tlsData, Wire.kXR_tlsGPF, Wire.kXR_tlsTPC)
            srv, port = start_tls_server(; flags=Wire.kXR_haveTLS | flag | UInt32(1))
            conn, err = tls_bringup(port; username="tester", x509=false)
            @test err === nothing
            @test tls_await_move(srv) == "login"
            @test conn.sock isa Sockets.TCPSocket
            @test isempty(srv.violations)
        end
    end

    @testset "a demand the server cannot honour is refused, not downgraded" begin
        # kXR_gotoTLS without kXR_haveTLS is a server contradicting itself.
        # The safe reading is the strict one: no session at all.
        srv, port = start_tls_server(; flags=Wire.kXR_gotoTLS | UInt32(1))
        _, err = tls_bringup(port; username="tester", x509=false)
        @test err !== nothing
        @test occursin("does not offer it", sprint(showerror, err))
        @test tls_await_move(srv) == "gone"
        @test isempty(srv.logins)
        @test isempty(srv.violations)
    end

    @testset "a client that requires TLS will not settle for less" begin
        srv, port = start_tls_server(; flags=UInt32(1))
        _, err = tls_bringup(port; username="tester", want_tls=true, x509=false)
        @test err !== nothing
        @test occursin("does not offer it", sprint(showerror, err))
        @test tls_await_move(srv) == "gone"
        @test isempty(srv.logins)

        # roots:// is that requirement spelled as a URL, and it reaches the
        # session the same way — the handle reports the failure as a status.
        # It is not a transient fault, so the retry window is kept short.
        withenv("XRDC_MAX_STALL_MS" => "500") do
            st, _ = stat(XrdCl.FileSystem("roots://127.0.0.1:$port"), "/data/a.txt")
            @test isError(st)
        end
        @test isempty(srv.logins)
        @test isempty(srv.violations)
    end

    @testset "a refused bring-up does not leave the connection open" begin
        # The client opened the socket, so the client closes it: the server
        # reading the far end is how we know it did. Without that, a redirect
        # chain of failures would strand one half-open connection per hop.
        srv, port = start_tls_server(; flags=Wire.kXR_tlsLogin | UInt32(1))
        _, err = tls_bringup(port; username="tester", x509=false)
        @test err !== nothing
        @test tls_await_move(srv) == "gone"
        @test srv.conns == 1
        @test isempty(srv.violations)
    end
end
