# The security exchange, as bytes on the wire: which credential the client
# chooses from what the server offers, what it puts in it, and what happens
# when the server refuses it.
#
# The choice is the interesting part. A server states a set of acceptable
# protocols and the client picks one; picking a weaker one than it could have,
# or sending a credential for a protocol the server never offered, is a
# security failure that leaves a perfectly healthy-looking session behind.
# Ground truth for the preference order and payload shapes: libxrdc
# sec/sec_{token,sss,unix}.c and PyXRootD's XrdSecProtocol selection.

using XRootD: Wire, Session

@testset "conformance: the security exchange" begin
    @testset "a login the server does not challenge needs no credential" begin
        srv, port = start_auth_server(; sec="")
        conn, err = auth_bringup(port; username="tester")
        @test err === nothing
        @test srv.logins == ["tester"]

        # Absence is proved by what comes next: the first frame after login is
        # the ping, so no credential was slipped in ahead of it.
        hdr, _ = Session.roundtrip(conn, Wire.PingRequest())
        @test hdr.status == Wire.kXR_ok
        @test srv.ops == [Wire.kXR_ping]
        @test isempty(srv.creds)
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "a trailer that names no protocol is not a challenge" begin
        # kXR_secreqs asks for the trailer, and a server with nothing to
        # require may still answer with one. Nothing in it means nothing to do.
        srv, port = start_auth_server(; sec="&x=1")
        conn, err = auth_bringup(port; username="tester")
        @test err === nothing
        Session.roundtrip(conn, Wire.PingRequest())
        @test srv.ops == [Wire.kXR_ping]
        @test isempty(srv.creds)
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "unix names the user, and nothing more" begin
        srv, port = start_auth_server(; sec="&P=unix")
        conn, err = auth_bringup(port; username="tester")
        @test err === nothing
        @test length(srv.creds) == 1
        credtype, cred = srv.creds[1]
        @test credtype == "unix"
        # sec_unix.c: the tag is repeated inside the credential, NUL-separated
        # from the name the login already carried.
        @test String(cred) == "unix\0tester"
        @test srv.ops == [Wire.kXR_auth]
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "ztn carries the bearer token itself" begin
        srv, port = start_auth_server(; sec="&P=ztn")
        conn, err = withenv("BEARER_TOKEN" => "header.payload.signature") do
            auth_bringup(port; username="tester")
        end
        @test err === nothing
        @test srv.creds[1][1] == "ztn"
        @test String(srv.creds[1][2]) == "ztn\0header.payload.signature"
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "the token given to the client wins over the environment" begin
        srv, port = start_auth_server(; sec="&P=ztn")
        conn, err = withenv("BEARER_TOKEN" => "from.the.environment") do
            auth_bringup(port; username="tester", token="from.the.caller")
        end
        @test err === nothing
        @test String(srv.creds[1][2]) == "ztn\0from.the.caller"
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "protocol arguments do not confuse the protocol name" begin
        # A real trailer is "&P=ztn,v:10400&P=unix": everything after the comma
        # is the protocol's own parameters, not another protocol.
        srv, port = start_auth_server(; sec="&P=ztn,v:10400,x:1&P=unix")
        conn, err = withenv("BEARER_TOKEN" => "tok") do
            auth_bringup(port; username="tester")
        end
        @test err === nothing
        @test srv.creds[1][1] == "ztn"
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "the strongest offered mechanism is the one used" begin
        # Wire order is the server's, not a preference: ztn beats sss beats
        # unix whichever way round they are listed.
        with_keytab() do keytab
            for sec in ("&P=unix&P=sss&P=ztn", "&P=ztn&P=sss&P=unix")
                srv, port = start_auth_server(; sec=sec)
                conn, err = withenv("BEARER_TOKEN" => "tok") do
                    auth_bringup(port; username="tester", keytab=keytab)
                end
                @test err === nothing
                @test srv.creds[1][1] == "ztn"
                @test isempty(srv.violations)
                close(conn)
            end
        end
    end

    @testset "sss is preferred to unix when a keytab key exists" begin
        with_keytab(; id=42) do keytab
            srv, port = start_auth_server(; sec="&P=unix&P=sss")
            conn, err = without_token() do
                auth_bringup(port; username="tester", keytab=keytab)
            end
            @test err === nothing
            credtype, cred = srv.creds[1]
            @test credtype == "sss"
            # The blob is self-describing (sss_credential.c): tag, version,
            # cipher, then the big-endian key id the server looks up.
            @test cred[1:4] == UInt8['s', 's', 's', 0x00]
            @test cred[5] == 0x01
            @test cred[8] == Session.SSS_ENC_BF32
            @test Wire.get_u64(cred, 9) == 42
            @test isempty(srv.violations)
            close(conn)
        end
    end

    @testset "a mechanism that cannot be satisfied falls through to one that can" begin
        # Offered ztn and sss, but no token and no keytab: the client must not
        # stall on the strongest offer, and must not invent a credential for it.
        srv, port = start_auth_server(; sec="&P=ztn&P=sss&P=unix")
        missing_keytab = joinpath(mktempdir(), "absent.keytab")
        conn, err = without_token() do
            @test Session.discover_token() === nothing
            auth_bringup(port; username="tester", keytab=missing_keytab)
        end
        @test err === nothing
        @test srv.creds[1][1] == "unix"
        @test String(srv.creds[1][2]) == "unix\0tester"
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "no offered mechanism can be satisfied" begin
        # gsi and krb5 are real protocols this client does not implement.
        # Sending a unix credential anyway would be answering a challenge that
        # was never made, so the session ends instead.
        srv, port = start_auth_server(; sec="&P=gsi,v:10400&P=krb5")
        conn, err = without_token() do
            auth_bringup(port; username="tester")
        end
        @test conn === nothing
        @test err !== nothing
        msg = sprint(showerror, err)
        @test occursin("no supported authentication mechanism offered", msg)
        @test occursin("gsi", msg) && occursin("krb5", msg)
        @test isempty(srv.creds)
        @test isempty(srv.violations)
    end

    @testset "a refused credential fails the session, with the server's reason" begin
        srv, port = start_auth_server(;
            sec="&P=unix",
            auth_status=Wire.kXR_error,
            auth_message="unix credentials are not accepted here",
        )
        conn, err = auth_bringup(port; username="tester")
        @test conn === nothing
        @test err !== nothing
        msg = sprint(showerror, err)
        @test occursin("unix authentication failed", msg)
        @test occursin("unix credentials are not accepted here", msg)
        @test srv.creds[1][1] == "unix"
        @test isempty(srv.violations)
    end

    @testset "an answer that is neither ok nor an error is still not success" begin
        # kXR_wait to a kXR_auth is not something this client can act on; what
        # it must not do is carry on as though the credential was accepted.
        srv, port = start_auth_server(; sec="&P=unix", auth_status=Wire.kXR_wait)
        conn, err = auth_bringup(port; username="tester")
        @test conn === nothing
        @test err !== nothing
        @test occursin(
            "unix authentication failed (status $(Wire.kXR_wait))", sprint(showerror, err)
        )
        @test isempty(srv.violations)
    end

    @testset "a rejected credential is not retried with a weaker one" begin
        # One kXR_auth round per connection: a client that answered a refusal
        # by working down the list would be doing the server's policy for it.
        srv, port = start_auth_server(; sec="&P=ztn&P=unix", auth_status=Wire.kXR_error)
        _, err = withenv("BEARER_TOKEN" => "tok") do
            auth_bringup(port; username="tester")
        end
        @test err !== nothing
        @test occursin("ztn authentication failed", sprint(showerror, err))
        @test length(srv.creds) == 1
        @test srv.creds[1][1] == "ztn"
        @test srv.conns == 1
        @test isempty(srv.violations)
    end
end

@testset "conformance: signed requests" begin
    key = collect(0x01:0x20)

    @testset "a mutating request arrives with its signature" begin
        srv, port = start_auth_server(; signing_key=key)
        conn, err = auth_bringup(port; username="tester")
        @test err === nothing
        conn.sec_level = 2
        conn.signing_key = key

        hdr, _ = Session.roundtrip(conn, Wire.MkdirRequest("/data/new"))
        @test hdr.status == Wire.kXR_ok
        @test srv.signed == [Wire.kXR_mkdir]
        @test srv.ops == [Wire.kXR_mkdir]
        @test srv.seqnos == [UInt64(1)]
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "every signature has its own sequence number" begin
        # The counter is what stops a captured signature being replayed, so it
        # has to advance per signed request, not per connection.
        srv, port = start_auth_server(; signing_key=key)
        conn, err = auth_bringup(port; username="tester")
        @test err === nothing
        conn.sec_level = 2
        conn.signing_key = key

        for i in 1:4
            Session.roundtrip(conn, Wire.MkdirRequest("/data/d$i"))
        end
        @test srv.seqnos == UInt64[1, 2, 3, 4]
        @test srv.signed == fill(Wire.kXR_mkdir, 4)
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "the signature covers the payload, not just the header" begin
        # The server recomputes the HMAC over the request bytes it received;
        # a path that did not go into the client's HMAC would not verify.
        srv, port = start_auth_server(; signing_key=key)
        conn, err = auth_bringup(port; username="tester")
        @test err === nothing
        conn.sec_level = 2
        conn.signing_key = key

        for req in (
            Wire.MkdirRequest("/data/a/long/path/that/is/mostly/payload"),
            Wire.RmRequest("/data/gone"),
            Wire.TruncateRequest("/data/short", 4096),
            Wire.ChmodRequest("/data/mode", UInt16(0o640)),
        )
            hdr, _ = Session.roundtrip(conn, req)
            @test hdr.status == Wire.kXR_ok
        end
        @test srv.signed == [Wire.kXR_mkdir, Wire.kXR_rm, Wire.kXR_truncate, Wire.kXR_chmod]
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "a request that changes nothing is not signed" begin
        # Signing every request would cost an extra frame each way for reads.
        # The policy is the server's list of mutating opcodes, and the client
        # has to agree with it in both directions.
        srv, port = start_auth_server(; signing_key=key)
        conn, err = auth_bringup(port; username="tester")
        @test err === nothing
        conn.sec_level = 2
        conn.signing_key = key

        Session.roundtrip(conn, Wire.PingRequest())
        Session.roundtrip(conn, Wire.StatRequest("/data/a.txt"))
        @test isempty(srv.signed)
        @test isempty(srv.seqnos)
        @test srv.ops == [Wire.kXR_ping, Wire.kXR_stat]
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "signing needs both a key and a server that asked for it" begin
        # sec_level < 2 is the ordinary case: no server demanded signing, so a
        # key sitting on the connection must not put frames on the wire. This
        # server verifies nothing and flags any signature it receives.
        for (level, sig_key) in ((0, key), (1, key), (2, nothing), (3, nothing))
            srv, port = start_auth_server()
            conn, err = auth_bringup(port; username="tester")
            @test err === nothing
            conn.sec_level = level
            conn.signing_key = sig_key

            hdr, _ = Session.roundtrip(conn, Wire.MkdirRequest("/data/new"))
            @test hdr.status == Wire.kXR_ok
            @test srv.ops == [Wire.kXR_mkdir]
            @test isempty(srv.signed)
            @test isempty(srv.violations)
            close(conn)
        end
    end
end
