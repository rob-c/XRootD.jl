# The security exchange, as bytes on the wire: which credential the client
# chooses from what the server offers, what it puts in it, and what happens
# when the server refuses it.
#
# The choice is the interesting part. A server states its acceptable
# protocols in the order its authorization honours them, and the client works
# down that list; ignoring the server's order, or sending a credential for a
# protocol the server never offered, is a security failure that leaves a
# perfectly healthy-looking session behind. Ground truth for the selection
# and payload shapes: libxrdc sec/sec_{token,sss,unix}.c.

using XRootD: Wire, Session
using XRootD.Session: CredentialRequest

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
        # These mock servers speak plain TCP, and the client withholds a
        # bearer token over cleartext; XRDC_ZTN_CLEARTEXT is the documented
        # opt-out for a test bench that is its own network, so the ztn
        # testsets here run under it.
        srv, port = start_auth_server(; sec="&P=ztn")
        conn, err = withenv(
            "BEARER_TOKEN" => "header.payload.signature", "XRDC_ZTN_CLEARTEXT" => "1"
        ) do
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
        conn, err = withenv(
            "BEARER_TOKEN" => "from.the.environment", "XRDC_ZTN_CLEARTEXT" => "1"
        ) do
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
        conn, err = withenv("BEARER_TOKEN" => "tok", "XRDC_ZTN_CLEARTEXT" => "1") do
            auth_bringup(port; username="tester")
        end
        @test err === nothing
        @test srv.creds[1][1] == "ztn"
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "a bearer token is not volunteered over cleartext" begin
        # The token is a reusable secret and these connections are plain TCP:
        # without the opt-out the client keeps it, falls back when it can, and
        # names the withholding when it cannot — "the token was withheld" and
        # "no token exists" need different fixes.
        srv, port = start_auth_server(; sec="&P=ztn&P=unix")
        conn, err = withenv(
            "BEARER_TOKEN" => "secret.jwt", "XRDC_ZTN_CLEARTEXT" => nothing
        ) do
            auth_bringup(port; username="tester")
        end
        @test err === nothing
        @test all(c[1] != "ztn" for c in srv.creds)
        @test srv.creds[1][1] == "unix"
        @test isempty(srv.violations)
        close(conn)

        srv, port = start_auth_server(; sec="&P=ztn")
        asked = CredentialRequest[]
        conn, err = withenv(
            "BEARER_TOKEN" => "secret.jwt", "XRDC_ZTN_CLEARTEXT" => nothing
        ) do
            auth_bringup(port; username="tester", prompter=r -> (push!(asked, r); "typed"))
        end
        @test conn === nothing && err !== nothing
        msg = sprint(showerror, err)
        @test occursin("only sent over TLS", msg)
        @test occursin("XRDC_ZTN_CLEARTEXT", msg)
        @test isempty(srv.creds)     # the secret stayed on this side
        @test isempty(asked)         # nor was anyone asked to type one it would not send
        @test isempty(srv.violations)
    end

    @testset "the server's advertised order decides, not a client ranking" begin
        # The trailer is built from the server's sec.protocol directives first
        # to last: whichever mechanism it lists first is the one its
        # authorization actually honours, so with everything satisfiable the
        # first offer is the one answered.
        with_keytab() do keytab
            for (sec, winner) in
                (("&P=unix&P=sss&P=ztn", "unix"), ("&P=ztn&P=sss&P=unix", "ztn"))
                srv, port = start_auth_server(; sec=sec)
                conn, err = withenv("BEARER_TOKEN" => "tok", "XRDC_ZTN_CLEARTEXT" => "1") do
                    auth_bringup(port; username="tester", keytab=keytab)
                end
                @test err === nothing
                @test srv.creds[1][1] == winner
                @test isempty(srv.violations)
                close(conn)
            end
        end
    end

    @testset "an offered sss is satisfied from the keytab" begin
        with_keytab(; id=42) do keytab
            srv, port = start_auth_server(; sec="&P=sss&P=unix")
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
        conn, err = withenv("XRDC_ZTN_CLEARTEXT" => "1") do
            without_token() do
                @test Session.discover_token() === nothing
                auth_bringup(port; username="tester", keytab=missing_keytab)
            end
        end
        @test err === nothing
        @test srv.creds[1][1] == "unix"
        @test String(srv.creds[1][2]) == "unix\0tester"
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "a token the client cannot find is asked for" begin
        # Falling through to unix is not free: an authorizing server accepts
        # the login and then refuses operation after operation. Asking here is
        # the last moment at which the user can still fix it.
        srv, port = start_auth_server(; sec="&P=ztn&P=unix")
        asked = CredentialRequest[]
        conn, err = withenv("XRDC_ZTN_CLEARTEXT" => "1") do
            without_token() do
                auth_bringup(
                    port;
                    username="tester",
                    prompter=r -> (push!(asked, r); "typed.at.the.prompt"),
                )
            end
        end
        @test err === nothing
        @test srv.creds[1][1] == "ztn"
        @test String(srv.creds[1][2]) == "ztn\0typed.at.the.prompt"
        @test length(asked) == 1
        @test asked[1].kind === :token
        @test asked[1].host == "127.0.0.1" && asked[1].port == port
        @test !asked[1].secret
        # The prompt names the endpoint that asked and every place already
        # searched, so the answer can be made permanent.
        @test occursin("root://127.0.0.1:$port", asked[1].reason)
        @test "\$BEARER_TOKEN" in asked[1].searched
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "a declined prompt falls through as though nothing was asked" begin
        srv, port = start_auth_server(; sec="&P=ztn&P=unix")
        conn, err = withenv("XRDC_ZTN_CLEARTEXT" => "1") do
            without_token() do
                auth_bringup(port; username="tester", prompter=_ -> nothing)
            end
        end
        @test err === nothing
        @test srv.creds[1][1] == "unix"
        @test isempty(srv.violations)
        close(conn)
    end

    @testset "a credential the client already has is not asked about" begin
        # Three ways of already having one: the caller passed a token, the
        # environment holds one, or sss can be satisfied instead. None of them
        # is a reason to interrupt the user.
        asked = CredentialRequest[]
        record = r -> (push!(asked, r); nothing)

        srv, port = start_auth_server(; sec="&P=ztn&P=unix")
        conn, err = withenv("XRDC_ZTN_CLEARTEXT" => "1") do
            without_token() do
                auth_bringup(
                    port; username="tester", token="from.the.caller", prompter=record
                )
            end
        end
        @test err === nothing && isempty(asked)
        @test String(srv.creds[1][2]) == "ztn\0from.the.caller"
        close(conn)

        srv, port = start_auth_server(; sec="&P=ztn&P=unix")
        conn, err = withenv(
            "BEARER_TOKEN" => "from.the.environment", "XRDC_ZTN_CLEARTEXT" => "1"
        ) do
            auth_bringup(port; username="tester", prompter=record)
        end
        @test err === nothing && isempty(asked)
        @test String(srv.creds[1][2]) == "ztn\0from.the.environment"
        close(conn)

        with_keytab(; id=7) do keytab
            srv, port = start_auth_server(; sec="&P=ztn&P=sss&P=unix")
            conn, err = withenv("XRDC_ZTN_CLEARTEXT" => "1") do
                without_token() do
                    auth_bringup(port; username="tester", keytab=keytab, prompter=record)
                end
            end
            @test err === nothing && isempty(asked)
            @test srv.creds[1][1] == "sss"
            close(conn)
        end
    end

    @testset "a keytab is asked for only when nothing else would work" begin
        # sss alongside unix needs no help; sss alone is the whole offer, so a
        # missing keytab ends the session unless someone supplies one.
        asked = CredentialRequest[]
        srv, port = start_auth_server(; sec="&P=sss&P=unix")
        conn, err = without_token() do
            auth_bringup(port; username="tester", prompter=r -> (push!(asked, r); nothing))
        end
        @test err === nothing && isempty(asked)
        @test srv.creds[1][1] == "unix"
        close(conn)

        with_keytab(; id=11) do keytab
            srv, port = start_auth_server(; sec="&P=sss")
            conn, err = without_token() do
                auth_bringup(
                    port; username="tester", prompter=r -> (push!(asked, r); keytab)
                )
            end
            @test err === nothing
            @test length(asked) == 1 && asked[1].kind === :keytab
            @test srv.creds[1][1] == "sss"
            @test Wire.get_u64(srv.creds[1][2], 9) == 11
            @test isempty(srv.violations)
            close(conn)
        end
    end

    @testset "a token that was typed and refused is not remembered" begin
        # An accepted token is typed once and reused for every connection the
        # cluster needs; a refused one is worth asking about again, because a
        # paste from a stale terminal is exactly what it looks like.
        function connect_twice(sec, auth_status)
            srv, port = start_auth_server(; sec=sec, auth_status=auth_status)
            asked, conns = 0, Any[]
            previous = Session.prompt_credentials!(_ -> (asked += 1; "typed.token"))
            Session.forget_credentials!()
            try
                withenv("XRDC_ZTN_CLEARTEXT" => "1") do
                    without_token() do
                        for _ in 1:2
                            try
                                push!(
                                    conns,
                                    Session.connect(
                                        "127.0.0.1", port; x509=false, username="tester"
                                    ),
                                )
                            catch
                                # a refused credential fails the bring-up, as it must
                            end
                        end
                    end
                end
            finally
                Session.prompt_credentials!(previous)
                Session.forget_credentials!()
                foreach(close, conns)
            end
            return srv, asked, length(conns)
        end

        srv, asked, up = connect_twice("&P=ztn", Wire.kXR_error)
        @test asked == 2
        @test up == 0
        @test length(srv.creds) == 2
        @test isempty(srv.violations)

        srv, asked, up = connect_twice("&P=ztn", Wire.kXR_ok)
        @test asked == 1
        @test up == 2
        @test all(String(c[2]) == "ztn\0typed.token" for c in srv.creds)
        @test isempty(srv.violations)
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
        # ...and named as unimplemented, so gsi does not look like a protocol
        # this client speaks that merely went wrong.
        @test occursin("not implemented by this client", msg)
        @test isempty(srv.creds)
        @test isempty(srv.violations)
    end

    @testset "\$XrdSecPROTOCOL both orders and restricts the choice" begin
        # XrdCl's variable, honoured under XrdCl's name: a site that pins its
        # jobs to one mechanism has pinned this client too.
        @testset "it reorders" begin
            srv, port = start_auth_server(; sec="&P=ztn&P=unix")
            conn, err = withenv(
                "BEARER_TOKEN" => "tok",
                "XRDC_ZTN_CLEARTEXT" => "1",
                "XrdSecPROTOCOL" => "unix,ztn",
            ) do
                auth_bringup(port; username="tester")
            end
            @test err === nothing
            @test srv.creds[1][1] == "unix"     # ztn was available and passed over
            @test isempty(srv.violations)
            close(conn)
        end

        @testset "it restricts" begin
            # unix is offered and would have worked. Pinned to ztn with no
            # token to send, the session ends rather than logging in weakly —
            # which is the whole point of pinning.
            asked = CredentialRequest[]
            srv, port = start_auth_server(; sec="&P=sss&P=unix")
            conn, err = without_token() do
                withenv("XrdSecPROTOCOL" => "ztn") do
                    auth_bringup(
                        port; username="tester", prompter=r -> (push!(asked, r); nothing)
                    )
                end
            end
            @test conn === nothing && err !== nothing
            @test isempty(srv.creds)
            # Nor was a keytab asked for: a credential the client would not
            # send is not a credential worth interrupting the user about.
            @test isempty(asked)
            @test isempty(srv.violations)
        end

        @testset "the failure names both lists" begin
            # "the server offered nothing usable" and "the environment
            # excluded the one mechanism both sides had" look identical from
            # the outside, so the message distinguishes them.
            srv, port = start_auth_server(; sec="&P=unix")
            conn, err = without_token() do
                withenv("XrdSecPROTOCOL" => "ztn sss") do
                    auth_bringup(port; username="tester")
                end
            end
            @test conn === nothing
            msg = sprint(showerror, err)
            @test occursin("server: unix", msg)
            @test occursin("client: ztn, sss", msg)
            @test isempty(srv.violations)
        end

        @testset "a name this client does not implement is passed over" begin
            # gsi stays in the list — it is reported when nothing works — but
            # sss behind it is still tried.
            with_keytab(; id=5) do keytab
                srv, port = start_auth_server(; sec="&P=gsi&P=sss&P=unix")
                conn, err = without_token() do
                    withenv("XrdSecPROTOCOL" => "gsi,sss,unix") do
                        auth_bringup(port; username="tester", keytab=keytab)
                    end
                end
                @test err === nothing
                @test srv.creds[1][1] == "sss"
                @test isempty(srv.violations)
                close(conn)
            end
        end
    end

    @testset "a live connection prints no session key" begin
        # sss leaves a shared signing key on the Connection, and a key that
        # has been printed into a log is a key that has to be rotated.
        key = collect(0x01:0x20)
        srv, port = start_auth_server(; sec="&P=unix", signing_key=key)
        conn, err = auth_bringup(port; username="tester")
        @test err === nothing
        conn.sec_level = 2
        conn.signing_key = key

        s = sprint(show, conn)
        @test occursin("tester@127.0.0.1:$port", s)
        @test occursin("open", s)
        @test occursin("signed(level 2)", s)
        @test !occursin("signing_key", s)
        @test !occursin(string(key), s)
        close(conn)
        @test occursin("closed", sprint(show, conn))
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
        _, err = withenv("BEARER_TOKEN" => "tok", "XRDC_ZTN_CLEARTEXT" => "1") do
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
        # The server recomputes the hash over the request bytes it received
        # and re-encrypts it under the session key; a path that did not go
        # into the client's hash would not verify.
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
