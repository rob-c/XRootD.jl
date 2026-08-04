# X.509 client credentials: the discovery order the grid tools use, the
# failure modes that must not be silent, and a real mutual-TLS handshake
# against a server that requires a client certificate.
#
# `with_prompter` comes from session/test_prompt.jl, which runs first.

using XRootD: Session
using XRootD.Session:
    CredentialRequest,
    X509Credentials,
    discover_x509,
    x509_proxy_candidates,
    x509_ca_path,
    client_ssl_context,
    use_x509!,
    encrypted_key,
    check_key_secrecy,
    tls_upgrade
using HTTP: HTTP
using OpenSSL: OpenSSL
using Sockets: Sockets

"`openssl(1)` is only needed to mint throwaway certificates for these tests."
const HAVE_OPENSSL = Sys.which("openssl") !== nothing

"""
Mint a throwaway PKI under `dir`: a CA, a `localhost` server certificate and a
`grid-user` client certificate, both signed by it. Returns
`(ca, (servercert, serverkey), (clientcert, clientkey))`.
"""
function make_test_pki(dir::AbstractString)
    ca_key = joinpath(dir, "ca.key")
    ca = joinpath(dir, "ca.pem")
    run(
        pipeline(
            `openssl req -x509 -newkey rsa:2048 -nodes -keyout $ca_key -out $ca
             -days 1 -subj "/CN=XRootDjl Test CA"`;
            stdout=devnull,
            stderr=devnull,
        ),
    )
    function issue(name, cn, ext)
        key = joinpath(dir, "$name.key")
        crt = joinpath(dir, "$name.pem")
        csr = joinpath(dir, "$name.csr")
        extfile = joinpath(dir, "$name.ext")
        run(
            pipeline(
                `openssl req -new -newkey rsa:2048 -nodes -keyout $key -out $csr
                 -subj "/CN=$cn"`;
                stdout=devnull,
                stderr=devnull,
            ),
        )
        write(extfile, ext)
        run(
            pipeline(
                `openssl x509 -req -in $csr -CA $ca -CAkey $ca_key -CAcreateserial
                 -out $crt -days 1 -extfile $extfile`;
                stdout=devnull,
                stderr=devnull,
            ),
        )
        chmod(key, 0o600)
        return crt, key
    end
    server = issue(
        "server",
        "localhost",
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
    )
    client = issue("client", "grid-user", "extendedKeyUsage=clientAuth\n")
    return ca, server, client
end

"What a mock HTTP server records for each request it serves."
const RequestLog = Vector{Tuple{String,String,Vector{Pair{String,String}}}}

"Wrap `handler` so every request it serves is appended to `recorded`."
function recording(handler, recorded::RequestLog)
    return function (req)
        push!(recorded, (req.method, req.target, collect(Pair{String,String}, req.headers)))
        return handler(req)
    end
end

"""
An HTTPS server that will not talk to a client without a certificate signed by
`ca`. TLS 1.2 is pinned in both directions: the native TLS 1.3 server never
sends a CertificateRequest, so client authentication only happens over 1.2.
"""
function start_mtls_server(ca, servercert, serverkey, handler)
    cfg = HTTP.TLS.Config(;
        cert_file=servercert,
        key_file=serverkey,
        client_ca_file=ca,
        client_auth=HTTP.TLS.ClientAuthMode.RequireAndVerifyClientCert,
        min_version=HTTP.TLS.TLS1_2_VERSION,
        max_version=HTTP.TLS.TLS1_2_VERSION,
    )
    return HTTP.serve!(handler, HTTP.TLS.listen("tcp", "127.0.0.1:0", cfg); verbose=false)
end

@testset "X.509 credentials" begin
    @testset "discovery order" begin
        mktempdir() do dir
            proxy = joinpath(dir, "proxy.pem")
            cert = joinpath(dir, "usercert.pem")
            key = joinpath(dir, "userkey.pem")
            absent = joinpath(dir, "absent.pem")
            foreach(p -> write(p, "pem"), (proxy, cert, key))
            home = joinpath(dir, "home")
            mkpath(joinpath(home, ".globus"))
            gcert = joinpath(home, ".globus", "usercert.pem")
            gkey = joinpath(home, ".globus", "userkey.pem")
            foreach(p -> write(p, "pem"), (gcert, gkey))

            clean = (
                "X509_USER_PROXY" => nothing,
                "X509_USER_CERT" => nothing,
                "X509_USER_KEY" => nothing,
                "HOME" => home,
            )

            withenv(clean...) do
                # An explicit certificate wins, and doubles as its own key —
                # a proxy PEM holds the chain and the key together.
                c = discover_x509(; cert=proxy, proxies=[proxy])
                @test (c.cert, c.key) == (proxy, proxy)
                c = discover_x509(; cert=cert, key=key, proxies=[proxy])
                @test (c.cert, c.key) == (cert, key)

                # A proxy on the search path beats $X509_USER_CERT and ~/.globus.
                c = discover_x509(; proxies=[absent, proxy])
                @test (c.cert, c.key) == (proxy, proxy)

                # ~/.globus is the last resort.
                c = discover_x509(; proxies=[absent])
                @test (c.cert, c.key) == (gcert, gkey)
            end

            withenv(clean..., "X509_USER_CERT" => cert, "X509_USER_KEY" => key) do
                c = discover_x509(; proxies=[absent])
                @test (c.cert, c.key) == (cert, key)
            end

            # $X509_USER_CERT without $X509_USER_KEY: the certificate file is
            # also the key file.
            withenv(clean..., "X509_USER_CERT" => proxy) do
                c = discover_x509(; proxies=[absent])
                @test (c.cert, c.key) == (proxy, proxy)
            end

            # No credential anywhere is not an error: the handshake just
            # carries no client certificate.
            withenv(clean..., "HOME" => dir) do
                @test discover_x509(; proxies=[absent]) === nothing
            end

            withenv("X509_USER_PROXY" => proxy) do
                @test first(x509_proxy_candidates()) == proxy
            end
            withenv("X509_USER_PROXY" => nothing) do
                @test only(x509_proxy_candidates()) ==
                    "/tmp/x509up_u$(ccall(:getuid, Cuint, ()))"
            end

            @test_throws ArgumentError discover_x509(; cert=absent)
            @test_throws ArgumentError discover_x509(; cert=cert, key=absent)
            @test_throws ArgumentError discover_x509(; key=key)
        end
    end

    @testset "CA directory" begin
        mktempdir() do dir
            withenv("X509_CERT_DIR" => dir) do
                @test x509_ca_path() == dir
            end
            withenv("X509_CERT_DIR" => joinpath(dir, "absent")) do
                @test x509_ca_path() === nothing
            end
        end
    end

    @testset "unusable private keys" begin
        mktempdir() do dir
            pkcs8 = joinpath(dir, "pkcs8.pem")
            write(pkcs8, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n")
            legacy = joinpath(dir, "legacy.pem")
            write(legacy, "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n")
            plain = joinpath(dir, "plain.pem")
            write(plain, "-----BEGIN PRIVATE KEY-----\nAAAA\n")

            @test encrypted_key(pkcs8)
            @test encrypted_key(legacy)
            @test !encrypted_key(plain)
            @test !encrypted_key(joinpath(dir, "absent.pem"))   # unreadable ≠ encrypted

            # A world-readable key is a warning, not a refusal: container and
            # network filesystems report bits the user cannot always fix.
            loose = joinpath(dir, "loose.pem")
            write(loose, "-----BEGIN PRIVATE KEY-----\n")
            chmod(loose, 0o644)
            @test_logs (:warn,) check_key_secrecy(loose)
            chmod(loose, 0o600)
            @test_logs check_key_secrecy(loose)
            # A key that cannot be statted has no permissions to complain
            # about; the caller's own open will produce the real diagnosis.
            @test_logs check_key_secrecy(joinpath(dir, "absent.pem"))
            @test check_key_secrecy(joinpath(dir, "absent.pem")) === nothing
        end
    end

    if !HAVE_OPENSSL
        @warn "openssl(1) not on PATH — X.509 handshake tests skipped"
    else
        mktempdir() do dir
            ca, (servercert, serverkey), (clientcert, clientkey) = make_test_pki(dir)

            @testset "loading a credential into a context" begin
                @test client_ssl_context() isa OpenSSL.SSLContext
                creds = X509Credentials(clientcert, clientkey)
                @test client_ssl_context(; creds, ca_path=ca) isa OpenSSL.SSLContext

                # Certificate and key from different identities must not load.
                mismatched = X509Credentials(clientcert, serverkey)
                @test_throws ErrorException use_x509!(
                    OpenSSL.SSLContext(OpenSSL.TLSClientMethod()), mismatched
                )

                # A file that is not a certificate fails at the chain load,
                # before the key is ever looked at.
                notacert = joinpath(dir, "notacert.pem")
                write(notacert, "this is not a certificate\n")
                err = try
                    use_x509!(
                        OpenSSL.SSLContext(OpenSSL.TLSClientMethod()),
                        X509Credentials(notacert, clientkey),
                    )
                catch e
                    e
                end
                @test err isa ErrorException && occursin("certificate chain", err.msg)

                encrypted = joinpath(dir, "encrypted.key")
                write(encrypted, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n")
                chmod(encrypted, 0o600)
                err = try
                    use_x509!(
                        OpenSSL.SSLContext(OpenSSL.TLSClientMethod()),
                        X509Credentials(clientcert, encrypted),
                    )
                catch e
                    e
                end
                @test err isa ErrorException && occursin("proxy", err.msg)
            end

            @testset "a passphrase-encrypted key is asked about, not refused" begin
                locked = joinpath(dir, "locked.key")
                run(
                    pipeline(
                        `openssl pkcs8 -topk8 -in $clientkey -out $locked
                         -passout pass:hunter2 -v2 aes-256-cbc`;
                        stdout=devnull,
                        stderr=devnull,
                    ),
                )
                chmod(locked, 0o600)
                @test encrypted_key(locked)
                creds = X509Credentials(clientcert, locked)
                fresh() = OpenSSL.SSLContext(OpenSSL.TLSClientMethod())

                asked = CredentialRequest[]
                with_prompter(r -> (push!(asked, r); "hunter2")) do
                    @test use_x509!(fresh(), creds) isa OpenSSL.SSLContext
                    @test length(asked) == 1
                    @test asked[1].kind === :passphrase
                    @test asked[1].secret          # never echoed back at the user
                    @test occursin(locked, asked[1].reason)
                    # Asked once and remembered against the key it unlocks: a
                    # redirect chain builds a context per hop from the same file.
                    @test use_x509!(fresh(), creds) isa OpenSSL.SSLContext
                    @test length(asked) == 1
                end

                tries = 0
                with_prompter(_ -> (tries += 1; "wrong")) do
                    # A passphrase that does not decrypt is forgotten, so the
                    # next attempt asks again rather than replaying it.
                    @test_throws ErrorException use_x509!(fresh(), creds)
                    @test_throws ErrorException use_x509!(fresh(), creds)
                    @test tries == 2
                end

                withenv("XRDC_NO_PROMPT" => "1") do
                    err = try
                        use_x509!(fresh(), creds)
                    catch e
                        e
                    end
                    @test err isa ErrorException
                    @test occursin("no passphrase was given", err.msg)
                end
            end

            @testset "mutual TLS handshake" begin
                recorded = RequestLog()
                server = start_mtls_server(
                    ca,
                    servercert,
                    serverkey,
                    recording(req -> HTTP.Response(200, "ok"), recorded),
                )
                port = HTTP.port(server)
                try
                    # tls_upgrade presenting the client certificate: the server
                    # requires one, so a reply at all proves it was accepted.
                    creds = discover_x509(; cert=clientcert, key=clientkey)
                    ssl = tls_upgrade(
                        Sockets.connect("127.0.0.1", port), "localhost"; creds, cafile=ca
                    )
                    try
                        write(ssl, "GET /x509 HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        @test String(Session.readn(ssl, 12)) == "HTTP/1.1 200"
                    finally
                        close(ssl)
                    end
                    @test last(recorded)[2] == "/x509"

                    # The same upgrade without a credential cannot complete.
                    sock = Sockets.connect("127.0.0.1", port)
                    @test_throws Exception tls_upgrade(sock, "localhost"; cafile=ca)

                    # An unknown CA is refused even with a valid credential.
                    sock = Sockets.connect("127.0.0.1", port)
                    @test_throws Exception tls_upgrade(sock, "localhost"; creds)
                finally
                    close(server)
                end
            end
        end
    end
end
