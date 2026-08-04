# The `XRD_*` environment, and keeping credentials out of what gets printed.
#
# Two properties carry the weight here. A site profile written for the C++
# client must configure this one the same way, because a job that is handed a
# tuned environment and quietly ignores it is worse than one that has no
# environment at all — it looks configured. And a value that a variable
# supplies must survive being wrong: a typo in a profile file is discovered by
# every job on the site at once, so an unparseable setting has to fall back to
# the default rather than fail the connection.

using Sockets
using XRootD: Session, Storage, XrdCl
using XRootD.Session:
    DEFAULT_AUTH_ORDER,
    DEFAULT_CONNECTION_WINDOW_S,
    DEFAULT_MAX_WAIT_MS,
    DEFAULT_REDIRECT_LIMIT,
    REDACTED,
    auth_order,
    connection_window_s,
    env_cafile,
    env_flag,
    env_int,
    env_number,
    is_secret,
    max_wait_ms,
    redact,
    redact_url,
    redacted,
    redirect_limit,
    stream_timeout_s,
    tcp_connect,
    xrd_username

@testset "the XRD_* environment" begin
    @testset "flags" begin
        withenv("XRD_T" => nothing) do
            @test env_flag("XRD_T") == false
            @test env_flag("XRD_T", true) == true
        end
        for on in ("1", "true", "TRUE", "yes", "on", " on ")
            withenv("XRD_T" => on) do
                @test env_flag("XRD_T") == true
            end
        end
        for off in ("0", "false", "no", "off", "maybe")
            withenv("XRD_T" => off) do
                @test env_flag("XRD_T", true) == false
            end
        end
        # An empty value is not a value: `export XRD_T=` in a profile that
        # meant to unset it must not read as "off" where the default is on.
        withenv("XRD_T" => "") do
            @test env_flag("XRD_T", true) == true
        end
    end

    @testset "numbers" begin
        withenv("XRD_N" => nothing) do
            @test env_number("XRD_N", 7) == 7.0
            @test env_int("XRD_N", 7) == 7
        end
        withenv("XRD_N" => "2.5") do
            @test env_number("XRD_N", 7) == 2.5
        end
        withenv("XRD_N" => " 12 ") do
            @test env_int("XRD_N", 7) == 12
        end
        # Nonsense and negatives leave the default standing rather than
        # arming a timeout of minus thirty seconds.
        for bad in ("", "soon", "-1", "3s")
            withenv("XRD_N" => bad) do
                @test env_number("XRD_N", 7) == 7.0
                @test env_int("XRD_N", 7) == 7
            end
        end
        # A fractional count is not an integer, and is refused as such.
        withenv("XRD_N" => "2.5") do
            @test env_int("XRD_N", 7) == 7
        end
    end

    @testset "the login account" begin
        withenv("XRD_USERNAME" => "grid01", "USER" => "local", "LOGNAME" => nothing) do
            @test xrd_username() == "grid01"
        end
        withenv("XRD_USERNAME" => nothing, "USER" => "local", "LOGNAME" => nothing) do
            @test xrd_username() == "local"
        end
        withenv("XRD_USERNAME" => nothing, "USER" => "", "LOGNAME" => "fromlog") do
            @test xrd_username() == "fromlog"
        end
        # A container with no passwd entry still has to log in as somebody.
        withenv("XRD_USERNAME" => nothing, "USER" => nothing, "LOGNAME" => nothing) do
            @test xrd_username() == "nobody"
        end
    end

    @testset "the CA bundle" begin
        mktemp() do path, io
            close(io)
            withenv("X509_CERT_FILE" => path, "SSL_CERT_FILE" => nothing) do
                @test env_cafile() == path
            end
            withenv("X509_CERT_FILE" => nothing, "SSL_CERT_FILE" => path) do
                @test env_cafile() == path
            end
            # X509_CERT_FILE first, both being set.
            withenv("X509_CERT_FILE" => path, "SSL_CERT_FILE" => "/nonexistent") do
                @test env_cafile() == path
            end
            # A stale profile pointing at a bundle that was removed must not
            # be handed to OpenSSL, which would fail every handshake.
            withenv("X509_CERT_FILE" => "/nonexistent", "SSL_CERT_FILE" => nothing) do
                @test env_cafile() === nothing
            end
        end
        withenv("X509_CERT_FILE" => nothing, "SSL_CERT_FILE" => nothing) do
            @test env_cafile() === nothing
        end
    end

    @testset "timeouts and limits" begin
        withenv(
            "XRD_CONNECTIONWINDOW" => nothing,
            "XRD_STREAMTIMEOUT" => nothing,
            "XRD_REDIRECTLIMIT" => nothing,
        ) do
            @test connection_window_s() == DEFAULT_CONNECTION_WINDOW_S
            @test stream_timeout_s() == 0
            @test redirect_limit() == DEFAULT_REDIRECT_LIMIT
        end
        withenv(
            "XRD_CONNECTIONWINDOW" => "5",
            "XRD_STREAMTIMEOUT" => "60",
            "XRD_REDIRECTLIMIT" => "2",
        ) do
            @test connection_window_s() == 5
            @test stream_timeout_s() == 60
            @test redirect_limit() == 2
        end
    end

    @testset "the request-timeout ceiling" begin
        withenv("XRDC_MAX_WAIT_MS" => nothing, "XRD_REQUESTTIMEOUT" => nothing) do
            @test max_wait_ms() == DEFAULT_MAX_WAIT_MS
        end
        # XrdCl states it in seconds; this client counts in milliseconds.
        withenv("XRDC_MAX_WAIT_MS" => nothing, "XRD_REQUESTTIMEOUT" => "90") do
            @test max_wait_ms() == 90_000
        end
        # The client's own knob is the more specific of the two and wins.
        withenv("XRDC_MAX_WAIT_MS" => "1500", "XRD_REQUESTTIMEOUT" => "90") do
            @test max_wait_ms() == 1500
        end
        withenv("XRDC_MAX_WAIT_MS" => nothing, "XRD_REQUESTTIMEOUT" => "0") do
            @test max_wait_ms() == DEFAULT_MAX_WAIT_MS
        end
    end

    @testset "the mechanism order" begin
        withenv("XrdSecPROTOCOL" => nothing) do
            @test auth_order() == collect(DEFAULT_AUTH_ORDER)
        end
        withenv("XrdSecPROTOCOL" => "unix,ztn") do
            @test auth_order() == ["unix", "ztn"]
        end
        # Comma, space, or both — XrdCl accepts all three spellings.
        withenv("XrdSecPROTOCOL" => "ZTN gsi , sss") do
            @test auth_order() == ["ztn", "gsi", "sss"]
        end
        withenv("XrdSecPROTOCOL" => "   ") do
            @test auth_order() == collect(DEFAULT_AUTH_ORDER)
        end
    end

    @testset "a connect that is never accepted gives up" begin
        # A socket nothing listens on, on a host that does not answer: the
        # connect neither completes nor is refused, which is the case the
        # window exists for. 10.255.255.1 is RFC1918 space with no route.
        t0 = time()
        @test_throws ErrorException tcp_connect("10.255.255.1", 1094, 0.5)
        @test time() - t0 < 5

        # A refusal must still arrive as the IOError it would have been
        # without the window, or every `catch` upstream would need to learn a
        # new exception type.
        listener = listen(ip"127.0.0.1", 0)
        _, port = getsockname(listener)
        close(listener)
        @test_throws Base.IOError tcp_connect("127.0.0.1", Int(port), 5)

        srv = listen(ip"127.0.0.1", 0)
        _, open_port = getsockname(srv)
        try
            sock = tcp_connect("127.0.0.1", Int(open_port), 5)
            @test isopen(sock)
            close(sock)
            # Zero means "as long as the operating system allows".
            sock = tcp_connect("127.0.0.1", Int(open_port), 0)
            @test isopen(sock)
            close(sock)
        finally
            close(srv)
        end

        # And the window is what `connect` uses, not just what `tcp_connect`
        # accepts: the default is read from the environment on every call, so
        # a profile exported after this process started still applies.
        t0 = time()
        withenv("XRD_CONNECTIONWINDOW" => "0.5") do
            @test_throws ErrorException Session.connect("10.255.255.1", 1094)
        end
        @test time() - t0 < 5
    end
end

@testset "credentials stay out of what is printed" begin
    @testset "which names are credentials" begin
        @test is_secret(:token)
        @test is_secret("Authz")
        @test is_secret("X-Amz-Signature")
        @test !is_secret(:insecure_tls)
        @test !is_secret("access-key-id")
    end

    @testset "a secret prints as its absence or not at all" begin
        # Withheld and absent are different diagnoses of the same failure, so
        # they do not collapse into one another.
        @test redacted(nothing) === nothing
        @test redacted("") == ""
        @test redacted("eyJhbGciOi") == REDACTED
        @test redacted(Vector{UInt8}("key")) == REDACTED
    end

    @testset "option dictionaries keep their keys" begin
        opts = Dict{Symbol,Any}(:token => "eyJhbGciOi", :insecure_tls => true)
        r = redact(opts)
        @test r[:token] == REDACTED
        @test r[:insecure_tls] === true
        @test opts[:token] == "eyJhbGciOi"      # the copy, not the original
    end

    @testset "URLs that carry a credential in the query" begin
        @test redact_url("root://h:1094//p") == "root://h:1094//p"
        @test redact_url("root://h:1094//p?authz=Bearer%20eyJ&xrd.wantprot=ztn") ==
            "root://h:1094//p?authz=$REDACTED&xrd.wantprot=ztn"
        @test redact_url("https://x/o?X-Amz-Signature=dead&list-type=2") ==
            "https://x/o?X-Amz-Signature=$REDACTED&list-type=2"
        # A bare flag has no value to redact, and must not be mangled.
        @test redact_url("root://h//p?xrd.k8s&authz=t") ==
            "root://h//p?xrd.k8s&authz=$REDACTED"
    end

    @testset "handles print what they are, not what they hold" begin
        fs = XrdCl.FileSystem("root://h:1094"; token="eyJhbGciOi", keytab="/etc/k")
        s = sprint(show, fs)
        @test occursin("root://h:1094", s)
        @test occursin(":token => \"$REDACTED\"", s)
        @test occursin(":keytab => \"$REDACTED\"", s)
        @test !occursin("eyJhbGciOi", s)
        @test !occursin("/etc/k", s)

        f = XrdCl.File()
        f.url = "root://h//p?authz=eyJhbGciOi"
        f.opts = Dict{Symbol,Any}(:token => "eyJhbGciOi", :insecure_tls => true)
        s = sprint(show, f)
        @test !occursin("eyJhbGciOi", s)
        @test occursin("insecure_tls => true", s)

        b = Storage.storage_for("https://example.org/o"; token="eyJhbGciOi")
        s = sprint(show, b)
        @test occursin("https://example.org/o", s)
        @test occursin("token=$REDACTED", s)
        @test !occursin("eyJhbGciOi", s)          # nor via the header it became

        xb = Storage.storage_for("root://h:1094//p"; token="eyJhbGciOi")
        @test !occursin("eyJhbGciOi", sprint(show, xb))

        creds = Storage.S3Credentials(;
            access_key="AKIAEXAMPLE", secret_key="wJalrXUtn", session_token="FQoGZ"
        )
        s = sprint(show, creds)
        @test occursin("AKIAEXAMPLE", s)          # the identity is not a secret
        @test !occursin("wJalrXUtn", s)
        @test !occursin("FQoGZ", s)
    end
end
