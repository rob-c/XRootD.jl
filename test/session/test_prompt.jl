# Asking for a credential the client could not find. Two properties matter
# more than the wording: a prompt must never fire where nobody can answer it
# (a batch job that blocks forever is worse than one that fails), and it must
# fire at most once per process for a credential that a redirect chain will
# need at every hop.

using XRootD: Session
using XRootD.Session:
    CredentialRequest,
    TLSHandshakeFailed,
    ask_credential,
    ask_on,
    forget_credential!,
    forget_credentials!,
    pem_has_key,
    prompt_client_cert,
    prompt_credentials!,
    prompting_enabled,
    resolve_answer,
    tty_prompt,
    untrusted_server,
    wants_client_cert

"Run `f` with `p` as the credential prompter and no credential remembered."
function with_prompter(f, p)
    previous = prompt_credentials!(p)
    forget_credentials!()
    try
        return f()
    finally
        prompt_credentials!(previous)
        forget_credentials!()
    end
end

"The answer `ask_on` gives to `req` when `typed` is what the user types."
function typed_answer(req::CredentialRequest, typed::AbstractString; tries::Int=3)
    out = IOBuffer()
    answer = ask_on(IOBuffer(typed), out, req; tries=tries)
    return answer, String(take!(out))
end

function token_request(; kwargs...)
    return CredentialRequest(
        :token, "example.org", 1094; reason="no token was found", kwargs...
    )
end

@testset "credential prompting" begin
    @testset "a request carries everywhere the client already looked" begin
        req = token_request(; searched=["\$BEARER_TOKEN", "/tmp/bt_u0"])
        @test req.kind === :token
        @test req.host == "example.org"
        @test req.port == 1094
        @test req.searched == ["\$BEARER_TOKEN", "/tmp/bt_u0"]
        @test !req.secret

        _, shown = typed_answer(req, "\n")
        # The places tried are in the prompt, so the answer can be made
        # permanent instead of retyped at the next invocation.
        @test occursin("no token was found", shown)
        @test occursin("looked in: \$BEARER_TOKEN, /tmp/bt_u0", shown)
        @test occursin("press Enter alone", shown)
    end

    @testset "the terminal prompter stays silent when told to be" begin
        withenv("XRDC_NO_PROMPT" => "1") do
            @test !prompting_enabled()
            @test tty_prompt(token_request()) === nothing
        end
        withenv("XRDC_NO_PROMPT" => nothing) do
            # The suite runs with the switch set, so this is the only place the
            # stream test itself is evaluated; whether it says yes depends on
            # how the runner was started, and the prompter is only called when
            # it says no — asking here would block the suite on a real answer.
            enabled = prompting_enabled()
            @test enabled == (isa(stdin, Base.TTY) && isa(stderr, Base.TTY))
            if !enabled
                @test tty_prompt(token_request()) === nothing
            end
        end
    end

    @testset "an empty answer means carry on without one" begin
        @test typed_answer(token_request(), "\n")[1] === nothing
        @test typed_answer(token_request(), "   \n")[1] === nothing
        @test typed_answer(token_request(), "")[1] === nothing        # EOF
    end

    @testset "a token may be pasted or pointed at" begin
        @test typed_answer(token_request(), "header.payload.signature\n")[1] ==
            "header.payload.signature"
        mktemp() do path, io
            write(io, "  from.the.file  \n")
            close(io)
            @test typed_answer(token_request(), "$path\n")[1] == "from.the.file"
        end
    end

    @testset "a mistyped path is not sent to the server as a token" begin
        # The distinction is whether the answer looks like a path: a token has
        # no slashes in it, so one that does and does not exist is a typo.
        missing_path = joinpath(mktempdir(), "absent.tok")
        answer, shown = typed_answer(token_request(), "$missing_path\n\n")
        @test answer === nothing
        @test occursin("no such token file: $missing_path", shown)

        mktemp() do path, io
            close(io)                                   # an empty token file
            answer, shown = typed_answer(token_request(), "$path\n\n")
            @test answer === nothing
            @test occursin("is empty", shown)
        end
    end

    @testset "a path that is not there is asked for again" begin
        req = CredentialRequest(:x509, "example.org", 1094; reason="no proxy")
        absent = joinpath(mktempdir(), "absent.pem")
        mktemp() do path, io
            write(io, "pem")
            close(io)
            answer, shown = typed_answer(req, "$absent\n$path\n")
            @test answer == path
            @test occursin("no such file: $absent", shown)
        end
        # ... but not forever: three refusals end the exchange rather than
        # looping at a user who does not have the file.
        answer, shown = typed_answer(req, "$absent\n$absent\n$absent\n$absent\n")
        @test answer === nothing
        @test count("no such file", shown) == 3
    end

    @testset "a passphrase is taken exactly as typed" begin
        # Not stripped and not treated as a path: leading and trailing spaces
        # are as much a part of a passphrase as any other character.
        req = CredentialRequest(:passphrase, "", 0; reason="encrypted key", secret=true)
        @test typed_answer(req, "  two words  \n")[1] == "  two words  "
        @test resolve_answer("~/not/expanded", req) == ("~/not/expanded", "")
    end

    @testset "one process asks once" begin
        asked = CredentialRequest[]
        with_prompter(r -> (push!(asked, r); "tok")) do
            @test ask_credential(token_request()) == "tok"
            @test ask_credential(token_request()) == "tok"
            # A redirect chain re-authenticates at every hop; the user typed it
            # for the cluster, not for the manager that answered first.
            @test length(asked) == 1
        end
    end

    @testset "a declined prompt is not asked again either" begin
        asked = 0
        with_prompter(_ -> (asked += 1; nothing)) do
            @test ask_credential(token_request()) === nothing
            @test ask_credential(token_request()) === nothing
            @test asked == 1
        end
    end

    @testset "credentials asked for separately are remembered separately" begin
        with_prompter(r -> "answer-for-$(r.kind)") do
            @test ask_credential(token_request()) == "answer-for-token"
            req = CredentialRequest(:passphrase, "", 0; reason="k", secret=true)
            @test ask_credential(req; scope="/a.pem") == "answer-for-passphrase"
            forget_credential!(:passphrase, "/a.pem")
            @test ask_credential(req; scope="/b.pem") == "answer-for-passphrase"
        end
    end

    @testset "a rejected credential can be forgotten" begin
        answers = ["first", "second"]
        with_prompter(_ -> popfirst!(answers)) do
            @test ask_credential(token_request()) == "first"
            forget_credential!(:token)
            @test ask_credential(token_request()) == "second"
        end
    end

    @testset "a prompter that fails is not a connection failure" begin
        # A closed terminal or a secret manager that is down means "no
        # credential", which every caller already knows how to handle.
        with_prompter(_ -> error("no terminal")) do
            @test ask_credential(token_request()) === nothing
        end
        with_prompter(_ -> "") do
            @test ask_credential(token_request()) === nothing
        end
    end

    @testset "prompt_credentials! hands back what it replaced" begin
        p = r -> "x"
        previous = prompt_credentials!(p)
        try
            @test prompt_credentials!(previous) === p
        finally
            prompt_credentials!(previous)
        end
        @test tty_prompt === Session.tty_prompt   # the default is a plain function
    end

    @testset "only a handshake refused for want of a certificate is asked about" begin
        refused = TLSHandshakeFailed(
            "srv", 1094, false, ErrorException("handshake failure")
        )
        mktemp() do path, io
            write(io, "-----BEGIN CERTIFICATE-----\nx\n-----BEGIN PRIVATE KEY-----\ny\n")
            close(io)
            with_prompter(_ -> path) do
                @test prompt_client_cert(refused) == (cert=path, key=path)
            end
        end

        with_prompter(_ -> "/nowhere.pem") do
            # Not a TLS failure at all, and a failure we already answered with
            # a credential: neither is the user's to fix by typing a path.
            @test prompt_client_cert(ErrorException("connection refused")) === nothing
            @test prompt_client_cert(
                TLSHandshakeFailed("srv", 1094, true, ErrorException("handshake failure"))
            ) === nothing
            # A server we could not verify is the other side's problem; asking
            # for a client certificate here sends the user the wrong way.
            @test prompt_client_cert(
                TLSHandshakeFailed(
                    "srv", 1094, false, ErrorException("certificate verify failed")
                ),
            ) === nothing
            @test prompt_client_cert(
                TLSHandshakeFailed("srv", 1094, false, ErrorException("connection reset"))
            ) === nothing
        end

        with_prompter(_ -> nothing) do
            @test prompt_client_cert(refused) === nothing
        end
    end

    @testset "a certificate without its key is asked for separately" begin
        mktempdir() do dir
            cert = joinpath(dir, "cert.pem")
            key = joinpath(dir, "key.pem")
            write(cert, "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
            write(key, "-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----\n")
            @test !pem_has_key(cert)
            @test pem_has_key(key)
            @test !pem_has_key(joinpath(dir, "absent.pem"))

            err = TLSHandshakeFailed("srv", 1094, false, ErrorException("bad certificate"))
            with_prompter(r -> r.kind === :x509 ? cert : key) do
                @test prompt_client_cert(err) == (cert=cert, key=key)
            end
            with_prompter(r -> r.kind === :x509 ? cert : nothing) do
                @test prompt_client_cert(err) === nothing
            end
        end
    end

    @testset "a handshake failure says which side could not be verified" begin
        @test wants_client_cert(ErrorException("sslv3 alert handshake failure"))
        @test wants_client_cert(ErrorException("tlsv13 alert certificate required"))
        @test !wants_client_cert(ErrorException("connection reset by peer"))
        @test untrusted_server(ErrorException("certificate verify failed"))
        @test untrusted_server(ErrorException("self-signed certificate in chain"))
        @test !untrusted_server(ErrorException("alert handshake failure"))

        no_cert = sprint(
            showerror, TLSHandshakeFailed("srv", 1094, false, ErrorException("alert 40"))
        )
        @test occursin("TLS handshake with srv:1094 failed", no_cert)
        @test occursin("no X.509 client credential was presented", no_cert)
        @test occursin("voms-proxy-init", no_cert)

        bad_ca = sprint(
            showerror,
            TLSHandshakeFailed(
                "srv", 1094, false, ErrorException("certificate verify failed")
            ),
        )
        @test occursin("X509_CERT_DIR", bad_ca)
        @test !occursin("no X.509 client credential", bad_ca)

        with_cert = sprint(
            showerror, TLSHandshakeFailed("srv", 1094, true, ErrorException("alert 40"))
        )
        @test !occursin("no X.509 client credential", with_cert)
    end
end
