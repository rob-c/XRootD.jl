# Interactive credential prompting. A client that meets a server wanting a
# credential it cannot find has two honest options: fail with a message naming
# every place it looked, or ask. This does both — the message it would have
# printed becomes the prompt — but only when a human is on the other end of
# stdin. A batch job, a pipeline stage or a notebook cell must fail instead of
# blocking forever on a read that nobody will answer.

"""
    CredentialRequest(kind, host, port; reason, searched=String[], secret=false)

What the client is missing, and everything a prompter needs to ask for it.

`kind` is one of `:token` (a WLCG bearer token), `:x509` (a proxy or
certificate PEM), `:x509key` (its private key, when the certificate does not
carry one), `:passphrase` (for an encrypted key) or `:keytab` (an `sss`
keytab). `reason` says in one line why the credential is wanted, `searched`
lists the places already tried — so the user can make the answer permanent
rather than retyping it — and `secret` marks an answer that must not be
echoed.
"""
struct CredentialRequest
    kind::Symbol
    host::String
    port::Int
    reason::String
    searched::Vector{String}
    secret::Bool
end

function CredentialRequest(
    kind::Symbol,
    host::AbstractString,
    port::Integer;
    reason::AbstractString,
    searched::AbstractVector{<:AbstractString}=String[],
    secret::Bool=false,
)
    return CredentialRequest(
        kind, String(host), Int(port), String(reason), String.(searched), secret
    )
end

"The installed prompter; `nothing` means [`tty_prompt`](@ref)."
const _PROMPTER = Ref{Any}(nothing)

# One process asks once. A redirect chain re-authenticates at every hop, and a
# user who typed a token for the manager meant it for the data servers too.
# A declined prompt is remembered as an empty string, so "no, carry on
# without one" is also answered once rather than at every hop.
const _CRED_LOCK = ReentrantLock()
const _CRED_CACHE = Dict{Tuple{Symbol,String},String}()

"""
    prompt_credentials!(f) -> previous

Install `f` as the credential prompter, replacing the terminal one. `f` is
called as `f(req::CredentialRequest)` and returns the credential (a token, a
path, a passphrase) or `nothing` to proceed without one; anything it throws is
treated as `nothing`. This is how a GUI, a notebook, a secret manager or a
test supplies credentials that no terminal is there to type.

`prompt_credentials!(nothing)` restores [`tty_prompt`](@ref). Returns the
prompter that was installed before, so a caller can put it back.
"""
function prompt_credentials!(f)
    previous = _PROMPTER[]
    _PROMPTER[] = f
    return previous
end

"""
    ask_credential(req; scope="") -> Union{String,Nothing}

Ask for one credential, at most once per `(kind, scope)` per process (see
[`forget_credential!`](@ref)). Returns `nothing` when there is nobody to ask
or the answer was empty, in which case the caller must carry on without the
credential — or fail — exactly as it would have before.
"""
function ask_credential(req::CredentialRequest; scope::AbstractString="")
    key = (req.kind, String(scope))
    return lock(_CRED_LOCK) do
        if haskey(_CRED_CACHE, key)
            hit = _CRED_CACHE[key]
            return isempty(hit) ? nothing : hit
        end
        prompter = _PROMPTER[]
        answer = try
            (prompter === nothing ? tty_prompt : prompter)(req)
        catch err
            # A prompter that throws — a closed terminal, a secret manager that
            # is down — means "no credential", not "abort the connection".
            @debug "credential prompt failed" kind = req.kind exception = err
            nothing
        end
        given = answer === nothing ? "" : String(answer)
        _CRED_CACHE[key] = given
        return isempty(given) ? nothing : given
    end
end

"""
    forget_credential!(kind, scope="")

Forget one prompted credential so the next request asks again. Called when a
server rejects what was typed: a token the user pasted from a stale terminal
is worth asking about a second time, whereas one read from `\$BEARER_TOKEN` is
not (the environment is the user's to fix).
"""
function forget_credential!(kind::Symbol, scope::AbstractString="")
    lock(_CRED_LOCK) do
        return delete!(_CRED_CACHE, (kind, String(scope)))
    end
    return nothing
end

"Forget every prompted credential."
function forget_credentials!()
    lock(_CRED_LOCK) do
        return empty!(_CRED_CACHE)
    end
    return nothing
end

"""
    prompting_enabled() -> Bool

Whether the terminal prompter will ask. Both stdin and stderr must be a
terminal — stdin because the answer has to come from somewhere, stderr
because that is where the question goes (stdout belongs to the data a client
is piping) — and neither `XRDC_NO_PROMPT` nor `XRD_PROMPT=0` may have turned
it off, which is how a script that does run under a terminal opts out.
`XRD_PROMPT=1` is not an override: a terminal is where an answer can come
from, and a job that has none must fail rather than block whatever it was
told to try.
"""
function prompting_enabled()
    isempty(get(ENV, "XRDC_NO_PROMPT", "")) || return false
    env_flag("XRD_PROMPT", true) || return false
    return isa(stdin, Base.TTY) && isa(stderr, Base.TTY)
end

"""
    tty_prompt(req) -> Union{String,Nothing}

The default prompter: ask on the terminal when there is one, otherwise say
nothing is available. Installed unless [`prompt_credentials!`](@ref) has
replaced it.
"""
function tty_prompt(req::CredentialRequest)
    prompting_enabled() || return nothing
    return ask_on(stdin, stderr, req)
end

"What to type, per kind — the line under the reason that says how to answer."
function answer_hint(kind::Symbol)
    kind === :token && return "give a path to a token file, or paste the token itself"
    kind === :x509 && return "give a path to a proxy or certificate PEM"
    kind === :x509key && return "give a path to the matching private key PEM"
    kind === :keytab && return "give a path to an sss keytab"
    return ""
end

"The short label in front of the cursor."
function answer_label(req::CredentialRequest)
    req.kind === :token && return "token"
    req.kind === :x509 && return "certificate"
    req.kind === :x509key && return "private key"
    req.kind === :keytab && return "keytab"
    req.kind === :passphrase && return "passphrase"
    return String(req.kind)
end

"""
    ask_on(input, output, req; tries=3) -> Union{String,Nothing}

The prompt itself, on explicit streams. A path that does not exist is
reported and asked for again rather than accepted and failed later, up to
`tries` times; an empty answer means "carry on without one" and ends the
exchange immediately.
"""
function ask_on(input::IO, output::IO, req::CredentialRequest; tries::Int=3)
    println(output, "xrootd: ", req.reason)
    if !isempty(req.searched)
        println(output, "        looked in: ", join(req.searched, ", "))
    end
    hint = answer_hint(req.kind)
    isempty(hint) || println(output, "        ", hint)
    println(output, "        press Enter alone to continue without one")
    for attempt in 1:tries
        answer = read_answer(input, output, req)
        (answer === nothing || isempty(answer)) && return nothing
        resolved, problem = resolve_answer(answer, req)
        resolved === nothing || return resolved
        isempty(problem) && return nothing
        println(output, "xrootd: ", problem)
        attempt == tries && return nothing
    end
    return nothing
end

"""
Read one answer. A secret is read without echo when the terminal can do that;
on any other stream there is no echo to suppress, so a plain line is read —
which is also what makes this testable without a pseudo-terminal.
"""
function read_answer(input::IO, output::IO, req::CredentialRequest)
    label = answer_label(req)
    if req.secret && isa(input, Base.TTY) && input === stdin
        # `Base.getpass` caps input at 128 characters, which is ample for a
        # passphrase and far too short for a JWT — only :passphrase is secret.
        buf = Base.getpass(input, output, "        $label")
        answer = read(buf, String)
        Base.shred!(buf)
        println(output)
        return answer
    end
    print(output, "        $label: ")
    flush(output)
    return eof(input) ? nothing : readline(input)
end

"""
    resolve_answer(answer, req) -> (credential, problem)

Turn one typed answer into the credential itself: a passphrase is taken
verbatim, a path is expanded and checked, and a token may be either a file to
read or the token pasted in — told apart by whether the answer looks like a
path, so that a mistyped filename is reported rather than sent to the server
as a token. A `nothing` credential with a non-empty `problem` is worth asking
about again; with an empty one the user declined.
"""
function resolve_answer(answer::AbstractString, req::CredentialRequest)
    req.kind === :passphrase && return String(answer), ""
    text = String(strip(answer))
    isempty(text) && return nothing, ""
    path = expanduser(text)
    if req.kind === :token && !isfile(path)
        looks_like_path = occursin('/', text) || startswith(text, "~")
        looks_like_path && return nothing, "no such token file: $text"
        return text, ""                          # pasted rather than pointed at
    end
    isfile(path) || return nothing, "no such file: $text"
    req.kind === :token || return path, ""
    content = try
        String(strip(read(path, String)))
    catch err
        return nothing, "cannot read $text: $(sprint(showerror, err))"
    end
    return isempty(content) ? (nothing, "the token file $text is empty") : (content, "")
end
