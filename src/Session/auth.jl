# Authentication mechanisms. After kXR_login the server may return a
# security trailer ("&P=ztn,...&P=sss,...&P=unix"); `authenticate` parses the
# offered protocols and tries them in the server's order (filtered to what
# this client speaks; $XrdSecPROTOCOL overrides), sending the selected
# credential in one kXR_auth round. Ground truth: libxrdc
# sec/sec_{token,sss,unix}.c.

"""
Ordered list of protocol names in a `&P=<proto>[,args]` security trailer.
Wire order IS the server's preference order — the trailer is built from its
`sec.protocol` directives first to last — and [`authenticate`](@ref) honours
it unless the caller (or `\$XrdSecPROTOCOL`) imposes their own.
"""
function parse_sec_protocols(sec::AbstractString)
    protos = String[]
    for m in eachmatch(r"&P=([^,&]+)", sec)
        push!(protos, String(something(m.captures[1])))
    end
    return protos
end

"""
    discover_token(; explicit=nothing) -> Union{String,Nothing}

Locate a WLCG bearer token, in libxrdc's order: the `explicit` argument,
`\$BEARER_TOKEN`, `\$BEARER_TOKEN_FILE`, `\$XDG_RUNTIME_DIR/bt_u<uid>`, then
`/tmp/bt_u<uid>`. Returns the trimmed token, or `nothing`.
"""
function discover_token(; explicit::Union{AbstractString,Nothing}=nothing)
    explicit !== nothing && return String(strip(explicit))
    tok = get(ENV, "BEARER_TOKEN", "")
    isempty(tok) || return strip(tok)
    for path in token_file_candidates()
        if isfile(path)
            content = strip(read(path, String))
            isempty(content) || return content
        end
    end
    return nothing
end

function token_file_candidates()
    paths = String[]
    f = get(ENV, "BEARER_TOKEN_FILE", "")
    isempty(f) || push!(paths, f)
    uid = ccall(:getuid, Cuint, ())
    rt = get(ENV, "XDG_RUNTIME_DIR", "")
    isempty(rt) || push!(paths, joinpath(rt, "bt_u$(uid)"))
    push!(paths, "/tmp/bt_u$(uid)")
    return paths
end

"""
    authenticate(sock, username, sec; token=nothing, keytab=nothing,
                 host="", port=0, order=env_auth_order(),
                 timeout_s=connection_window_s())
        -> Union{NamedTuple,Nothing}

Complete authentication after login. Parses the server's security trailer
`sec` and tries the offered mechanisms in the *server's* order, filtered to
the ones this client implements (`ztn`, `sss`, `unix`): the server listed
them in the order its authorization actually honours them. An explicit
`order` — or `\$XrdSecPROTOCOL` ([`env_auth_order`](@ref)) — takes over both
the order and the restriction: a mechanism it leaves out is not tried even
when the server offers it. Errors if nothing offered can be satisfied.

Returns `(; mech, key)` naming the mechanism that won and the session key it
established — the raw sss key bytes, the material request signing encrypts
with — or `nothing` for the mechanisms (`ztn`, `unix`) that leave no key
behind, and for a trailer that asked for nothing.

A bearer token is a reusable secret, so `ztn` is only tried when the
connection is encrypted: volunteering it over cleartext hands it to every
middlebox on the path. `XRDC_ZTN_CLEARTEXT=1` overrides, for a test bench
that is its own network.

A credential the server asks for and discovery cannot find is asked for
([`ask_credential`](@ref)) at the point where its absence is about to cost
something — for `ztn`, when the alternative is falling back to an anonymous
`unix` login that an authorizing server will refuse operation by operation;
for `sss`, when there is no fallback at all. `host`/`port` name the endpoint
in the prompt.

`timeout_s` bounds each `kXR_auth` exchange with the server
([`guard_bringup`](@ref)). It covers only the exchange: a prompt waits on a
person, who is entitled to take longer than a connection window to find their
token.
"""
function authenticate(
    sock::IO,
    username::AbstractString,
    sec::String;
    token::Union{AbstractString,Nothing}=nothing,
    keytab::Union{AbstractString,Nothing}=nothing,
    host::AbstractString="",
    port::Integer=0,
    order::Union{AbstractVector{<:AbstractString},Nothing}=env_auth_order(),
    timeout_s::Real=connection_window_s(),
)
    offered = parse_sec_protocols(sec)
    isempty(offered) && return nothing   # trailer with no &P= — nothing to do

    # Which mechanisms may be tried, in whose order. With no order imposed the
    # server's stands, filtered to what this client speaks; an imposed order
    # replaces it outright. A mechanism ruled out here is invisible to
    # everything below, including the prompts: asking for a keytab that
    # `$XrdSecPROTOCOL` has already excluded would be asking for something we
    # would not send.
    usable = if order === nothing
        [String(m) for m in offered if m in DEFAULT_AUTH_ORDER]
    else
        [String(m) for m in order if m in offered]
    end
    isempty(usable) && return error(mechanism_error(offered, order))

    sss = "sss" in usable ? sss_material(; keytab) : nothing
    ztn_allowed = sock isa OpenSSL.SSLStream || env_flag("XRDC_ZTN_CLEARTEXT")
    ztn_blocked = false

    for mech in usable
        if mech == "ztn"
            if !ztn_allowed
                # Skipped, not failed: the next mechanism may well work, and
                # the prompt is skipped too — asking a person for a token this
                # connection would refuse to send helps nobody.
                ztn_blocked = true
                continue
            end
            jwt = discover_token(; explicit=token)
            prompted = false
            if jwt === nothing && token === nothing && sss === nothing
                jwt = prompt_token(host, port)
                prompted = jwt !== nothing
            end
            jwt === nothing && continue
            # ztn payload repeats the tag: "ztn\0" then the JWT (sec_token.c).
            cred = vcat(Vector{UInt8}(codeunits("ztn\0")), Vector{UInt8}(codeunits(jwt)))
            try
                send_auth(sock, "ztn", cred; host, port, timeout_s)
                return (; mech="ztn", key=nothing)
            catch
                # A token that was typed and then rejected is most likely stale
                # or mispasted, so it is forgotten and the next connection asks
                # again; one read from the environment is the user's to fix.
                prompted && forget_credential!(:token)
                rethrow()
            end
        elseif mech == "sss"
            if sss === nothing && keytab === nothing && !("unix" in usable)
                sss = prompt_keytab(host, port)
            end
            sss === nothing && continue
            send_auth(sock, "sss", sss.cred; host, port, timeout_s)
            return (; mech="sss", key=sss.key.key)
        elseif mech == "unix"
            cred = vcat(
                Vector{UInt8}(codeunits("unix\0")), Vector{UInt8}(codeunits(username))
            )
            send_auth(sock, "unix", cred; host, port, timeout_s)
            return (; mech="unix", key=nothing)
        end
        # Anything else is a mechanism this client does not implement (`gsi`,
        # `krb5`): it stays in the list so the error can name it, but there is
        # nothing to send for it.
    end

    return error(mechanism_error(offered, order; ztn_blocked))
end

"""
Why authentication got nowhere. The server's list is always named; the
client's is named too when it was narrowed, because `\$XrdSecPROTOCOL`
excluding the one mechanism both sides had looks exactly like a server that
offered nothing usable. Mechanisms the server offered that this client does
not implement are called out — `gsi` looks supported until someone says it
is not — and so is a token withheld for want of encryption, which otherwise
looks exactly like having no token.
"""
function mechanism_error(offered, order; ztn_blocked::Bool=false)
    msg = "no supported authentication mechanism offered (server: $(join(offered, ", ")))"
    if order !== nothing && Set(order) != Set(DEFAULT_AUTH_ORDER)
        msg *= " (client: $(join(order, ", ")))"
    end
    missing_mechs = unique([String(m) for m in offered if !(m in DEFAULT_AUTH_ORDER)])
    if !isempty(missing_mechs)
        verb = length(missing_mechs) == 1 ? "is" : "are"
        msg *= "; $(join(missing_mechs, ", ")) $verb not implemented by this client"
    end
    if ztn_blocked
        msg *=
            "; a ztn bearer token is only sent over TLS — reconnect with " *
            "roots:// (or set XRDC_ZTN_CLEARTEXT=1 to send it in the clear)"
    end
    return msg
end

"Ask for the bearer token the server wants, naming everywhere we looked for one."
function prompt_token(host::AbstractString, port::Integer)
    return ask_credential(
        CredentialRequest(
            :token,
            host,
            port;
            reason="$(endpoint_name(host, port)) asks for a bearer token (ztn) and none was found",
            searched=vcat("\$BEARER_TOKEN", token_file_candidates()),
        ),
    )
end

"Ask for an sss keytab, and turn the answer into credential material."
function prompt_keytab(host::AbstractString, port::Integer)
    answer = ask_credential(
        CredentialRequest(
            :keytab,
            host,
            port;
            reason="$(endpoint_name(host, port)) offers only sss and no keytab key was found",
            searched=[default_keytab_path()],
        ),
    )
    answer === nothing && return nothing
    return sss_material(; keytab=answer)
end

"How an endpoint is named in a prompt: `root://host:port`, or just `the server`."
function endpoint_name(host::AbstractString, port::Integer)
    isempty(host) && return "the server"
    return "root://$host:$port"
end

"""
Send one kXR_auth round and check the reply, under the same watchdog as the
rest of bring-up: a server that goes quiet once it has the credential is no
more answerable than one that went quiet before it asked for it.
"""
function send_auth(
    sock::IO,
    credtype::String,
    cred::Vector{UInt8};
    host::AbstractString="",
    port::Integer=0,
    timeout_s::Real=connection_window_s(),
)
    return guard_bringup(sock, host, port, timeout_s, "the $credtype auth reply") do
        write(sock, Wire.encode(Wire.AuthRequest(credtype, cred), UInt16(3)))
        hdr, body = read_frame(sock)
        if hdr.status != Wire.kXR_ok
            msg = hdr.status == Wire.kXR_error ? Wire.decode_error(body).message : ""
            error("$credtype authentication failed (status $(hdr.status)): $msg")
        end
        return nothing
    end
end
