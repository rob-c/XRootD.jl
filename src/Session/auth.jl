# Authentication mechanisms. After kXR_login the server may return a
# security trailer ("&P=ztn,...&P=sss,...&P=unix"); `authenticate` parses the
# offered protocols and tries them best-first (ztn > sss > unix), sending the
# selected credential in one kXR_auth round. Ground truth: libxrdc
# sec/sec_{token,sss,unix}.c.

"""
Ordered list of protocol names in a `&P=<proto>[,args]` security trailer,
most-preferred first is NOT implied by wire order — we impose our own
preference in [`authenticate`](@ref).
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
    authenticate(sock, username, sec; token=nothing, keytab=nothing)

Complete authentication after login. Parses the server's security trailer
`sec` and tries the offered protocols best-first: `ztn` (when a token is
found), then `sss` (when a keytab key is found), then `unix`. Errors if no
offered mechanism can be satisfied.
"""
function authenticate(
    sock::IO,
    username::AbstractString,
    sec::String;
    token::Union{AbstractString,Nothing}=nothing,
    keytab::Union{AbstractString,Nothing}=nothing,
)
    offered = parse_sec_protocols(sec)
    isempty(offered) && return nothing   # trailer with no &P= — nothing to do

    if "ztn" in offered
        jwt = discover_token(; explicit=token)
        if jwt !== nothing
            # ztn payload repeats the tag: "ztn\0" then the JWT (sec_token.c).
            cred = vcat(Vector{UInt8}(codeunits("ztn\0")), Vector{UInt8}(codeunits(jwt)))
            return send_auth(sock, "ztn", cred)
        end
    end

    if "sss" in offered
        cred = sss_credential(; keytab)
        cred !== nothing && return send_auth(sock, "sss", cred)
    end

    if "unix" in offered
        cred = vcat(Vector{UInt8}(codeunits("unix\0")), Vector{UInt8}(codeunits(username)))
        return send_auth(sock, "unix", cred)
    end

    offered_list = join(offered, ", ")
    return error("no supported authentication mechanism offered (server: $offered_list)")
end

"Send one kXR_auth round and check the reply."
function send_auth(sock::IO, credtype::String, cred::Vector{UInt8})
    write(sock, Wire.encode(Wire.AuthRequest(credtype, cred), UInt16(3)))
    hdr, body = read_frame(sock)
    if hdr.status != Wire.kXR_ok
        msg = hdr.status == Wire.kXR_error ? Wire.decode_error(body).message : ""
        error("$credtype authentication failed (status $(hdr.status)): $msg")
    end
    return nothing
end
