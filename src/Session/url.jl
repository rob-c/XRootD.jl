# The `root://` URL grammar, in one place.
#
# `root://[user@]host[:port][//path]`, with `xroot://` as the documented alias
# and `roots://`/`xroots://` asking for TLS. The two parts that are easy to get
# wrong are the ones a regex over `[^/:@]+` silently mangles: the userinfo
# (which names the login account) and a bracketed IPv6 literal (whose colons
# are not the port separator). Both are what libxrdc `net/url.c` and
# `compat/host_split.c` take apart, and this is their translation.

"Default port for the `root://` schemes (libxrdc `BRIX_DEFAULT_PORT_LOCAL`)."
const DEFAULT_PORT = 1094

"A parsed `root://` URL."
struct RootURL
    "`root` or `roots`; the `xroot(s)://` aliases normalise onto these."
    scheme::String
    "The account named before `@`, or `\"\"` when the URL names none."
    username::String
    "The host, with the brackets of an IPv6 literal removed."
    host::String
    port::Int
    "The path, leading `//` collapsed to `/`; `\"\"` for an endpoint-only URL."
    path::String
    raw::String
end

const _ROOT_SCHEMES = Dict(
    "root" => "root", "xroot" => "root", "roots" => "roots", "xroots" => "roots"
)

"""
    parse_root_url(url::AbstractString) -> RootURL

Parse `root://[user@]host[:port][//path]`. Throws `ArgumentError` on a scheme
this client does not speak, a missing or malformed authority, or a port
outside 1–65535.

The XRootD convention doubles the slash between the authority and an absolute
path (`root://host//store/f` addresses `/store/f`), so a leading `//` in the
remainder collapses to one `/`; everything after that — including any `?cgi` —
is kept verbatim, because it is the server that splits the two apart.
"""
function parse_root_url(url::AbstractString)
    raw = String(url)
    m = match(r"^([A-Za-z]+)://(.*)$"s, raw)
    m === nothing && throw(ArgumentError("not a root:// URL: $(repr(raw))"))
    scheme = get(_ROOT_SCHEMES, lowercase(String(something(m.captures[1]))), nothing)
    scheme === nothing && throw(ArgumentError("not a root:// URL: $(repr(raw))"))

    rest = String(something(m.captures[2]))
    cut = findfirst('/', rest)
    authority = cut === nothing ? rest : rest[1:prevind(rest, cut)]
    rawpath = cut === nothing ? "" : rest[cut:end]

    at = findfirst('@', authority)
    username = at === nothing ? "" : authority[1:prevind(authority, at)]
    hostport = at === nothing ? authority : authority[nextind(authority, at):end]
    host, port = split_host_port(hostport, raw)

    path = startswith(rawpath, "//") ? rawpath[2:end] : rawpath
    return RootURL(scheme, username, host, port, path, raw)
end

"""
Split `host[:port]` or `[ipv6][:port]`, defaulting to [`DEFAULT_PORT`]. The
brackets around an IPv6 literal exist to tell its colons from the port
separator, and are not part of the host.
"""
function split_host_port(auth::AbstractString, url::AbstractString)
    bad(why) = throw(ArgumentError("$why in $(repr(String(url)))"))
    isempty(auth) && bad("no host")

    if startswith(auth, '[')
        rb = findfirst(']', auth)
        rb === nothing && bad("unterminated IPv6 literal")
        host = auth[2:prevind(auth, rb)]
        isempty(host) && bad("empty IPv6 literal")
        tail = auth[nextind(auth, rb):end]
        isempty(tail) && return host, DEFAULT_PORT
        startswith(tail, ':') || bad("junk after the IPv6 literal")
        return host, checked_port(tail[2:end], url)
    end

    # The *last* colon is the port separator: an unbracketed literal with more
    # than one colon is not addressable, and splitting on the first would take
    # a piece of it for the host.
    colon = findlast(':', auth)
    colon === nothing && return String(auth), DEFAULT_PORT
    host = auth[1:prevind(auth, colon)]
    isempty(host) && bad("no host")
    return host, checked_port(auth[nextind(auth, colon):end], url)
end

"""
    unbracket(host) -> String

Strip the brackets an IPv6 literal wears on the wire. A `kXR_redirect` names
its target host already bracketed (libxrdc `frame_roundtrip.c`), but the
resolver wants the address itself. Anything else is returned unchanged.
"""
function unbracket(host::AbstractString)
    (startswith(host, '[') && endswith(host, ']')) || return String(host)
    return String(host[nextind(host, firstindex(host)):prevind(host, lastindex(host))])
end

function checked_port(text::AbstractString, url::AbstractString)
    port = tryparse(Int, text)
    (port === nothing || port < 1 || port > 65535) &&
        throw(ArgumentError("invalid port $(repr(String(text))) in $(repr(String(url)))"))
    return port
end
