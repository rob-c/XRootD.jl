# URL parsing for the storage layer. Scheme table and default ports mirror
# libxrdc url.c.

"A parsed storage URL."
struct StorageURL
    scheme::String
    host::String
    port::Int
    path::String
    tls::Bool
    raw::String
end

const _DEFAULT_PORTS = Dict(
    "root" => 1094,
    "roots" => 1094,
    "http" => 80,
    "https" => 443,
    "dav" => 80,
    "davs" => 443,
    "s3" => 80,
    "s3s" => 443,
)

const _TLS_SCHEMES = Set(["roots", "https", "davs", "s3s"])

"""
    parse_url(url::AbstractString) -> StorageURL

Parse a storage URL. A string with no recognized `scheme://` prefix is
treated as a local path (`scheme = "file"`). XRootD URLs keep their
double-slash path convention (`root://host//path` → `/path`).
"""
function parse_url(url::AbstractString)
    url = String(url)
    m = match(r"^([A-Za-z0-9]+)://([^/]*)(/.*)?$", url)
    if m === nothing
        return StorageURL("file", "", 0, String(url), false, String(url))
    end
    scheme = lowercase(String(something(m.captures[1])))
    authority = String(something(m.captures[2]))
    pathcap = m.captures[3]
    rawpath = pathcap === nothing ? "" : String(pathcap)

    host, port = split_authority(authority, get(_DEFAULT_PORTS, scheme, 0))
    # XRootD uses root://host//path; collapse the leading double slash.
    path = if scheme in ("root", "roots") && startswith(rawpath, "//")
        rawpath[2:end]
    else
        rawpath
    end
    return StorageURL(scheme, host, port, path, scheme in _TLS_SCHEMES, String(url))
end

function split_authority(authority::AbstractString, default_port::Int)
    isempty(authority) && return "", default_port
    # keep IPv6 literals ("[::1]:port") intact
    m = match(r"^(\[[^\]]+\]|[^:]+)(?::(\d+))?$", authority)
    m === nothing && return String(authority), default_port
    host = String(something(m.captures[1]))
    portcap = m.captures[2]
    port = portcap === nothing ? default_port : parse(Int, portcap)
    return host, port
end

"Reconstruct an `http(s)://host[:port]/path` URL for the HTTP backends."
function http_url(u::StorageURL)
    scheme = u.tls ? "https" : "http"
    portpart = u.port in (80, 443) ? "" : ":$(u.port)"
    return "$scheme://$(u.host)$portpart$(u.path)"
end
