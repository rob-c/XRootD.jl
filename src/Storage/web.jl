# HTTP / WebDAV backend on HTTP.jl. Read = GET (+ Range), write = PUT,
# stat = HEAD, list = WebDAV PROPFIND depth 1, mkdir = MKCOL, rename = MOVE,
# server-side and third-party copies = COPY. Bearer tokens and X.509 client
# certificates are the XrdHttp credentials.

"HTTP/WebDAV (`http(s)://`, `dav(s)://`) backend."
struct WebBackend <: Backend
    url::StorageURL
    headers::Vector{Pair{String,String}}
    client::Union{HTTP.Client,Nothing}
    token::Union{String,Nothing}   # retained for third-party delegation
end

"""
    WebBackend(u::StorageURL; headers=[], token=nothing, use_token=true,
               allow_cleartext_token=false, cert=nothing, key=nothing,
               cafile=nothing, insecure_tls=false)

Construct the backend for `u`. A bearer token (`token`, else whatever
[`XRootD.Session.discover_token`](@ref) finds) becomes an `Authorization:
Bearer` header — XrdHttp's, and WLCG's, token credential. `cert`/`key` add an
X.509 client certificate to the TLS handshake, `cafile` a CA bundle to trust,
and `insecure_tls` disables verification (self-signed test servers only).

A token is never sent over cleartext `http://`: a discovered one is dropped
with a warning, an explicitly passed one is an error, and
`allow_cleartext_token` overrides both for test endpoints.
"""
function WebBackend(
    u::StorageURL;
    headers=Pair{String,String}[],
    token::Union{AbstractString,Nothing}=nothing,
    use_token::Bool=true,
    allow_cleartext_token::Bool=false,
    cert::Union{AbstractString,Nothing}=nothing,
    key::Union{AbstractString,Nothing}=nothing,
    cafile::Union{AbstractString,Nothing}=nothing,
    insecure_tls::Bool=false,
)
    hdrs = collect(Pair{String,String}, headers)
    jwt = use_token ? Session.discover_token(; explicit=token) : nothing
    if jwt !== nothing && !u.tls && !allow_cleartext_token
        if token === nothing
            @warn "dropping the discovered bearer token: $(u.scheme):// is not encrypted" maxlog =
                1
            jwt = nothing
        else
            throw(
                ArgumentError(
                    "refusing to send a bearer token over cleartext $(u.scheme)://; " *
                    "use https:// or pass allow_cleartext_token=true",
                ),
            )
        end
    end
    jwt === nothing || push!(hdrs, "Authorization" => "Bearer $jwt")
    client = web_client(; cert, key, cafile, insecure_tls)
    return WebBackend(u, hdrs, client, jwt)
end

"""
Clients are cached by TLS configuration, not created per backend: an
`HTTP.Client` owns a connection pool, and a tree copy builds one backend per
object. `nothing` means "the default client" — no custom TLS at all.
"""
const _WEB_CLIENTS = Dict{NTuple{4,Any},HTTP.Client}()
const _WEB_CLIENTS_LOCK = ReentrantLock()

function web_client(;
    cert::Union{AbstractString,Nothing}=nothing,
    key::Union{AbstractString,Nothing}=nothing,
    cafile::Union{AbstractString,Nothing}=nothing,
    insecure_tls::Bool=false,
)
    if cert === nothing && cafile === nothing && !insecure_tls
        key === nothing ||
            throw(ArgumentError("an X.509 key needs its certificate: pass cert= as well"))
        return nothing
    end
    certfile = cert === nothing ? nothing : String(cert)
    keyfile = if certfile === nothing
        nothing
    else
        # A proxy holds the chain and the key in one PEM; HTTP.jl still wants
        # both file names, so the certificate doubles as the key file.
        key === nothing ? certfile : String(key)
    end
    ca = cafile === nothing ? nothing : String(cafile)
    entry = (certfile, keyfile, ca, insecure_tls)
    return lock(_WEB_CLIENTS_LOCK) do
        return get!(_WEB_CLIENTS, entry) do
            cfg = HTTP.TLS.Config(;
                verify_peer=(!insecure_tls),
                verify_hostname=(!insecure_tls),
                ca_file=ca,
                cert_file=certfile,
                key_file=keyfile,
                # HTTP.jl's TLS 1.3 client lane never answers a
                # CertificateRequest, so a client certificate is only actually
                # presented over TLS 1.2. Pinning the ceiling is what makes
                # X.509 authentication work at all here.
                max_version=(certfile === nothing ? nothing : HTTP.TLS.TLS1_2_VERSION),
            )
            return HTTP.Client(; transport=HTTP.Transport(; tls_config=cfg))
        end
    end
end

"""
Issue one request against `b`, returning the response or `nothing` when the
transport failed. `url` defaults to the backend's own object, so the WebDAV
verbs that address a different resource can override it.
"""
function web_request(
    b::WebBackend,
    method::AbstractString,
    headers::Vector{Pair{String,String}}=b.headers,
    body=UInt8[];
    url::AbstractString=http_url(b.url),
)
    client = b.client
    try
        if client === nothing
            return HTTP.request(method, url, headers, body; status_exception=false)
        end
        return HTTP.request(method, url, headers, body; client, status_exception=false)
    catch
        return nothing
    end
end

function storage_stat(b::WebBackend)
    resp = web_request(b, "HEAD")
    resp === nothing && return :error, nothing
    resp.status == 200 || return (resp.status == 404 ? :notfound : :error), nothing
    size = parse_content_length(resp)
    mtime = parse_last_modified(resp)
    isdir = endswith(b.url.path, "/")
    return :ok, StorageInfo(size, mtime, isdir)
end

function storage_read(b::WebBackend, sink::IO; offset::Integer=0, length=nothing)
    headers = copy(b.headers)
    if offset > 0 || length !== nothing
        last = length === nothing ? "" : string(offset + Int(length) - 1)
        push!(headers, "Range" => "bytes=$offset-$last")
    end
    resp = web_request(b, "GET", headers)
    resp === nothing && return :error
    (resp.status == 200 || resp.status == 206) || return :error
    write(sink, resp.body)
    return :ok
end

"""
Upload with a single `PUT`, which holds the object in memory — one request
carries one body, and chunked upload is not something every XrdHttp/WebDAV
endpoint accepts. The source is still read in bounded steps so that a copy
feeding this from a pipe keeps draining it.
"""
function storage_write(b::WebBackend, source::IO; length=nothing)
    body = drain(source, length)
    resp = web_request(b, "PUT", b.headers, body)
    resp === nothing && return :error
    return (200 <= resp.status < 300) ? :ok : :error
end

function storage_list(b::WebBackend)
    headers = vcat(b.headers, ["Depth" => "1", "Content-Type" => "application/xml"])
    body = """<?xml version="1.0"?><propfind xmlns="DAV:"><prop>
             <getcontentlength/><getlastmodified/><resourcetype/></prop></propfind>"""
    resp = web_request(b, "PROPFIND", headers, body)
    resp === nothing && return Tuple{String,StorageInfo}[]
    resp.status == 207 || return Tuple{String,StorageInfo}[]
    return parse_propfind(String(resp.body), b.url.path)
end

function storage_remove(b::WebBackend)
    resp = web_request(b, "DELETE")
    resp === nothing && return :error
    return (200 <= resp.status < 300) ? :ok : :error
end

"""
Create the collection with `MKCOL`. `405 Method Not Allowed` is the WebDAV
answer for "already a collection here", which is success for a caller that
only wants the directory to exist.
"""
function storage_mkdir(b::WebBackend)
    resp = web_request(b, "MKCOL", b.headers; url=collection_url(b.url))
    resp === nothing && return :error
    (200 <= resp.status < 300) && return :ok
    resp.status == 405 && return :ok
    return :error
end

"""
    storage_move(b::WebBackend, dst_url; overwrite=false)

Rename/move within the same server (`MOVE`).
"""
function storage_move(b::WebBackend, dst_url::AbstractString; overwrite::Bool=false)
    return dav_transfer(b, "MOVE", dst_url, overwrite)
end

"""
    storage_copy(b::WebBackend, dst_url; overwrite=false)

Server-side copy within the same server (`COPY`). A copy *between* servers is
a third-party copy — see [`storage_tpc`](@ref).
"""
function storage_copy(b::WebBackend, dst_url::AbstractString; overwrite::Bool=false)
    return dav_transfer(b, "COPY", dst_url, overwrite)
end

function dav_transfer(
    b::WebBackend, method::String, dst_url::AbstractString, overwrite::Bool
)
    headers = vcat(
        b.headers,
        ["Destination" => dav_destination(dst_url), "Overwrite" => (overwrite ? "T" : "F")],
    )
    resp = web_request(b, method, headers)
    resp === nothing && return :error
    return (200 <= resp.status < 300) ? :ok : :error
end

"The `Destination:` header wants an absolute URL, in HTTP scheme terms."
dav_destination(url::AbstractString) = http_url(parse_url(url))

"MKCOL addresses a collection, which is spelled with a trailing slash."
function collection_url(u::StorageURL)
    url = http_url(u)
    return endswith(url, "/") ? url : url * "/"
end

"""
    storage_tpc(dst::WebBackend, src::WebBackend; overwrite=false,
                mode=:pull) -> (Symbol, String)

Third-party copy: ask one endpoint to transfer the object directly to/from the
other, so the bytes never pass through this client. `:pull` sends `COPY` with a
`Source:` header to the destination (the WLCG default); `:push` sends `COPY`
with a `Destination:` header to the source. The far end's bearer token travels
in `TransferHeaderAuthorization`, which the active endpoint replays as its own
`Authorization` header (WLCG HTTP-TPC).

Returns `(:ok, message)` or `(:error, message)`. The transfer is only
successful when the body's final marker says so: HTTP-TPC servers answer 200
as soon as the transfer *starts*, and report the outcome in the (chunked)
body.
"""
function storage_tpc(
    dst::WebBackend, src::WebBackend; overwrite::Bool=false, mode::Symbol=:pull
)
    mode in (:pull, :push) || throw(ArgumentError("tpc mode must be :pull or :push"))
    active, passive = mode === :pull ? (dst, src) : (src, dst)
    direction = mode === :pull ? "Source" : "Destination"
    headers = vcat(
        active.headers,
        [
            direction => http_url(passive.url),
            "Overwrite" => (overwrite ? "T" : "F"),
            "RequireChecksumVerification" => "false",
        ],
    )
    remote = passive.token
    if remote === nothing
        push!(headers, "Credential" => "none")
    else
        push!(headers, "TransferHeaderAuthorization" => "Bearer $remote")
    end
    resp = web_request(active, "COPY", headers)
    resp === nothing && return :error, "third-party COPY failed at the transport layer"
    if !(200 <= resp.status < 300)
        return :error, "third-party COPY rejected with HTTP $(resp.status)"
    end
    return tpc_outcome(String(resp.body))
end

"""
Interpret an HTTP-TPC response body. The body is a stream of performance
markers terminated by `success: ...` or `failure: ...`; a server that sends no
markers at all has nothing to report but its 2xx.
"""
function tpc_outcome(body::AbstractString)
    failure = nothing
    success = nothing
    for line in eachsplit(body, '\n')
        s = strip(line)
        if startswith(s, "failure:")
            failure = strip(s[9:end])
        elseif startswith(s, "success:")
            success = strip(s[9:end])
        end
    end
    failure === nothing || return :error, "third-party copy failed: $failure"
    success === nothing && return :ok, "third-party copy accepted (no completion marker)"
    return :ok, "third-party copy: $success"
end

# ---- header / XML helpers ----

function parse_content_length(resp)
    for (k, v) in resp.headers
        lowercase(k) == "content-length" && return something(tryparse(Int64, v), Int64(0))
    end
    return Int64(0)
end

function parse_last_modified(resp)
    for (k, v) in resp.headers
        if lowercase(k) == "last-modified"
            dt = tryparse(Dates.DateTime, v, Dates.dateformat"e, d u Y H:M:S \G\M\T")
            dt === nothing && return Int64(0)
            return Int64(round(Dates.datetime2unix(dt)))
        end
    end
    return Int64(0)
end

"""
Parse a WebDAV `multistatus` body into `(name, StorageInfo)` entries.
Deliberately minimal (regex over `<response>` blocks) — enough for a
directory listing without pulling in a full XML dependency.
"""
function parse_propfind(xml::AbstractString, base_path::AbstractString)
    out = Tuple{String,StorageInfo}[]
    for resp in eachmatch(r"<(?:\w+:)?response\b.*?</(?:\w+:)?response>"s, xml)
        block = resp.match
        href_m = match(r"<(?:\w+:)?href>\s*([^<]+?)\s*</(?:\w+:)?href>", block)
        href_m === nothing && continue
        href = URIs.unescapeuri(strip(String(something(href_m.captures[1]))))
        name = rstrip(basename(rstrip(href, '/')), '/')
        isempty(name) && continue
        # Depth: 1 answers with the collection itself first; it is not one of
        # its own children.
        endswith(rstrip(href, '/'), rstrip(base_path, '/')) && continue
        len_m = match(r"<(?:\w+:)?getcontentlength>\s*(\d+)", block)
        size = len_m === nothing ? Int64(0) : parse(Int64, something(len_m.captures[1]))
        isdir = occursin(r"<(?:\w+:)?collection\b", block)
        push!(out, (String(name), StorageInfo(size, Int64(0), isdir)))
    end
    return out
end
