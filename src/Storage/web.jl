# HTTP / WebDAV backend on HTTP.jl. Read = GET (+ Range), write = PUT,
# stat = HEAD, list = WebDAV PROPFIND depth 1, mkdir = MKCOL, rename = MOVE,
# server-side and third-party copies = COPY. Bearer tokens and X.509 client
# certificates are the XrdHttp credentials.

"""
HTTP/WebDAV (`http(s)://`, `dav(s)://`) backend.

`token` is retained for third-party delegation, and is mutable because a
credential the endpoint asks for with a `401` arrives after the backend was
built ([`web_authorize!`](@ref)). `lasterror` holds why the last request never
came back, for a caller that has only a `:error` symbol to go on.
"""
mutable struct WebBackend <: Backend
    const url::StorageURL
    const headers::Vector{Pair{String,String}}
    const client::Union{HTTP.Client,Nothing}
    token::Union{String,Nothing}
    lasterror::Union{String,Nothing}
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
    return WebBackend(u, hdrs, client, jwt, nothing)
end

"""
Print the endpoint and whether a token is held — never the token, and never
`headers`, which is where the token ends up as an `Authorization` value.
"""
function Base.show(io::IO, b::WebBackend)
    print(io, "WebBackend(", repr(Session.redact_url(b.url.raw)))
    b.token === nothing || print(io, ", token=", Session.REDACTED)
    return print(io, ")")
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

A `401` is the HTTP way of saying what a `ztn` security trailer says on the
xroot side — this endpoint wants a credential — so it is the one status worth
asking the user about, and the request is then reissued with the answer.
"""
function web_request(
    b::WebBackend,
    method::AbstractString,
    headers::Vector{Pair{String,String}}=b.headers,
    body=UInt8[];
    url::AbstractString=http_url(b.url),
)
    resp = web_send(b, method, headers, body, url)
    (resp === nothing || resp.status != 401) && return resp
    added = web_authorize!(b)
    added === nothing && return resp
    # The backend's own header list has already been added to; a caller that
    # built its own (the WebDAV verbs do) needs the credential grafted on.
    retry = headers === b.headers ? headers : vcat(headers, added)
    return web_send(b, method, retry, body, url)
end

"""
Seconds one request may spend with nothing arriving before it is abandoned
(`\$XRDC_HTTP_IDLE_TIMEOUT_S`, `0` disables). A stalled HTTP transfer is
otherwise indistinguishable from a slow one and outlives any job: the
connection stays open, the read blocks, and no error is ever raised. Two
minutes of complete silence is a dead transfer by any storage-element
standard, and abandoning it is what lets the retry below happen at all.
"""
const DEFAULT_HTTP_IDLE_TIMEOUT_S = 120

function http_idle_timeout_s()
    return Session.env_number("XRDC_HTTP_IDLE_TIMEOUT_S", DEFAULT_HTTP_IDLE_TIMEOUT_S)
end

"""
Seconds one HTTP request may take from first byte sent to last byte received
(`\$XRDC_HTTP_REQUEST_TIMEOUT_S`, `0` disables); by default the request timeout
the rest of the client uses ([`XRootD.Session.max_wait_ms`](@ref),
`\$XRD_REQUESTTIMEOUT`).

An idle timeout alone does not bound a transfer. A slowloris endpoint — or a
middlebox re-buffering a stream it cannot keep up with — sends one byte just
often enough to reset the idle clock, and the request lives for as long as it
keeps that up: the connection is healthy, bytes are arriving, and nothing is
ever wrong enough to raise. The deadline is what turns that into a failure the
caller can retry elsewhere, and it is the HTTP twin of the xroot lane's stall
deadline ([`XRootD.Session.stall_deadline_default_ms`](@ref)).
"""
function http_request_timeout_s()
    return Session.env_number("XRDC_HTTP_REQUEST_TIMEOUT_S", Session.max_wait_ms() / 1000)
end

"""
WebDAV verbs that may be replayed. HTTP.jl's built-in policy knows the methods
RFC 9110 defines and retries those; `PROPFIND` and `MKCOL` are idempotent by
WebDAV's own definition and it has no way to know it.
"""
const WEBDAV_IDEMPOTENT = ("PROPFIND", "MKCOL")

"""
Verbs never replayed, whatever the built-in policy says. After one that
reached the server but whose answer did not reach us, the replay finds no
source and fails an operation that in fact succeeded — a deleted object
answers the second `DELETE` with `404`. Reporting a failure the caller can
check beats reporting one that is not true.

`DELETE` is on this list against HTTP.jl's own rules, which count it
idempotent: it is, in the sense that the resource ends up gone either way,
and not in the sense that matters here, which is what the caller is told.
"""
const NEVER_REPLAYED = ("DELETE", "MOVE", "COPY")

"Statuses worth another attempt: the server saying *later*, not *no*."
const HTTP_RETRY_STATUS = (408, 425, 429, 500, 502, 503, 504)

"""
Extend HTTP.jl's retry policy over the WebDAV verbs it does not know
([`WEBDAV_IDEMPOTENT`](@ref)) and withdraw it from the ones that must not be
repeated ([`NEVER_REPLAYED`](@ref)). `nothing` defers to the built-in rules,
which is the answer for every method the standard already covers.
"""
function web_retry_if(_attempt, _err, request, response)
    request.method in NEVER_REPLAYED && return false
    request.method in WEBDAV_IDEMPOTENT || return nothing
    response === nothing && return true             # transport failure
    return response.status in HTTP_RETRY_STATUS
end

"""
Issue one HTTP request, returning the response or `nothing` when the transport
failed.

The retry budget is the client's own ([`XRootD.Session.max_retries`](@ref)), so
one variable governs how hard this client leans on a struggling endpoint
whether it is talking xroot or HTTP. `Retry-After` on a `429`/`503` is
honoured — a server that says when to come back has told us something our own
backoff has not.
"""
function web_send(b::WebBackend, method, headers, body, url)
    client = b.client
    # Whatever went wrong last time did not go wrong this time: a stale reason
    # reported against a fresh failure is worse than no reason at all.
    b.lasterror = nothing
    opts = (;
        status_exception=false,
        retries=Session.max_retries(),
        retry_if=web_retry_if,
        respect_retry_after=true,
        connect_timeout=Session.connection_window_s(),
        read_idle_timeout=http_idle_timeout_s(),
        request_timeout=http_request_timeout_s(),
    )
    try
        if client === nothing
            return HTTP.request(method, url, headers, body; opts...)
        end
        return HTTP.request(method, url, headers, body; client, opts...)
    catch err
        # The transport reason is the one thing a caller staring at `:error`
        # actually needs, and the Storage API returns symbols. Keeping it on
        # the backend is what lets the copy engine name the failure.
        b.lasterror = sprint(showerror, err)
        return nothing
    end
end

"""
    web_authorize!(b) -> Union{Pair{String,String},Nothing}

Answer a `401` by asking for the bearer token the endpoint wants, and keep it
on `b` so every later request — and any third-party copy delegating from it —
carries it. Returns the header that was added, or `nothing` when there was
nothing to add.

Only over TLS, and only when no `Authorization` header was sent: a credential
typed into a cleartext connection is a credential given away, and a token the
endpoint has already refused is not worth asking for a second time.
"""
function web_authorize!(b::WebBackend)
    b.url.tls || return nothing
    any(p -> lowercase(p.first) == "authorization", b.headers) && return nothing
    jwt = Session.ask_credential(
        Session.CredentialRequest(
            :token,
            b.url.host,
            b.url.port;
            reason="$(b.url.scheme)://$(b.url.host):$(b.url.port) answered 401 and no bearer token was found",
            searched=vcat("\$BEARER_TOKEN", Session.token_file_candidates()),
        ),
    )
    jwt === nothing && return nothing
    added = "Authorization" => "Bearer $jwt"
    push!(b.headers, added)
    b.token = jwt
    return added
end

function storage_stat(b::WebBackend)
    resp = web_request(b, "HEAD")
    resp === nothing && return :error, nothing
    if resp.status != 200
        resp.status == 404 && return :notfound, nothing
        b.lasterror = "the endpoint answered HTTP $(resp.status)"
        return :error, nothing
    end
    size = parse_content_length(resp)
    mtime = parse_last_modified(resp)
    isdir = endswith(b.url.path, "/")
    return :ok, StorageInfo(size, mtime, isdir)
end

"""
Stream the object, or the requested range of it, into `sink`. A range the
endpoint declined to honour is cut out of the whole-object answer, and a body
shorter than the range asked for is reported as `:truncated` rather than
written off as the end of the object ([`ranged_body`](@ref)).
"""
function storage_read(b::WebBackend, sink::IO; offset::Integer=0, length=nothing)
    headers = copy(b.headers)
    if offset > 0 || length !== nothing
        last = length === nothing ? "" : string(offset + Int(length) - 1)
        push!(headers, "Range" => "bytes=$offset-$last")
    end
    resp = web_request(b, "GET", headers)
    resp === nothing && return :error
    (resp.status == 200 || resp.status == 206) || return :error
    code, bytes = ranged_body(resp.status, resp.body, offset, length)
    write(sink, bytes)
    return code
end

"""
Bytes an upload of unknown size may hold before it stops trying to find out
how big it is. Below this the object is buffered and sent as one framed `PUT`
— the request that every endpoint accepts and that this client can retry;
above it, holding the object is the thing to avoid, and the upload streams.
"""
const WEB_PUT_SPILL = 8 << 20

"""
    storage_write(b::WebBackend, source::IO; length=nothing)

Upload the bytes of `source` with a `PUT`.

An upload of known `length` streams straight from `source` to the socket under
a `Content-Length` of that many bytes — the object never exists in memory, and
the framing is the one XrdHttp and WebDAV endpoints all accept.
[`XRootD.Tools.copyfile`](@ref) knows the size of what it is copying and passes
it; a caller that knows should too.

Without a length there is nothing to declare, so up to [`WEB_PUT_SPILL`](@ref)
bytes are held to find out whether that is the whole object. It usually is, and
it is then sent as one ordinary `PUT`. Only a source that outruns the spill is
streamed with `Transfer-Encoding: chunked`, which some storage elements refuse
— the reason to pass `length` when it is known.

A streamed upload is read once and cannot be replayed, so neither the retry
policy nor the `401`-then-authorize handshake ([`web_authorize!`](@ref)) applies
to it: by the time the endpoint answers, the bytes are gone. A backend that will
need a credential should be given one before the upload, and one that answers
`401` here says so through `b.lasterror`.
"""
function storage_write(b::WebBackend, source::IO; length=nothing)
    if length !== nothing
        total = Int64(length)
        # Small enough to hold is small enough to retry, and a replayable
        # request is worth more than the memory it costs.
        total <= WEB_PUT_SPILL && return web_put_buffered(b, drain(source, total))
        return web_put_stream(b, source, UInt8[], total)
    end
    head = drain(source, WEB_PUT_SPILL)
    # A source that stopped at the spill boundary is a whole object that
    # happens to be exactly that big; `eof` is the only way to tell.
    (Base.length(head) < WEB_PUT_SPILL || eof(source)) && return web_put_buffered(b, head)
    return web_put_stream(b, source, head, Int64(-1))
end

"Upload a body this client is still holding: one `PUT`, retried like any other."
function web_put_buffered(b::WebBackend, body::Vector{UInt8})
    resp = web_request(b, "PUT", b.headers, body)
    resp === nothing && return :error
    return (200 <= resp.status < 300) ? :ok : :error
end

"""
The body of a streamed `PUT`: `head` (the bytes already read to decide how to
upload) and then the rest of `source`, pulled as the socket drains.

A callback rather than the source itself because HTTP.jl buffers an `IO` body
whole — the object would be back in memory, which is what this path exists to
avoid — and because a `Base.BufferStream`, which is what the copy engine feeds
this, must be read through [`fill_chunk!`](@ref) rather than `readbytes!`.
"""
mutable struct PutBody
    const head::Vector{UInt8}
    const source::IO
    at::Int
end

PutBody(head::Vector{UInt8}, source::IO) = PutBody(head, source, 1)

function (body::PutBody)(dst::Vector{UInt8})
    Base.length(dst) == 0 && return 0
    if body.at <= Base.length(body.head)
        n = min(Base.length(dst), Base.length(body.head) - body.at + 1)
        copyto!(dst, 1, body.head, body.at, n)
        body.at += n
        return n
    end
    return fill_chunk!(body.source, dst, Base.length(dst))
end

"""
The client a streamed `PUT` is issued on. `HTTP.do!` needs one, where
`HTTP.request` has a default of its own; backends with no TLS configuration
share this rather than opening a connection pool per upload.
"""
const _WEB_STREAM_CLIENT = Ref{Union{HTTP.Client,Nothing}}(nothing)

function web_stream_client(b::WebBackend)
    client = b.client
    client === nothing || return client
    return lock(_WEB_CLIENTS_LOCK) do
        cached = _WEB_STREAM_CLIENT[]
        cached === nothing || return cached
        fresh = HTTP.Client()
        _WEB_STREAM_CLIENT[] = fresh
        return fresh
    end
end

"""
    web_put_stream(b, source, head, total) -> Symbol

`PUT` the object by pulling it from `source` as the socket takes it, under a
`Content-Length` of `total` bytes — or chunked, when `total` is negative and
there is no length to declare.

`HTTP.do!` is the entry point rather than `HTTP.request` because it is the one
that carries a caller's `Content-Length` through to the wire: `request` frames a
streaming body as chunked and drops the header. It also takes no timeouts, so
the request deadline ([`http_request_timeout_s`](@ref)) is attached to the
request context instead — an upload with no deadline is one a stalled endpoint
can park forever.

A source that ends before `total` bytes have been sent fails the request rather
than storing a short object: the length was a promise made in the header, and
HTTP has no way to take it back. One that runs past `total` is cut off there,
which is the same promise seen from the other side.
"""
function web_put_stream(b::WebBackend, source::IO, head::Vector{UInt8}, total::Int64)
    b.lasterror = nothing
    u = b.url
    port = u.port
    address = "$(u.host):$port"
    target = isempty(u.path) ? "/" : u.path
    headers = copy(b.headers)
    ctx = HTTP.RequestContext()
    timeout = http_request_timeout_s()
    timeout > 0 && HTTP.set_deadline!(ctx, time_ns() + round(Int64, timeout * 1e9))
    body = PutBody(head, source)
    req = HTTP.Request(
        "PUT",
        target;
        headers=headers,
        body=HTTP.CallbackBody(body, () -> nothing),
        host=address,
        content_length=total,
        context=ctx,
    )
    resp = try
        HTTP.do!(web_stream_client(b), address, req; secure=u.tls)
    catch err
        b.lasterror = sprint(showerror, err)
        return :error
    end
    (200 <= resp.status < 300) && return :ok
    b.lasterror = if resp.status == 401
        "the endpoint asked for a credential ($(resp.status)) after the upload had " *
        "already been streamed; a streamed PUT cannot be replayed"
    else
        "streamed PUT rejected with HTTP $(resp.status)"
    end
    return :error
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
