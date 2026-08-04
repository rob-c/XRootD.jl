# S3 backend with AWS Signature Version 4. GET/PUT/HEAD an object; list a
# bucket prefix. Signer follows the AWS "Signature Version 4" spec and is
# validated against the documented example vectors.

"S3 credentials (from the environment by default)."
struct S3Credentials
    access_key::String
    secret_key::String
    session_token::String
    region::String
end

function S3Credentials(;
    access_key::AbstractString=get(ENV, "AWS_ACCESS_KEY_ID", ""),
    secret_key::AbstractString=get(ENV, "AWS_SECRET_ACCESS_KEY", ""),
    session_token::AbstractString=get(ENV, "AWS_SESSION_TOKEN", ""),
    region::AbstractString=get(ENV, "AWS_DEFAULT_REGION", "us-east-1"),
)
    return S3Credentials(access_key, secret_key, session_token, region)
end

"""
The access key identifies, the secret key authenticates; only the first is
printed. A signing key derived from a printed secret is the whole account, and
credentials reach a terminal most often through a struct someone displayed
while working out why a request was refused.
"""
function Base.show(io::IO, c::S3Credentials)
    print(io, "S3Credentials(", repr(c.access_key), ", ", Session.REDACTED)
    isempty(c.session_token) || print(io, ", session_token=", Session.REDACTED)
    return print(io, ", region=", repr(c.region), ")")
end

"S3 (`s3(s)://bucket/key`) backend."
struct S3Backend <: Backend
    url::StorageURL
    bucket::String
    key::String
    creds::S3Credentials
    endpoint_host::String
end

function S3Backend(u::StorageURL; creds::S3Credentials=S3Credentials(), endpoint=nothing)
    # s3://bucket/key — the host is the bucket, the path is the key.
    bucket = u.host
    key = lstrip(u.path, '/')
    host = endpoint === nothing ? default_s3_host(bucket) : rstrip(String(endpoint), '/')
    return S3Backend(u, bucket, String(key), creds, host)
end

# ---- SigV4 ----

_hmac(key, msg) = hmac_sha256(key, Vector{UInt8}(codeunits(msg)))

"Derive the SigV4 signing key for `date`/`region`/`service`."
function signing_key(secret::AbstractString, date::AbstractString, region, service)
    kDate = _hmac(Vector{UInt8}(codeunits("AWS4" * secret)), date)
    kRegion = _hmac(kDate, region)
    kService = _hmac(kRegion, service)
    return _hmac(kService, "aws4_request")
end

"""
    sigv4_headers(method, url, creds; payload_hash="UNSIGNED-PAYLOAD",
                  headers=[], now=Dates.now(UTC)) -> Vector{Pair}

Build the `Authorization`, `x-amz-date`, and `x-amz-content-sha256` headers
for an S3 request signed with AWS Signature Version 4 (service `s3`).
"""
function sigv4_headers(
    method::AbstractString,
    url::AbstractString,
    creds::S3Credentials;
    payload_hash::AbstractString="UNSIGNED-PAYLOAD",
    headers::Vector{Pair{String,String}}=Pair{String,String}[],
    now::Dates.DateTime=Dates.now(Dates.UTC),
    service::AbstractString="s3",
)
    uri = URI(url)
    amzdate = Dates.format(now, Dates.dateformat"yyyymmdd\THHMMSS\Z")
    datestamp = amzdate[1:8]
    host = uri.port == "" ? uri.host : "$(uri.host):$(uri.port)"

    signed = Dict{String,String}(
        "host" => host, "x-amz-content-sha256" => payload_hash, "x-amz-date" => amzdate
    )
    isempty(creds.session_token) || (signed["x-amz-security-token"] = creds.session_token)
    for (k, v) in headers
        signed[lowercase(k)] = String(v)
    end

    names = sort(collect(keys(signed)))
    canonical_headers = join(("$n:$(signed[n])\n" for n in names))
    signed_headers = join(names, ";")
    canonical_path = isempty(uri.path) ? "/" : String(uri.path)
    canonical_query = String(uri.query)   # assumed already canonical (sorted) by callers

    canonical_request =
        uppercase(method) *
        "\n" *
        canonical_path *
        "\n" *
        canonical_query *
        "\n" *
        canonical_headers *
        "\n" *
        signed_headers *
        "\n" *
        payload_hash

    scope = "$datestamp/$(creds.region)/$service/aws4_request"
    creq_hash = bytes2hex(sha256(Vector{UInt8}(codeunits(canonical_request))))
    string_to_sign = "AWS4-HMAC-SHA256\n" * amzdate * "\n" * scope * "\n" * creq_hash
    key = signing_key(creds.secret_key, datestamp, creds.region, service)
    signature = bytes2hex(_hmac(key, string_to_sign))

    auth =
        "AWS4-HMAC-SHA256 Credential=$(creds.access_key)/$scope, " *
        "SignedHeaders=$signed_headers, Signature=$signature"

    out = [
        "Authorization" => auth,
        "x-amz-date" => amzdate,
        "x-amz-content-sha256" => payload_hash,
    ]
    isempty(creds.session_token) ||
        push!(out, "x-amz-security-token" => creds.session_token)
    return out
end

"""
The bucket's URL. AWS is reached over HTTPS, but an `endpoint` may name its
own scheme: the S3-compatible services (MinIO, Ceph RGW) are routinely served
as plain HTTP inside a private network.
"""
function s3_bucket_url(b::S3Backend)
    occursin("://", b.endpoint_host) && return b.endpoint_host
    return "https://$(b.endpoint_host)"
end

"The object's URL."
s3_object_url(b::S3Backend) = "$(s3_bucket_url(b))/$(b.key)"

"The host AWS serves `bucket` on when no endpoint was given."
default_s3_host(bucket::AbstractString) = "$bucket.s3.amazonaws.com"

"The payload hash of a request with no body, which SigV4 still signs."
const EMPTY_SHA256 = bytes2hex(sha256(UInt8[]))

"""
Issue one signed request, returning the response or `nothing` when the
transport failed — a copy halfway through a tree should see an error code, not
an exception from the socket layer.

Bounded exactly as the WebDAV lane is ([`web_send`](@ref)): an object store
reached over the same wide-area network stalls in the same ways, and a request
with no deadline on it is one a bad path can park forever.
"""
function s3_request(method::AbstractString, url::AbstractString, headers, body=UInt8[])
    try
        return HTTP.request(
            method,
            url,
            headers,
            body;
            status_exception=false,
            connect_timeout=Session.connection_window_s(),
            read_idle_timeout=http_idle_timeout_s(),
            request_timeout=http_request_timeout_s(),
        )
    catch
        return nothing
    end
end

function storage_stat(b::S3Backend)
    url = s3_object_url(b)
    resp = s3_request("HEAD", url, sigv4_headers("HEAD", url, b.creds))
    resp === nothing && return :error, nothing
    resp.status == 200 || return (resp.status == 404 ? :notfound : :error), nothing
    return :ok, StorageInfo(parse_content_length(resp), parse_last_modified(resp), false)
end

function storage_read(b::S3Backend, sink::IO; offset::Integer=0, length=nothing)
    url = s3_object_url(b)
    extra = Pair{String,String}[]
    if offset > 0 || length !== nothing
        last = length === nothing ? "" : string(offset + Int(length) - 1)
        push!(extra, "range" => "bytes=$offset-$last")
    end
    # The signature covers `extra`, so `extra` has to travel with it: a
    # request whose SignedHeaders names a header it does not carry is rejected
    # as a signature mismatch (and, before that, would fetch the whole object).
    hdrs = vcat(extra, sigv4_headers("GET", url, b.creds; headers=extra))
    resp = s3_request("GET", url, hdrs)
    resp === nothing && return :error
    (resp.status == 200 || resp.status == 206) || return :error
    # An endpoint that ignored `range` sent the whole object, and one whose
    # connection died mid-body sent a prefix; neither is the range asked for.
    code, bytes = ranged_body(resp.status, resp.body, offset, length)
    write(sink, bytes)
    return code
end

"""
Bytes per part in a multipart upload of an object whose size is not known in
advance, and the size past which such an upload stops being a single `PUT`.
"""
const S3_PART_SIZE = 64 * 1024 * 1024

"Smallest part S3 accepts anywhere but at the end of an upload."
const S3_MIN_PART_SIZE = 5 * 1024 * 1024

"Parts S3 accepts in one multipart upload."
const S3_MAX_PARTS = 10_000

"""
Parts to aim for when the size is known. Each one is a signed request, and
each one is held in memory while it is signed, so the two costs pull in
opposite directions; a thousand is the middle of them.
"""
const S3_TARGET_PARTS = 1_000

"""
    s3_part_size(total) -> Int

Bytes per part for an upload of `total` bytes (`nothing` when the size is not
known in advance).

A fixed part size is either too big or too small, and which one depends on the
object: [`S3_PART_SIZE`](@ref) holds 64 MiB in memory to upload a 100 MiB file,
and caps an upload at 640 GB — S3 takes at most [`S3_MAX_PARTS`](@ref) parts,
so the part size *is* the ceiling. Sizing it to the object costs neither:
[`S3_TARGET_PARTS`](@ref) parts of the object, floored at S3's own minimum,
capped at the default, and raised past that cap only when nothing smaller could
carry the object at all — which is what puts a 5 TB upload, S3's own limit,
within reach.
"""
function s3_part_size(total)
    total === nothing && return S3_PART_SIZE
    n = Int64(total)
    n <= 0 && return S3_PART_SIZE
    want = clamp(cld(n, S3_TARGET_PARTS), Int64(S3_MIN_PART_SIZE), Int64(S3_PART_SIZE))
    return Int(max(want, cld(n, S3_MAX_PARTS)))
end

"""
    storage_write(b::S3Backend, source::IO; length=nothing, part_size=nothing)

Upload the bytes of `source` to the object.

SigV4 signs a hash of the payload, so a request cannot start before its last
byte has arrived — an upload is therefore held in memory, and the memory is
bounded by uploading in parts. Up to one part it is a single `PUT`; past that
the parts go up under one multipart upload, which is also the only way to
exceed S3's 5 GB single-`PUT` limit. A part that fails aborts the upload rather
than leaving its fragments to be paid for.

`part_size` defaults to what the object needs ([`s3_part_size`](@ref)), which
is why passing `length` is worth doing: it is what decides both how much of the
upload is resident and how large an object can be sent at all.
"""
function storage_write(
    b::S3Backend, source::IO; length=nothing, part_size::Union{Integer,Nothing}=nothing
)
    part = part_size === nothing ? s3_part_size(length) : Int(part_size)
    part > 0 || throw(ArgumentError("an S3 part must hold at least one byte"))
    left = length === nothing ? nothing : Int(length)
    head = drain(source, left === nothing ? part : min(left, part))
    left === nothing || (left -= Base.length(head))
    # Only an object that does not fit in one part pays for a multipart upload.
    fits = Base.length(head) < part || (left !== nothing && left <= 0) || eof(source)
    fits && return s3_put(b, head)
    return s3_multipart_write(b, head, source, left, part)
end

"Upload `body` as the whole object."
function s3_put(b::S3Backend, body::Vector{UInt8})
    url = s3_object_url(b)
    hdrs = sigv4_headers("PUT", url, b.creds; payload_hash=bytes2hex(sha256(body)))
    resp = s3_request("PUT", url, hdrs, body)
    resp === nothing && return :error
    return (200 <= resp.status < 300) ? :ok : :error
end

function s3_multipart_write(
    b::S3Backend, head::Vector{UInt8}, source::IO, left, part_size::Int
)
    upload = s3_multipart_begin(b)
    upload === nothing && return :error
    etags = String[]
    chunk = head
    while true
        tag = s3_upload_part(b, upload, length(etags) + 1, chunk)
        if tag === nothing
            s3_multipart_abort(b, upload)
            return :error
        end
        push!(etags, tag)
        left !== nothing && left <= 0 && break
        chunk = drain(source, left === nothing ? part_size : min(left, part_size))
        isempty(chunk) && break
        left === nothing || (left -= length(chunk))
    end
    return s3_multipart_finish(b, upload, etags)
end

"Open a multipart upload, returning its id."
function s3_multipart_begin(b::S3Backend)
    url = s3_object_url(b) * "?uploads="
    hdrs = sigv4_headers("POST", url, b.creds; payload_hash=EMPTY_SHA256)
    resp = s3_request("POST", url, hdrs, UInt8[])
    (resp === nothing || resp.status != 200) && return nothing
    id = xml_text(String(resp.body), "UploadId")
    return (id === nothing || isempty(id)) ? nothing : id
end

"Upload one part, returning the ETag the completion has to quote back."
function s3_upload_part(
    b::S3Backend, upload::AbstractString, number::Int, body::Vector{UInt8}
)
    url = s3_object_url(b) * "?partNumber=$number&uploadId=$(URIs.escapeuri(upload))"
    hdrs = sigv4_headers("PUT", url, b.creds; payload_hash=bytes2hex(sha256(body)))
    resp = s3_request("PUT", url, hdrs, body)
    (resp === nothing || resp.status != 200) && return nothing
    for (k, v) in resp.headers
        lowercase(k) == "etag" && return strip(String(v), '"')
    end
    return nothing
end

"""
Assemble the parts. S3 answers a completion with `200` and *then* reports a
failure in the body, because the request is held open while the assembly runs;
a client that stopped at the status would call a failed upload successful.
"""
function s3_multipart_finish(b::S3Backend, upload::AbstractString, etags::Vector{String})
    body = IOBuffer()
    print(body, "<CompleteMultipartUpload>")
    for (i, tag) in enumerate(etags)
        print(
            body, "<Part><PartNumber>", i, "</PartNumber><ETag>\"", tag, "\"</ETag></Part>"
        )
    end
    print(body, "</CompleteMultipartUpload>")
    payload = take!(body)
    url = s3_object_url(b) * "?uploadId=$(URIs.escapeuri(upload))"
    hdrs = sigv4_headers("POST", url, b.creds; payload_hash=bytes2hex(sha256(payload)))
    resp = s3_request("POST", url, hdrs, payload)
    if resp === nothing || resp.status != 200 || occursin("<Error", String(resp.body))
        s3_multipart_abort(b, upload)
        return :error
    end
    return :ok
end

"""
Abandon a multipart upload. The parts already stored are billed until this
runs, so it runs on every path out of a failed upload — and its own failure is
not worth reporting over the failure that caused it.
"""
function s3_multipart_abort(b::S3Backend, upload::AbstractString)
    url = s3_object_url(b) * "?uploadId=$(URIs.escapeuri(upload))"
    s3_request("DELETE", url, sigv4_headers("DELETE", url, b.creds), UInt8[])
    return nothing
end

function storage_remove(b::S3Backend)
    url = s3_object_url(b)
    resp = s3_request("DELETE", url, sigv4_headers("DELETE", url, b.creds))
    resp === nothing && return :error
    return (200 <= resp.status < 300) ? :ok : :error
end

"""
List one level of the key prefix (`ListObjectsV2` with `/` as the delimiter),
so `s3://bucket/data` answers with what a filesystem would call the contents
of `data/`: the objects directly under it, and the prefixes below it as
directories. The listing is paged — a bucket answers at most 1000 keys per
request — and follows its own continuation token to the end.

An object whose key *is* the prefix is a directory marker, not an entry of
itself, and is left out.
"""
function storage_list(b::S3Backend)
    out = Tuple{String,StorageInfo}[]
    prefix = s3_list_prefix(b.key)
    token = ""
    while true
        url = s3_bucket_url(b) * "/?" * s3_list_query(prefix, token)
        resp = s3_request("GET", url, sigv4_headers("GET", url, b.creds))
        (resp === nothing || resp.status != 200) && return out
        xml = String(resp.body)
        append!(out, parse_list_objects(xml, prefix))
        xml_text(xml, "IsTruncated") == "true" || return out
        token = something(xml_text(xml, "NextContinuationToken"), "")
        isempty(token) && return out
    end
end

"A key addresses one object; as a listing prefix it addresses everything below it."
function s3_list_prefix(key::AbstractString)
    (isempty(key) || endswith(key, "/")) && return String(key)
    return key * "/"
end

"""
The query string of one `ListObjectsV2` page, in the order SigV4 signs it:
parameters sorted by name, values percent-encoded. The signature is computed
over exactly these bytes, so they are built once and used for both.
"""
function s3_list_query(prefix::AbstractString, token::AbstractString)
    parts = ["delimiter=%2F", "list-type=2"]
    isempty(token) || pushfirst!(parts, "continuation-token=$(URIs.escapeuri(token))")
    isempty(prefix) || push!(parts, "prefix=$(URIs.escapeuri(prefix))")
    return join(parts, "&")
end

"""
    storage_copy(b::S3Backend, dst_url; overwrite=false)

Copy the object to `dst_url` at the same endpoint (`x-amz-copy-source`), with
no bytes through this client.
"""
function storage_copy(b::S3Backend, dst_url::AbstractString; overwrite::Bool=false)
    dst = s3_destination(b, dst_url)
    dst === nothing && return :unsupported
    if !overwrite
        # S3 has no conditional PUT that every implementation honours, so
        # "don't overwrite" is a look before the leap. A destination whose
        # state cannot be established is not one to write over blind.
        code, _ = storage_stat(dst)
        code == :notfound || return :error
    end
    source = "/$(b.bucket)/$(b.key)"
    extra = ["x-amz-copy-source" => URIs.escapepath(source)]
    url = s3_object_url(dst)
    hdrs = vcat(extra, sigv4_headers("PUT", url, dst.creds; headers=extra))
    resp = s3_request("PUT", url, hdrs)
    resp === nothing && return :error
    (200 <= resp.status < 300) || return :error
    # A copy is answered as soon as it starts and reports its outcome in the
    # body, the same way a multipart completion does.
    return occursin("<Error", String(resp.body)) ? :error : :ok
end

"""
    storage_move(b::S3Backend, dst_url; overwrite=false)

Move the object to `dst_url`. S3 has no rename: this is a server-side copy
followed by a delete of the original, and the original survives a copy that
fails.
"""
function storage_move(b::S3Backend, dst_url::AbstractString; overwrite::Bool=false)
    code = storage_copy(b, dst_url; overwrite=overwrite)
    code === :ok || return code
    return storage_remove(b)
end

"""
The backend `dst_url` names at *this* endpoint, sharing its credentials, or
`nothing` when it names something the endpoint cannot reach. AWS serves every
bucket on its own host, so any bucket is addressable; an explicit endpoint was
configured for one bucket and cannot speak for another.
"""
function s3_destination(b::S3Backend, dst_url::AbstractString)
    u = parse_url(dst_url)
    u.scheme in ("s3", "s3s") || return nothing
    b.endpoint_host == default_s3_host(b.bucket) && return S3Backend(u; creds=b.creds)
    u.host == b.bucket || return nothing
    return S3Backend(u; creds=b.creds, endpoint=b.endpoint_host)
end

# ---- S3 XML ----

"Text of the first `<tag>` element of an S3 response, or `nothing`."
function xml_text(xml::AbstractString, tag::AbstractString)
    m = match(Regex("<$tag>\\s*(.*?)\\s*</$tag>", "s"), xml)
    return m === nothing ? nothing : String(something(m.captures[1]))
end

"""
Parse a `ListObjectsV2` page into `(name, StorageInfo)` entries relative to
`prefix`: `<Contents>` are objects, `<CommonPrefixes>` are the directories the
delimiter collapsed.
"""
function parse_list_objects(xml::AbstractString, prefix::AbstractString)
    out = Tuple{String,StorageInfo}[]
    for m in eachmatch(r"<Contents>.*?</Contents>"s, xml)
        block = m.match
        key = xml_text(block, "Key")
        key === nothing && continue
        name = s3_entry_name(key, prefix)
        isempty(name) && continue
        size = something(tryparse(Int64, something(xml_text(block, "Size"), "")), Int64(0))
        mtime = s3_timestamp(xml_text(block, "LastModified"))
        push!(out, (name, StorageInfo(size, mtime, false)))
    end
    for m in eachmatch(r"<CommonPrefixes>.*?</CommonPrefixes>"s, xml)
        p = xml_text(m.match, "Prefix")
        p === nothing && continue
        name = s3_entry_name(rstrip(p, '/'), prefix)
        isempty(name) && continue
        push!(out, (name, StorageInfo(Int64(0), Int64(0), true)))
    end
    return out
end

"The part of `key` below `prefix` — the leaf name, the delimiter having cut the rest."
function s3_entry_name(key::AbstractString, prefix::AbstractString)
    startswith(key, prefix) || return ""
    return String(SubString(key, ncodeunits(prefix) + 1))
end

"An S3 timestamp (ISO 8601, UTC, milliseconds optional) as a Unix time."
function s3_timestamp(s::Union{AbstractString,Nothing})
    s === nothing && return Int64(0)
    for fmt in
        (Dates.dateformat"yyyy-mm-ddTHH:MM:SS.sssZ", Dates.dateformat"yyyy-mm-ddTHH:MM:SSZ")
        dt = tryparse(Dates.DateTime, String(s), fmt)
        dt === nothing || return Int64(round(Dates.datetime2unix(dt)))
    end
    return Int64(0)
end
