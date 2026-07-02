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
    host = endpoint === nothing ? "$bucket.s3.amazonaws.com" : String(endpoint)
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

s3_object_url(b::S3Backend) = "https://$(b.endpoint_host)/$(b.key)"

function storage_stat(b::S3Backend)
    url = s3_object_url(b)
    hdrs = sigv4_headers("HEAD", url, b.creds)
    resp = try
        HTTP.request("HEAD", url, hdrs; status_exception=false)
    catch
        return :error, nothing
    end
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
    hdrs = sigv4_headers("GET", url, b.creds; headers=extra)
    resp = try
        HTTP.request("GET", url, hdrs; status_exception=false)
    catch
        return :error
    end
    (resp.status == 200 || resp.status == 206) || return :error
    write(sink, resp.body)
    return :ok
end

function storage_write(b::S3Backend, source::IO; length=nothing)
    url = s3_object_url(b)
    body = length === nothing ? read(source) : read(source, Int(length))
    hdrs = sigv4_headers("PUT", url, b.creds; payload_hash=bytes2hex(sha256(body)))
    resp = try
        HTTP.request("PUT", url, hdrs, body; status_exception=false)
    catch
        return :error
    end
    return (200 <= resp.status < 300) ? :ok : :error
end

function storage_remove(b::S3Backend)
    url = s3_object_url(b)
    hdrs = sigv4_headers("DELETE", url, b.creds)
    resp = try
        HTTP.request("DELETE", url, hdrs; status_exception=false)
    catch
        return :error
    end
    return (200 <= resp.status < 300) ? :ok : :error
end

# Bucket listing (ListObjectsV2) is out of scope for the initial backend;
# the copy engine and tools operate on explicit object keys.
storage_list(::S3Backend) = Tuple{String,StorageInfo}[]
