"""
    XRootD.Storage

Layer 4 of the client: a backend-agnostic storage interface that dispatches
on URL scheme. `root(s)://` delegates to the XRootD [`XRootD.XrdCl`](@ref)
client, `http(s)://`/`dav(s)://` to an HTTP/WebDAV backend, `s3(s)://` to an
S3 backend, and a plain path to the local filesystem. This is the multi-
protocol substrate the copy engine and CLI tools build on.

Scheme table and backend semantics follow libxrdc `url.c` / `webfile.c` /
`s3.c`.
"""
module Storage

using HTTP: HTTP
using URIs: URIs, URI
using SHA: sha256, hmac_sha256, bytes2hex
using Dates: Dates
using ..XrdCl

export storage_for,
    storage_stat, storage_read, storage_write, storage_list, storage_remove, StorageInfo

"Backend-neutral metadata for a storage object."
struct StorageInfo
    size::Int64
    mtime::Int64
    isdir::Bool
end

"""
    Backend

Abstract supertype of storage backends. Concrete backends implement
[`storage_stat`](@ref), [`storage_read`](@ref), [`storage_write`](@ref),
[`storage_list`](@ref), and [`storage_remove`](@ref).
"""
abstract type Backend end

include("url.jl")
include("local.jl")
include("xrootd.jl")
include("web.jl")
include("s3.jl")

"""
    storage_for(url::AbstractString; kwargs...) -> Backend

Select and construct the backend for `url` by scheme: `root(s)://` →
XRootD, `http(s)://`/`dav(s)://` → HTTP/WebDAV, `s3(s)://` → S3, anything
else → local filesystem.
"""
function storage_for(url::AbstractString; kwargs...)
    u = parse_url(url)
    if u.scheme in ("root", "roots")
        return XRootDBackend(u; kwargs...)
    elseif u.scheme in ("http", "https", "dav", "davs")
        return WebBackend(u; kwargs...)
    elseif u.scheme in ("s3", "s3s")
        return S3Backend(u; kwargs...)
    else
        return LocalBackend(u)
    end
end

# ---- interface (each backend adds its own methods) ----

"""
    storage_stat(backend) -> (XRootDStatus-like, StorageInfo | nothing)

Metadata for the backend's object.
"""
function storage_stat end

"""
    storage_read(backend, sink::IO; offset=0, length=nothing)

Stream the object (from `offset`, at most `length` bytes) into `sink`.
"""
function storage_read end

"""
    storage_write(backend, source::IO; length=nothing)

Upload the bytes read from `source` to the backend's object.
"""
function storage_write end

"""
    storage_list(backend) -> Vector{Tuple{String,StorageInfo}}

List a container/directory: `(name, info)` per entry.
"""
function storage_list end

"""
    storage_remove(backend)

Delete the backend's object.
"""
function storage_remove end

end # module Storage
