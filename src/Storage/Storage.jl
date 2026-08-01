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
using ..Session
using ..XrdCl

export storage_for,
    storage_stat,
    storage_read,
    storage_write,
    storage_list,
    storage_remove,
    storage_mkdir,
    storage_move,
    storage_copy,
    StorageInfo

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

"Transfer granularity, matching the copy engine's read size."
const IO_CHUNK = 1 << 20

"""
    fill_chunk!(source, buf, n) -> Int

Read at most `n` bytes into `buf`, returning how many; `0` is end of stream.

A `Base.BufferStream` is read through its own byte-level entry points rather
than `read(io, n)`. The generic `LibuvStream` bulk read locks a different lock
than `BufferStream`'s writer and, above the 64 KiB unbuffered threshold, swaps
the stream's buffer out from under it — with a producer still writing, that
silently loses and duplicates bytes (Julia 1.11). `unsafe_read` and `eof` take
the same lock the writer does.
"""
function fill_chunk!(source::IO, buf::Vector{UInt8}, n::Int)
    source isa Base.BufferStream || return readbytes!(source, buf, n)
    eof(source) && return 0
    k = min(n, bytesavailable(source))
    k == 0 && return 0
    GC.@preserve buf Base.unsafe_read(source, pointer(buf), UInt(k))
    return k
end

"""
    pump(source, sink, length=nothing) -> Int

Move `length` bytes (or everything up to end of stream) from `source` to
`sink` in [`IO_CHUNK`](@ref) steps, returning the byte count.

The chunking is load-bearing, not an optimisation: reading a
`Base.BufferStream` to end of stream parks until the writer closes it and
consumes *nothing* while it waits, so a backend that swallowed the copy
engine's pipe whole would deadlock against the producer's backlog throttle.
Bounded reads keep the pipe draining.
"""
function pump(source::IO, sink::IO, length=nothing)
    remaining = length === nothing ? typemax(Int) : Int(length)
    buf = Vector{UInt8}(undef, min(IO_CHUNK, remaining))
    total = 0
    while remaining > 0
        n = fill_chunk!(source, buf, min(IO_CHUNK, remaining))
        n == 0 && break
        GC.@preserve buf unsafe_write(sink, pointer(buf), UInt(n))
        total += n
        remaining -= n
    end
    return total
end

"""
    drain(source, length=nothing) -> Vector{UInt8}

[`pump`](@ref) into a byte vector, for the backends that must hand a whole
body to a single HTTP request.
"""
function drain(source::IO, length=nothing)
    buf = IOBuffer()
    pump(source, buf, length)
    return take!(buf)
end

include("url.jl")
include("local.jl")
include("xrootd.jl")
include("web.jl")
include("s3.jl")

"""
Options each backend understands. `storage_for` hands every backend only the
subset it accepts, so one bag of credentials can be applied to any URL — the
copy engine has one set of flags, not one per scheme.
"""
const _BACKEND_OPTS = (
    root=(:token, :keytab, :cert, :key, :cafile, :x509, :insecure_tls),
    web=(
        :headers,
        :token,
        :use_token,
        :allow_cleartext_token,
        :cert,
        :key,
        :cafile,
        :insecure_tls,
    ),
    s3=(:creds, :endpoint),
    file=(),
)

const _KNOWN_OPTS = Tuple(union(values(_BACKEND_OPTS)...))

"Keep the options `backend` accepts; reject a name no backend knows at all."
function backend_opts(opts::NamedTuple, backend::Symbol)
    allowed = _BACKEND_OPTS[backend]
    for k in keys(opts)
        k in _KNOWN_OPTS || throw(ArgumentError("unknown storage option $k"))
    end
    return NamedTuple{filter(k -> k in allowed, keys(opts))}(opts)
end

"""
    storage_for(url::AbstractString; kwargs...) -> Backend

Select and construct the backend for `url` by scheme: `root(s)://` →
XRootD, `http(s)://`/`dav(s)://` → HTTP/WebDAV, `s3(s)://` → S3, anything
else → local filesystem.

Credential keywords (`token`, `cert`/`key`, `keytab`, `insecure_tls`, …) are
filtered to what the selected backend supports; see [`_BACKEND_OPTS`](@ref).
"""
function storage_for(url::AbstractString; kwargs...)
    u = parse_url(url)
    opts = values(kwargs)
    if u.scheme in ("root", "roots")
        return XRootDBackend(u; backend_opts(opts, :root)...)
    elseif u.scheme in ("http", "https", "dav", "davs")
        return WebBackend(u; backend_opts(opts, :web)...)
    elseif u.scheme in ("s3", "s3s")
        return S3Backend(u; backend_opts(opts, :s3)...)
    else
        backend_opts(opts, :file)
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

"""
    storage_mkdir(backend) -> Symbol

Create the backend's path as a directory/collection, including parents where
the protocol has no other way to express them. `:ok` when the directory
exists afterwards, `:unsupported` for backends without a directory concept.
"""
function storage_mkdir end

"""
    storage_move(backend, dst_url; overwrite=false) -> Symbol

Rename the backend's object to `dst_url` within the same endpoint.
"""
function storage_move end

"""
    storage_copy(backend, dst_url; overwrite=false) -> Symbol

Copy the backend's object to `dst_url` *at the endpoint* — no bytes through
this client. Cross-endpoint copies are third-party copies
([`storage_tpc`](@ref)), not this.
"""
function storage_copy end

# S3 has no directories: a key prefix exists as soon as an object uses it.
storage_mkdir(::S3Backend) = :ok
storage_move(::S3Backend, ::AbstractString; overwrite::Bool=false) = :unsupported
storage_copy(::S3Backend, ::AbstractString; overwrite::Bool=false) = :unsupported

end # module Storage
