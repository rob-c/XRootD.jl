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
    storage_open,
    storage_list,
    storage_remove,
    storage_mkdir,
    storage_move,
    storage_copy,
    StorageInfo,
    StorageError

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

"Default transfer granularity, matching the copy engine's read size."
const IO_CHUNK = 1 << 20

"""
    io_chunk() -> Int

Bytes moved per read or write: `\$XRD_CPCHUNKSIZE` when a site has tuned it,
[`IO_CHUNK`](@ref) otherwise. A value of zero — or one that does not parse —
is not honoured, because a chunk of no bytes is a loop that never advances.
"""
function io_chunk()
    n = Session.env_int("XRD_CPCHUNKSIZE", IO_CHUNK)
    return n > 0 ? n : IO_CHUNK
end

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
`sink` in [`io_chunk`](@ref) steps, returning the byte count.

The chunking is load-bearing, not an optimisation: reading a
`Base.BufferStream` to end of stream parks until the writer closes it and
consumes *nothing* while it waits, so a backend that swallowed the copy
engine's pipe whole would deadlock against the producer's backlog throttle.
Bounded reads keep the pipe draining.
"""
function pump(source::IO, sink::IO, length=nothing)
    remaining = length === nothing ? typemax(Int) : Int(length)
    chunk = io_chunk()
    buf = Vector{UInt8}(undef, min(chunk, remaining))
    total = 0
    while remaining > 0
        n = fill_chunk!(source, buf, min(chunk, remaining))
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

"""
Bytes of backlog a producer may leave in a pipe before it is held back. A
`Base.BufferStream` has no bound of its own, so a producer faster than its
consumer — which, against a network, is every producer — turns the pipe into a
copy of the object in memory. This is what that costs instead.
"""
const STREAM_HIGH_WATER = 8 << 20

"""
    backpressure!(pipe, high_water=STREAM_HIGH_WATER; consumer=nothing)

Hold the caller back while `pipe` holds more than `high_water` bytes nobody has
read yet.

`consumer`, when given, is the task draining the pipe: a consumer that has
stopped is never going to catch up, and waiting for it to would be a deadlock
rather than a delay.
"""
function backpressure!(
    pipe::IO, high_water::Integer=STREAM_HIGH_WATER; consumer::Union{Task,Nothing}=nothing
)
    pipe isa Base.BufferStream || return nothing
    while isopen(pipe) && bytesavailable(pipe) > high_water
        consumer !== nothing && istaskdone(consumer) && break
        sleep(0.001)
    end
    return nothing
end

"""
    ranged_body(status, body, offset, length) -> (Symbol, AbstractVector{UInt8})

The bytes a ranged `GET` actually asked for, and whether they all arrived:
`:ok` with exactly the requested range, or `:truncated` with the short prefix
that did.

Two things stand between a `Range:` header and the bytes a caller wanted, and
neither announces itself:

  - An endpoint that does not implement ranges answers `200` with the *whole*
    object. Handing that back is not a partial success, it is the wrong bytes
    at the wrong offset, so the requested window is cut out of it here.
  - A body shorter than the range is a transfer that stopped rather than an
    object that ended — over a network that drops connections, the single
    most likely way to end up with a silently short file.

An over-long body is clipped to what was asked for; a server that answers
generously is not a reason to write bytes the caller has no room for.
"""
function ranged_body(status::Integer, body::AbstractVector{UInt8}, offset::Integer, length)
    bytes = if status == 200 && offset > 0
        # Range ignored: the object arrived from byte zero.
        start = Int(offset) + 1
        if start > Base.length(body)
            view(body, 1:0)
        else
            view(body, start:Base.length(body))
        end
    else
        view(body, 1:Base.length(body))
    end
    length === nothing && return :ok, bytes
    want = Int(length)
    Base.length(bytes) < want && return :truncated, bytes
    return :ok, view(bytes, 1:want)
end

include("url.jl")
# Ahead of the backends: each one adds its own handle to the stream layer's
# interface, and a subtype needs its supertype to already exist.
include("stream.jl")
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
XRootD, `http(s)://`/`dav(s)://` → HTTP/WebDAV, `s3(s)://` → S3, a string with
no `scheme://` at all → local filesystem.

A scheme this client does not speak raises `ArgumentError` rather than falling
back to the local filesystem: `rooot://host//data` is a typo, and answering it
by looking for a local directory of that name turns one mistake into a
puzzling one.

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
    elseif u.scheme == "file"
        backend_opts(opts, :file)
        return LocalBackend(u)
    else
        throw(
            ArgumentError(
                "$(u.scheme):// is not a scheme this client speaks (in $(repr(url))); " *
                "use root://, roots://, http://, https://, dav://, davs://, s3://, " *
                "s3s://, or a plain local path",
            ),
        )
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

end # module Storage
