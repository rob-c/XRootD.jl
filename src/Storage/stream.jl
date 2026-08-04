# A Julia `IO` over a storage object, so a remote file is read and written with
# the same vocabulary as a local one: `read(io, n)`, `write(io, data)`, `seek`,
# `position`, `eof`, `readline`, `readbytes!`.
#
# The whole-object entry points ([`storage_read`](@ref) / [`storage_write`](@ref))
# move bytes between a backend and an `IO` the caller already has. A stream is
# the other direction — the caller drives, and the backend is the thing being
# read from or written to — which is what the standard library's `IO` generics,
# and every package that takes an `IO`, expect to be handed.

"""
    StorageError(url, op, detail)

A stream operation that failed. The `IO` interface has no way to return a
status: `read` answers with bytes and `write` with a byte count, so a backend
failure has to be raised.

This is the one place in the Storage layer that throws rather than returning a
symbol. The backend-level functions keep their `Symbol` contract — a copy that
walks a tree wants a code it can carry — and the stream layer converts, because
a caller writing `read(io, UInt64)` has nowhere to put a code.
"""
struct StorageError <: Exception
    url::String
    op::String
    detail::String
end

function Base.showerror(io::IO, e::StorageError)
    print(io, "StorageError: ", e.op, " failed on ", Session.redact_url(e.url))
    isempty(e.detail) || print(io, ": ", e.detail)
    return nothing
end

"The URL a backend addresses, for the error messages a stream raises."
backend_url(b::Backend) = b.url.raw

# ---- handles: the per-backend state an open stream holds ----

"""
    StreamHandle

The open resource behind a [`StorageReader`](@ref) or [`StorageWriter`](@ref) —
a `File` on the xroot lane, an `IOStream` locally, an in-flight upload over
HTTP. Implementations provide [`stream_read!`](@ref), [`stream_write`](@ref),
[`stream_close`](@ref), [`stream_size`](@ref) and [`stream_seekable`](@ref).

A handle exists because a stream is not a sequence of whole-object transfers: it
is one open thing that many reads and writes address. On the backends that hold
a connection open that is the point — a 1 GB file read in 1 MiB steps opens the
file once, not a thousand times.
"""
abstract type StreamHandle end

"""
    stream_read!(h, buf, offset, n) -> Int

Read `n` bytes of the object at `offset` into the start of `buf`, returning how
many arrived. Fewer than `n` means the object ended there.
"""
function stream_read! end

"""
    stream_write(h, data, n, offset)

Write the first `n` bytes of `data` at `offset`. Raises [`StorageError`](@ref).
"""
function stream_write end

"Release the handle: `:ok` when everything it still owed has landed."
function stream_close end

"Bytes the object holds, or `-1` when the backend will not say."
function stream_size end

"Whether the handle addresses arbitrary offsets, or only the next one."
stream_seekable(::StreamHandle) = false

# ---- generic handles, built on the whole-object interface ----

"""
Read handle for a backend with no persistent connection to keep: every refill is
one ranged `GET`, which is what the HTTP and S3 lanes do anyway.

`size` may be `-1`. An endpoint that answers a `HEAD` without a
`Content-Length` has not said the object is empty, it has said nothing, and a
stream that took that for an empty object would hand back no bytes and call it
success. The object is then walked until a range comes back short — the cost
being that a connection dropped on the last chunk is indistinguishable from the
end of the object, which is what not knowing the size means.
"""
struct RangeReader{B<:Backend} <: StreamHandle
    backend::B
    url::String
    size::Int64
end

stream_size(h::RangeReader) = h.size
stream_seekable(::RangeReader) = true

function stream_read!(h::RangeReader, buf::Vector{UInt8}, offset::Int64, n::Int)
    known = h.size >= 0
    known && (n = min(n, Int(max(0, h.size - offset))))
    n == 0 && return 0
    sink = IOBuffer(buf; write=true, truncate=true, maxsize=n)
    code = try
        storage_read(h.backend, sink; offset=offset, length=n)
    catch err
        throw(StorageError(h.url, "read", sprint(showerror, err)))
    end
    # With a known size the window was clipped to what the object holds, so a
    # short answer is a transfer that stopped rather than an object that ended.
    # Without one, a short answer is the only end-of-object signal there is.
    if code != :ok && !(code == :truncated && !known)
        throw(StorageError(h.url, "read", "$n bytes at $offset: $code"))
    end
    return Int(position(sink))
end

stream_close(::RangeReader) = :ok

"""
Write handle for a backend whose upload is one request: the bytes are handed to
[`storage_write`](@ref) through a pipe that the upload drains as the caller
fills it, so neither end holds the object.

The alternative — collect the writes and upload on `close` — would make the
memory cost of a stream the size of the file, which is the thing this layer
exists to avoid. `total` is passed through because a destination that knows the
length can frame the upload with it (`Content-Length` over HTTP, part sizing on
S3) instead of falling back to a form that not every endpoint accepts.
"""
mutable struct PipeWriter{B<:Backend} <: StreamHandle
    const backend::B
    const url::String
    const pipe::Base.BufferStream
    const task::Task
    pos::Int64
end

function PipeWriter(b::Backend, url::AbstractString, total::Union{Integer,Nothing})
    pipe = Base.BufferStream()
    task = Threads.@spawn begin
        try
            storage_write(b, pipe; length=total)
        catch
            :error
        finally
            # A destination that stopped early must not leave the writer parked
            # against a pipe nobody reads; closing it turns the next write into
            # a failure the caller sees.
            close(pipe)
        end
    end
    return PipeWriter(b, String(url), pipe, task, Int64(0))
end

stream_size(::PipeWriter) = Int64(-1)

function stream_write(h::PipeWriter, data::Vector{UInt8}, n::Int, offset::Int64)
    offset == h.pos || throw(
        StorageError(
            h.url, "write", "this backend uploads in one pass: cannot write at $offset"
        ),
    )
    istaskdone(h.task) &&
        throw(StorageError(h.url, "write", "the upload ended before the data did"))
    GC.@preserve data unsafe_write(h.pipe, pointer(data), UInt(n))
    h.pos += n
    backpressure!(h.pipe; consumer=h.task)
    return nothing
end

function stream_close(h::PipeWriter)
    close(h.pipe)
    return fetch(h.task)::Symbol
end

# ---- opening a handle ----

"""
    open_read_handle(b::Backend) -> StreamHandle

The read handle for `b`. The default serves refills as ranged reads of the whole
object; a backend that can hold its file open overrides it.
"""
function open_read_handle(b::Backend)
    url = backend_url(b)
    code, info = try
        storage_stat(b)
    catch err
        throw(StorageError(url, "open", sprint(showerror, err)))
    end
    (code == :ok && info !== nothing) || throw(StorageError(url, "open", "stat: $code"))
    info.isdir && throw(StorageError(url, "open", "is a directory"))
    # Zero is what a backend reports both for an empty object and for one whose
    # size it was never told; the reader treats it as the second and finds out.
    return RangeReader(b, url, info.size > 0 ? Int64(info.size) : Int64(-1))
end

"""
    open_write_handle(b::Backend, total) -> StreamHandle

The write handle for `b`, for an object of `total` bytes (`nothing` when the
caller will not say).
"""
open_write_handle(b::Backend, total) = PipeWriter(b, backend_url(b), total)

# ---- the streams ----

"""
    StorageReader <: IO

A readable stream over a storage object: buffered, seekable, and driven by the
standard `IO` generics (`read`, `readbytes!`, `readline`, `eof`, `seek`,
`position`). Build one with [`storage_open`](@ref).

Bytes are fetched [`io_chunk`](@ref) at a time however small the caller's reads
are, because the cost that matters is the round trip, not the copy.
"""
mutable struct StorageReader{H<:StreamHandle} <: IO
    const handle::H
    const url::String
    const size::Int64
    pos::Int64
    const buf::Vector{UInt8}
    bufstart::Int64
    buflen::Int
    isopen::Bool
end

function StorageReader(h::StreamHandle, url::AbstractString)
    return StorageReader(
        h, String(url), stream_size(h), Int64(0), Vector{UInt8}(undef, io_chunk()), Int64(0),
        0, true,
    )
end

"""
    StorageWriter <: IO

A writable stream over a storage object: buffered, and driven by the standard
`IO` generics (`write`, `print`, `flush`, `position`). Build one with
[`storage_open`](@ref).

Writes are staged until [`io_chunk`](@ref) bytes are due, so a caller that
writes a line at a time still sends the object in whole chunks. `close` is where
an upload is finished, and where its failure is raised — a stream that swallowed
that would hand back a file that was never written.
"""
mutable struct StorageWriter{H<:StreamHandle} <: IO
    const handle::H
    const url::String
    base::Int64
    const buf::Vector{UInt8}
    isopen::Bool
end

function StorageWriter(h::StreamHandle, url::AbstractString)
    buf = Vector{UInt8}()
    sizehint!(buf, io_chunk())
    return StorageWriter(h, String(url), Int64(0), buf, true)
end

"The stream types this layer hands out."
const StorageStream = Union{StorageReader,StorageWriter}

function Base.show(io::IO, s::StorageStream)
    kind = s isa StorageReader ? "StorageReader" : "StorageWriter"
    print(io, kind, "(", repr(Session.redact_url(s.url)), ", ")
    s.isopen ? print(io, "at ", position(s)) : print(io, "closed")
    return print(io, ")")
end

Base.isopen(s::StorageStream) = s.isopen
Base.isreadable(s::StorageStream) = s.isopen && s isa StorageReader
Base.iswritable(s::StorageStream) = s.isopen && s isa StorageWriter

function check_open(s::StorageStream, op::AbstractString)
    s.isopen || throw(StorageError(s.url, op, "the stream is closed"))
    return nothing
end

# ---- reading ----

"Bytes of the read buffer that are still ahead of the cursor."
function buffered(r::StorageReader)
    (r.pos < r.bufstart || r.pos >= r.bufstart + r.buflen) && return 0
    return Int(r.bufstart + r.buflen - r.pos)
end

"Fetch the next chunk at the cursor. Returns how many bytes are now buffered."
function refill!(r::StorageReader)
    r.bufstart = r.pos
    r.buflen = stream_read!(r.handle, r.buf, r.pos, Base.length(r.buf))
    return r.buflen
end

"""
Whether the cursor is past the last byte. A backend that would not state a size
is asked for the next chunk to find out — `eof` is the standard library's
question "is there more?", and the only answer available is to go and see.
"""
function Base.eof(r::StorageReader)
    buffered(r) > 0 && return false
    r.size >= 0 && return r.pos >= r.size
    return refill!(r) == 0
end

Base.bytesavailable(r::StorageReader) = buffered(r)
Base.position(r::StorageReader) = r.pos
Base.close(r::StorageReader) = (r.isopen && (r.isopen = false; stream_close(r.handle)); nothing)

function Base.seek(r::StorageReader, pos::Integer)
    check_open(r, "seek")
    pos < 0 && throw(ArgumentError("cannot seek to a negative offset: $pos"))
    r.pos = Int64(pos)
    return r
end

Base.seekstart(r::StorageReader) = seek(r, 0)
Base.skip(r::StorageReader, n::Integer) = seek(r, r.pos + n)

function Base.seekend(r::StorageReader)
    r.size >= 0 ||
        throw(StorageError(r.url, "seek", "this endpoint did not say how large the object is"))
    return seek(r, r.size)
end

"""
Claim at most `n` bytes from the read buffer, refilling it once when it is spent,
and advance the cursor over them. Returns `(from, k)` — where in `r.buf` they
start and how many there are — leaving the copy to the caller, which knows
whether it is filling a pointer or a vector. `k == 0` is end of object.
"""
function take_buffered!(r::StorageReader, n::Int)
    avail = buffered(r)
    if avail == 0
        refill!(r) == 0 && return 0, 0
        avail = buffered(r)
        avail == 0 && return 0, 0
    end
    k = min(n, avail)
    from = Int(r.pos - r.bufstart) + 1
    r.pos += k
    return from, k
end

function Base.read(r::StorageReader, ::Type{UInt8})
    check_open(r, "read")
    from, k = take_buffered!(r, 1)
    k == 0 && throw(EOFError())
    return r.buf[from]
end

function Base.unsafe_read(r::StorageReader, p::Ptr{UInt8}, nb::UInt)
    check_open(r, "read")
    left = Int(nb)
    dest = p
    while left > 0
        from, k = take_buffered!(r, left)
        k == 0 && throw(EOFError())
        GC.@preserve r unsafe_copyto!(dest, pointer(r.buf, from), k)
        dest += k
        left -= k
    end
    return nothing
end

"How many bytes are left, when the backend said how many there were."
remaining(r::StorageReader) = r.size < 0 ? nothing : max(Int64(0), r.size - r.pos)

function Base.readbytes!(r::StorageReader, b::Vector{UInt8}, nb=Base.length(b))
    check_open(r, "read")
    left = remaining(r)
    want = left === nothing ? Int64(nb) : min(Int64(nb), left)
    left === nothing || (Base.length(b) < want && resize!(b, want))
    total = Int64(0)
    while total < want
        from, k = take_buffered!(r, Int(min(want - total, typemax(Int))))
        k == 0 && break
        Base.length(b) < total + k && resize!(b, total + k)
        copyto!(b, Int(total) + 1, r.buf, from, k)
        total += k
    end
    return Int(total)
end

function Base.read(r::StorageReader)
    left = remaining(r)
    b = Vector{UInt8}(undef, left === nothing ? 0 : Int(left))
    n = readbytes!(r, b, left === nothing ? typemax(Int) : Int(left))
    n == Base.length(b) || resize!(b, n)
    return b
end

function Base.readavailable(r::StorageReader)
    check_open(r, "read")
    from, k = take_buffered!(r, buffered(r) == 0 ? Base.length(r.buf) : buffered(r))
    k == 0 && return UInt8[]
    return r.buf[from:(from + k - 1)]
end

# ---- writing ----

Base.position(w::StorageWriter) = w.base + Base.length(w.buf)

function Base.unsafe_write(w::StorageWriter, p::Ptr{UInt8}, nb::UInt)
    check_open(w, "write")
    n = Int(nb)
    n == 0 && return 0
    chunk = io_chunk()
    at = Int(0)
    while at < n
        room = chunk - Base.length(w.buf)
        k = min(room, n - at)
        old = Base.length(w.buf)
        resize!(w.buf, old + k)
        GC.@preserve w unsafe_copyto!(pointer(w.buf, old + 1), p + at, k)
        at += k
        Base.length(w.buf) >= chunk && flush(w)
    end
    return n
end

function Base.write(w::StorageWriter, x::UInt8)
    check_open(w, "write")
    push!(w.buf, x)
    Base.length(w.buf) >= io_chunk() && flush(w)
    return 1
end

function Base.flush(w::StorageWriter)
    n = Base.length(w.buf)
    n == 0 && return nothing
    stream_write(w.handle, w.buf, n, w.base)
    w.base += n
    empty!(w.buf)
    return nothing
end

function Base.seek(w::StorageWriter, pos::Integer)
    check_open(w, "seek")
    pos < 0 && throw(ArgumentError("cannot seek to a negative offset: $pos"))
    stream_seekable(w.handle) ||
        throw(StorageError(w.url, "seek", "this backend writes in one forward pass"))
    flush(w)
    w.base = Int64(pos)
    return w
end

Base.seekstart(w::StorageWriter) = seek(w, 0)

"""
    close(w::StorageWriter)

Flush what is staged and finish the upload, raising [`StorageError`](@ref) when
the object did not land. Closing twice is a no-op, so a `do` block that already
closed the stream is safe.
"""
function Base.close(w::StorageWriter)
    w.isopen || return nothing
    try
        flush(w)
    catch
        w.isopen = false
        stream_close(w.handle)
        rethrow()
    end
    w.isopen = false
    code = stream_close(w.handle)
    code == :ok || throw(StorageError(w.url, "close", "the object was not written: $code"))
    return nothing
end

"Release the handle without reporting what went wrong with it — for the path
where an exception is already on its way up and must not be replaced."
function close_quietly(s::StorageStream)
    s.isopen || return nothing
    s.isopen = false
    try
        stream_close(s.handle)
    catch
    end
    return nothing
end

# ---- entry points ----

"""
    storage_open(url, mode="r"; length=nothing, kwargs...) -> StorageReader | StorageWriter
    storage_open(f::Function, url, mode="r"; kwargs...)

Open a storage object as a Julia `IO`. `mode` is `"r"` to read or `"w"` to write
(creating or truncating). Every scheme [`storage_for`](@ref) knows is accepted —
`root(s)://`, `http(s)://`/`dav(s)://`, `s3(s)://`, and local paths — and
credential keywords are those of `storage_for`.

    storage_open("root://host//data/f", "r") do io
        seek(io, 4096)
        header = read(io, 1024)
    end

`length` declares the size of the object being written. It is optional, and
worth passing: the HTTP lane can then frame the upload with a `Content-Length`
rather than a chunked encoding that not every storage element accepts, and S3
can size its parts. Writing a different number of bytes than declared fails the
upload rather than storing a wrong object.

Failures are raised as [`StorageError`](@ref) — an `IO` has no other way to
report one. For a writer, that includes `close`: an upload that the endpoint
refused is only knowable when the last byte has been offered, so a stream whose
`close` did not raise is one whose object landed.

The `do` form closes the stream, and lets an exception from the body out ahead
of anything `close` would have said.
"""
function storage_open(url::AbstractString, mode::AbstractString="r"; length=nothing, kwargs...)
    return open(storage_for(url; kwargs...), mode; length=length)
end

function storage_open(
    f::Function, url::AbstractString, mode::AbstractString="r"; length=nothing, kwargs...
)
    return open(f, storage_for(url; kwargs...), mode; length=length)
end

"""
    open(b::Backend, mode="r"; length=nothing) -> StorageReader | StorageWriter
    open(f::Function, b::Backend, mode="r"; length=nothing)

Open the backend's own object as a stream; see [`storage_open`](@ref), which is
this with the URL parsing in front of it.
"""
function Base.open(b::Backend, mode::AbstractString="r"; length=nothing)
    url = backend_url(b)
    if mode == "r"
        length === nothing ||
            throw(ArgumentError("length declares the size of a write; \"r\" reads"))
        return StorageReader(open_read_handle(b), url)
    elseif mode == "w"
        return StorageWriter(open_write_handle(b, length), url)
    end
    throw(ArgumentError("storage streams open \"r\" or \"w\", not $(repr(mode))"))
end

function Base.open(f::Function, b::Backend, mode::AbstractString="r"; length=nothing)
    s = open(b, mode; length=length)
    done = false
    try
        result = f(s)
        done = true
        return result
    finally
        # On the way out of a failed body, `close` has nothing to add and could
        # replace the exception that matters with one about the upload it could
        # not finish.
        done ? close(s) : close_quietly(s)
    end
end
