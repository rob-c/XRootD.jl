# The copy engine: pump bytes between any two Storage backends, with optional
# post-copy checksum verification and recursive tree copy.

"""
Chunk of pipe backlog the copy engine tolerates before holding the reader back
— the storage layer's bound ([`XRootD.Storage.STREAM_HIGH_WATER`](@ref)), since
a copy and a write stream are the same producer against the same pipe.
"""
const COPY_HIGH_WATER = Storage.STREAM_HIGH_WATER

"""
Tee sink for the copy engine: forwards bytes to the pipe the destination
backend reads from, hashing and counting them on the way through. Writes block
once the consumer falls `COPY_HIGH_WATER` bytes behind, so a copy costs a
bounded amount of memory instead of the size of the object.

`progress`, when given, is called with the running byte count. It is called
from the producer's write path, so it must be cheap and must not throw — this
is the only point in a copy that knows how far along it is.
"""
mutable struct CopySink{P} <: IO
    pipe::IO
    crc::UInt32
    nbytes::Int64
    progress::P
end

function CopySink(pipe::IO, progress=nothing)
    return CopySink{typeof(progress)}(pipe, UInt32(0), Int64(0), progress)
end

function Base.unsafe_write(s::CopySink, p::Ptr{UInt8}, n::UInt)
    n == 0 && return 0
    s.crc = CRC32c.crc32c(unsafe_wrap(Array, p, Int(n)), s.crc)
    s.nbytes += Int(n)
    nw = unsafe_write(s.pipe, p, n)
    s.progress === nothing || s.progress(s.nbytes)
    throttle!(s)
    return nw
end

function Base.write(s::CopySink, x::UInt8)
    buf = [x]
    return GC.@preserve buf unsafe_write(s, pointer(buf), UInt(1))
end

Base.isopen(s::CopySink) = isopen(s.pipe)
Base.close(s::CopySink) = close(s.pipe)
Base.flush(s::CopySink) = flush(s.pipe)

"Hold the producer back while the destination lags behind."
throttle!(s::CopySink) = Storage.backpressure!(s.pipe, COPY_HIGH_WATER)

"""
    stream_copy(src, dst, expected=nothing, progress=nothing) -> (read_code, write_code, crc32c, nbytes, write_error)

Stream `src` into `dst` through a bounded pipe. Reader and writer run
concurrently: the source backend writes into the pipe while the destination
backend drains it, so neither end sees the whole object.

`progress` is called with the running byte count as the copy advances
([`CopySink`](@ref)).

`expected` is what the source said it holds ([`source_size`](@ref)), and is
passed on to the destination because a backend that knows the size can say so:
an HTTP `PUT` frames the upload with a `Content-Length` instead of a chunked
encoding not every storage element accepts, and S3 sizes its parts to the
object. A destination told the wrong size fails the transfer, which is the same
answer the short-read check below gives — the size is checked either way.
"""
function stream_copy(src, dst, expected=nothing, progress=nothing)
    pipe = Base.BufferStream()
    sink = CopySink(pipe, progress)
    producer = Threads.@spawn begin
        try
            storage_read(src, sink)
        catch
            :error
        finally
            close(pipe)
        end
    end
    # What the destination said, kept rather than discarded: closing the pipe
    # below makes the producer fail too, so by the time both codes are in hand
    # the destination's own words are the only account of what went wrong.
    werr = ""
    wcode = try
        storage_write(dst, pipe; length=expected)
    catch err
        werr = sprint(showerror, err)
        :error
    finally
        # Unblock a producer still waiting on a destination that stopped
        # reading; without this a failed write would wedge the copy.
        close(pipe)
    end
    rcode = fetch(producer)
    return rcode, wcode, sink.crc, sink.nbytes, werr
end

"""
    source_size(src) -> Union{Int64,Nothing}

How many bytes the source says it holds, or `nothing` when it will not say.

This is what makes a lost connection visible to a copy. A transfer that ends
early ends with a *valid* short object at the destination, and `verify` cannot
catch it — the checksum is taken over the bytes that were actually streamed,
so both ends agree on a file that is half the one that was asked for. The
source's own declared size is the only independent statement of how long the
object should have been.

A size of zero is treated as "would not say" rather than as an empty object:
an endpoint that answers a `HEAD` without a `Content-Length` reports zero, and
failing every copy from it would be a worse trade than missing the check on a
file that has no bytes to lose.
"""
function source_size(src)
    code, info = try
        storage_stat(src)
    catch
        return nothing
    end
    (code == :ok && info !== nothing && !info.isdir && info.size > 0) || return nothing
    return Int64(info.size)
end

# `roots://` and `root://` reach the same object over different transports, as
# do `dav(s)://` and `http(s)://`; only the endpoint and the path decide what is
# being addressed.
const _SCHEME_FAMILY = Dict(
    "root" => "root",
    "roots" => "root",
    "http" => "http",
    "https" => "http",
    "dav" => "http",
    "davs" => "http",
    "s3" => "s3",
    "s3s" => "s3",
)

"""
    same_object(src_url, dst_url) -> Bool

Whether two URLs name the same stored object.

A copy opens its destination for writing before it has read a byte of its
source, so a copy onto itself truncates the thing it was about to read: the
object is gone and the error blames a short read. That is a mistake worth one
comparison up front — `cp(f, f)`, or `download(url, dir)` where `dir` already
holds a file of that name, is the kind of thing anyone does eventually.

Locally the question is asked of the filesystem, so a symlink or a hard link
to the same inode counts. Elsewhere it is the endpoint and the path.
"""
function same_object(src_url::AbstractString, dst_url::AbstractString)
    a, b = Storage.parse_url(src_url), Storage.parse_url(dst_url)
    if a.scheme == "file" && b.scheme == "file"
        return ispath(a.path) && ispath(b.path) && samefile(a.path, b.path)
    end
    get(_SCHEME_FAMILY, a.scheme, a.scheme) == get(_SCHEME_FAMILY, b.scheme, b.scheme) ||
        return false
    return a.host == b.host && a.port == b.port && a.path == b.path
end

"Stream an object past a hash: `(code, crc32c, nbytes)`, nothing buffered."
function checksum_object(b)
    sink = CopySink(devnull)
    code = try
        storage_read(b, sink)
    catch
        :error
    end
    return code, sink.crc, sink.nbytes
end

"""
    copyfile(src_url, dst_url; force=false, verify=false, tpc=:none, progress=nothing,
             src_opts=(;), dst_opts=(;), kwargs...) -> (ok::Bool, message::String)

Copy one object from `src_url` to `dst_url`; both may be local paths,
`root(s)://`, `http(s)://`/`dav(s)://`, or `s3(s)://`. `force` overwrites an
existing destination. `verify` recomputes a CRC32c over both ends and
compares after the copy.

`progress` is called as `progress(done::Int64, total)` while the bytes move,
where `total` is what the source said it holds or `nothing` when it would not
say. A third-party copy moves no bytes through this client and so reports none.

`tpc` requests a third-party copy, in `xrdcp`'s vocabulary: `:none` streams
through this client, `:first` tries a third-party copy and falls back to
streaming, `:only` fails when the endpoints cannot do one
([`tpc_copy`](@ref)).

Credential keywords (`token`, `cert`, `key`, `insecure_tls`, …) apply to both
ends; `src_opts` / `dst_opts` override them per end, for the common case of
two endpoints with different tokens.
"""
function copyfile(
    src_url::AbstractString,
    dst_url::AbstractString;
    force::Bool=false,
    verify::Bool=false,
    tpc::Symbol=:none,
    progress=nothing,
    src_opts=NamedTuple(),
    dst_opts=NamedTuple(),
    kwargs...,
)
    tpc in (:none, :first, :only) ||
        throw(ArgumentError("tpc must be :none, :first, or :only (got $(repr(tpc)))"))
    src = storage_for(src_url; kwargs..., src_opts...)
    dst = storage_for(dst_url; kwargs..., dst_opts...)

    same_object(src_url, dst_url) &&
        return false, "source and destination are the same object: $src_url"

    if !force
        code, _ = storage_stat(dst)
        code == :ok && return false, "destination exists (use force): $dst_url"
    end
    expected = source_size(src)

    if tpc !== :none
        code, msg = tpc_copy(src, dst; overwrite=force)
        code == :ok && return true, msg
        if code == :error || tpc === :only
            return false, "third-party copy failed: $msg"
        end
        # :unsupported with tpc=:first — fall through to a streaming copy.
    end

    # The sink counts bytes; only the caller knows what to do with the number,
    # and only this frame knows how many there are supposed to be.
    report = progress === nothing ? nothing : (done -> progress(done, expected))
    rcode, wcode, crc, nbytes, werr = stream_copy(src, dst, expected, report)
    # The destination is asked first: a write that failed closes the pipe under
    # the reader, so a broken destination shows up as a failure at both ends and
    # only one of them is the cause.
    if wcode != :ok
        return false, "write failed ($wcode): $dst_url" * (isempty(werr) ? "" : ": $werr")
    end
    rcode == :ok || return false, "read failed ($rcode): $src_url"
    if expected !== nothing && nbytes != expected
        return false, "short read: $nbytes of $expected bytes from $src_url"
    end

    if verify
        vcode, vcrc, _ = checksum_object(dst)
        vcode == :ok || return false, "verify read failed ($vcode): $dst_url"
        vcrc == crc || return false, "checksum mismatch after copy"
    end
    return true, "copied $nbytes bytes"
end

"""
    copytree(src_url, dst_url; force=false, verify=false, progress=nothing, kwargs...) -> (ok, message)

Recursively copy a directory tree from `src_url` to `dst_url`, recreating
the structure under the destination. Both must be directory-capable backends
(local, `root://`, or WebDAV). Keywords are those of [`copyfile`](@ref);
`progress` is reported per file, since a tree has no total until it is walked.
"""
function copytree(
    src_url::AbstractString,
    dst_url::AbstractString;
    force::Bool=false,
    verify::Bool=false,
    progress=nothing,
    kwargs...,
)
    src = storage_for(src_url; kwargs...)
    entries = storage_list(src)
    if isempty(entries)
        # Nothing to list is either a file or an empty directory, and only a
        # stat tells them apart. An empty directory is still part of the tree:
        # recreate it rather than trying to read it as an object.
        code, info = storage_stat(src)
        if code == :ok && info !== nothing && info.isdir
            ensure_dir(dst_url; kwargs...) == :error &&
                return false, "cannot create directory: $dst_url"
            return true, "created empty directory $dst_url"
        end
        return copyfile(src_url, dst_url; force, verify, progress, kwargs...)
    end

    code = ensure_dir(dst_url; kwargs...)
    code == :error && return false, "cannot create directory: $dst_url"
    copied = 0
    for (name, info) in entries
        child_src = joinurl(src_url, name)
        child_dst = joinurl(dst_url, name)
        ok, msg = if info.isdir
            copytree(child_src, child_dst; force, verify, progress, kwargs...)
        else
            copyfile(child_src, child_dst; force, verify, progress, kwargs...)
        end
        ok || return false, "failed on $child_src: $msg"
        copied += 1
    end
    return true, "copied $copied entries under $dst_url"
end

"Join a base URL/path and a child name, preserving the scheme."
function joinurl(base::AbstractString, name::AbstractString)
    return String(rstrip(base, '/') * "/" * name)
end

"""
    ensure_dir(url; kwargs...) -> Symbol

Create `url` as a directory: `mkpath` locally, `kXR_mkdir` with
`kXR_mkdirpath` over `root://`, `MKCOL` over WebDAV. `:unsupported` for a
backend without directories (S3 answers `:ok` — a prefix needs no creating).
"""
function ensure_dir(url::AbstractString; kwargs...)
    return storage_mkdir(storage_for(url; kwargs...))
end
