# The copy engine: pump bytes between any two Storage backends, with optional
# post-copy checksum verification and recursive tree copy.

"Chunk of pipe backlog the copy engine tolerates before holding the reader back."
const COPY_HIGH_WATER = 8 << 20

"""
Tee sink for the copy engine: forwards bytes to the pipe the destination
backend reads from, hashing and counting them on the way through. Writes block
once the consumer falls `COPY_HIGH_WATER` bytes behind, so a copy costs a
bounded amount of memory instead of the size of the object.
"""
mutable struct CopySink <: IO
    pipe::IO
    crc::UInt32
    nbytes::Int64
end

CopySink(pipe::IO) = CopySink(pipe, UInt32(0), Int64(0))

function Base.unsafe_write(s::CopySink, p::Ptr{UInt8}, n::UInt)
    n == 0 && return 0
    s.crc = CRC32c.crc32c(unsafe_wrap(Array, p, Int(n)), s.crc)
    s.nbytes += Int(n)
    nw = unsafe_write(s.pipe, p, n)
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
function throttle!(s::CopySink)
    pipe = s.pipe
    pipe isa Base.BufferStream || return nothing
    while isopen(pipe) && bytesavailable(pipe) > COPY_HIGH_WATER
        sleep(0.001)
    end
    return nothing
end

"""
Stream `src` into `dst` through a bounded pipe, returning
`(read_code, write_code, crc32c, nbytes)`. Reader and writer run
concurrently: the source backend writes into the pipe while the destination
backend drains it, so neither end sees the whole object.
"""
function stream_copy(src, dst)
    pipe = Base.BufferStream()
    sink = CopySink(pipe)
    producer = Threads.@spawn begin
        try
            storage_read(src, sink)
        catch
            :error
        finally
            close(pipe)
        end
    end
    wcode = try
        storage_write(dst, pipe)
    catch
        :error
    finally
        # Unblock a producer still waiting on a destination that stopped
        # reading; without this a failed write would wedge the copy.
        close(pipe)
    end
    rcode = fetch(producer)
    return rcode, wcode, sink.crc, sink.nbytes
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
    copyfile(src_url, dst_url; force=false, verify=false, tpc=:none,
             src_opts=(;), dst_opts=(;), kwargs...) -> (ok::Bool, message::String)

Copy one object from `src_url` to `dst_url`; both may be local paths,
`root(s)://`, `http(s)://`/`dav(s)://`, or `s3(s)://`. `force` overwrites an
existing destination. `verify` recomputes a CRC32c over both ends and
compares after the copy.

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
    src_opts=NamedTuple(),
    dst_opts=NamedTuple(),
    kwargs...,
)
    tpc in (:none, :first, :only) ||
        throw(ArgumentError("tpc must be :none, :first, or :only (got $(repr(tpc)))"))
    src = storage_for(src_url; kwargs..., src_opts...)
    dst = storage_for(dst_url; kwargs..., dst_opts...)

    if !force
        code, _ = storage_stat(dst)
        code == :ok && return false, "destination exists (use force): $dst_url"
    end

    if tpc !== :none
        code, msg = tpc_copy(src, dst; overwrite=force)
        code == :ok && return true, msg
        if code == :error || tpc === :only
            return false, "third-party copy failed: $msg"
        end
        # :unsupported with tpc=:first — fall through to a streaming copy.
    end

    rcode, wcode, crc, nbytes = stream_copy(src, dst)
    rcode == :ok || return false, "read failed ($rcode): $src_url"
    wcode == :ok || return false, "write failed ($wcode): $dst_url"

    if verify
        vcode, vcrc, _ = checksum_object(dst)
        vcode == :ok || return false, "verify read failed ($vcode): $dst_url"
        vcrc == crc || return false, "checksum mismatch after copy"
    end
    return true, "copied $nbytes bytes"
end

"""
    copytree(src_url, dst_url; force=false, verify=false, kwargs...) -> (ok, message)

Recursively copy a directory tree from `src_url` to `dst_url`, recreating
the structure under the destination. Both must be directory-capable backends
(local, `root://`, or WebDAV). Keywords are those of [`copyfile`](@ref).
"""
function copytree(
    src_url::AbstractString,
    dst_url::AbstractString;
    force::Bool=false,
    verify::Bool=false,
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
        return copyfile(src_url, dst_url; force, verify, kwargs...)
    end

    code = ensure_dir(dst_url; kwargs...)
    code == :error && return false, "cannot create directory: $dst_url"
    copied = 0
    for (name, info) in entries
        child_src = joinurl(src_url, name)
        child_dst = joinurl(dst_url, name)
        ok, msg = if info.isdir
            copytree(child_src, child_dst; force, verify, kwargs...)
        else
            copyfile(child_src, child_dst; force, verify, kwargs...)
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
