# XRootD backend — delegates to the XrdCl File/FileSystem client.

"""
XRootD (`root(s)://`) backend over the native client.

`lasterror` holds what the server said about the last failed operation, for a
caller that has only a `:error` symbol to go on.
"""
mutable struct XRootDBackend <: Backend
    const url::StorageURL
    const fs::XrdCl.FileSystem
    const path::String
    const creds::Dict{Symbol,Any}
    lasterror::Union{String,Nothing}
end

"""
    XRootDBackend(u::StorageURL; insecure_tls=false, kwargs...)

Credential keywords (`token`, `keytab`, `cert`/`key`, `x509`) are held on the
backend and applied to every connection it makes — the `FileSystem` handle and
each `File` open alike.
"""
function XRootDBackend(u::StorageURL; insecure_tls::Bool=false, kwargs...)
    base = "$(u.scheme)://$(u.host):$(u.port)"
    creds = Dict{Symbol,Any}(kwargs)
    fs = XrdCl.FileSystem(base; insecure_tls=insecure_tls, kwargs...)
    return XRootDBackend(
        u,
        fs,
        u.path,
        merge(creds, Dict{Symbol,Any}(:insecure_tls => insecure_tls)),
        nothing,
    )
end

"""
    note_error!(b, st) -> Symbol

Keep the server's own account of a failure on the backend and answer `:error`.

The message is what the server sent (`No such file or directory`), not the
formatted status, because it is read by people who asked for a file rather than
by people debugging the protocol; the codes stay reachable through the
[`XRootD.XrdCl`](@ref) layer.
"""
function note_error!(b::XRootDBackend, st::XrdCl.XRootDStatus)
    b.lasterror = isempty(st.message) ? string(st) : st.message
    return :error
end

"`creds` is exactly the credential keywords the caller passed, so it is
printed by name only ([`XRootD.Session.redact`](@ref))."
function Base.show(io::IO, b::XRootDBackend)
    print(io, "XRootDBackend(", repr(Session.redact_url(b.url.raw)))
    isempty(b.creds) || print(io, ", ", Session.redact(b.creds))
    return print(io, ")")
end

function storage_stat(b::XRootDBackend)
    st, info = XrdCl.stat(b.fs, b.path)
    XrdCl.isOK(st) || return note_error!(b, st), nothing
    return :ok, StorageInfo(info.size, info.modtime, XrdCl.isdir(info))
end

"The `root://host:port//path` URL of the backend's object."
file_url(b::XRootDBackend) = "$(b.url.scheme)://$(b.url.host):$(b.url.port)/$(b.path)"

"""
Stream the object into `sink`. A server that stops before the requested range
is served has *stopped*, not *finished*: the short transfer is reported as
`:truncated` rather than returning the clean prefix as a complete object.
"""
function storage_read(b::XRootDBackend, sink::IO; offset::Integer=0, length=nothing)
    f = XrdCl.File(file_url(b), XrdCl.OpenFlags.Read; b.creds...)
    f === nothing && return :error
    try
        st, info = XrdCl.stat(f)
        XrdCl.isOK(st) || return :error
        total = length === nothing ? info.size - offset : Int64(length)
        pos = Int64(offset)
        remaining = total
        chunk = io_chunk()
        while remaining > 0
            n = min(chunk, remaining)
            rst, data = read(f, n, pos)
            XrdCl.isOK(rst) || return :error
            isempty(data) && return :truncated
            write(sink, data)
            pos += Base.length(data)
            remaining -= Base.length(data)
        end
        return :ok
    finally
        close(f)
    end
end

"""
Upload `source` to the backend's object. `kXR_sync` and `kXR_close` are the
in-band signals that the bytes committed, so both are issued and both are
checked — an upload whose close fails has not been published, whatever the
individual writes returned.
"""
function storage_write(b::XRootDBackend, source::IO; length=nothing)
    f = XrdCl.File()
    st, _ = open(f, file_url(b), XrdCl.OpenFlags.Write | XrdCl.OpenFlags.Delete; b.creds...)
    XrdCl.isOK(st) || return :error
    ok = true
    try
        pos = Int64(0)
        chunk = io_chunk()
        buf = Vector{UInt8}(undef, chunk)
        while true
            n = fill_chunk!(source, buf, chunk)
            n == 0 && break
            wst, _ = write(f, buf, n, pos)
            if !XrdCl.isOK(wst)
                ok = false
                break
            end
            pos += n
        end
        if ok
            sst, _ = XrdCl.sync(f)
            ok = XrdCl.isOK(sst)
        end
    catch
        ok = false
    end
    cst, _ = close(f)
    return ok && XrdCl.isOK(cst) ? :ok : :error
end

"""
A stream over an open `kXR_open` handle rather than a file reopened per call.
The protocol addresses every read and write by absolute offset, so one handle
serves a whole stream — seeking included, in both directions.
"""
struct XRootDStream <: StreamHandle
    file::XrdCl.File
    url::String
    size::Int64
    writable::Bool
end

stream_size(h::XRootDStream) = h.size
stream_seekable(::XRootDStream) = true

function stream_read!(h::XRootDStream, buf::Vector{UInt8}, offset::Int64, n::Int)
    n = min(n, Int(max(0, h.size - offset)))
    n == 0 && return 0
    st, got = GC.@preserve buf unsafe_read(h.file, pointer(buf), n, offset)
    XrdCl.isOK(st) || throw(StorageError(h.url, "read", string(st)))
    # The window was clipped to the file's own size above, so a short reply is
    # a transfer that stopped rather than a file that ended.
    got == n || throw(StorageError(h.url, "read", "$got of $n bytes at $offset"))
    return Int(got)
end

function stream_write(h::XRootDStream, data::Vector{UInt8}, n::Int, offset::Int64)
    st, _ = write(h.file, data, n, offset)
    XrdCl.isOK(st) || throw(StorageError(h.url, "write", string(st)))
    return nothing
end

"""
`kXR_sync` and `kXR_close` are the in-band signals that the bytes committed, so
both are issued and both are checked — as in [`storage_write`](@ref), an upload
whose close failed has not been published, whatever its writes returned.
"""
function stream_close(h::XRootDStream)
    ok = true
    if h.writable
        sst, _ = XrdCl.sync(h.file)
        ok = XrdCl.isOK(sst)
    end
    cst, _ = close(h.file)
    return (ok && XrdCl.isOK(cst)) ? :ok : :error
end

function open_read_handle(b::XRootDBackend)
    url = file_url(b)
    f = XrdCl.File(url, XrdCl.OpenFlags.Read; b.creds...)
    f === nothing && throw(StorageError(url, "open", "the server refused the open"))
    st, info = XrdCl.stat(f)
    if !XrdCl.isOK(st)
        close(f)
        throw(StorageError(url, "open", string(st)))
    end
    return XRootDStream(f, url, info.size, false)
end

function open_write_handle(b::XRootDBackend, total)
    url = file_url(b)
    f = XrdCl.File()
    st, _ = open(f, url, XrdCl.OpenFlags.Write | XrdCl.OpenFlags.Delete; b.creds...)
    XrdCl.isOK(st) || throw(StorageError(url, "open", string(st)))
    return XRootDStream(f, url, total === nothing ? Int64(-1) : Int64(total), true)
end

function storage_list(b::XRootDBackend)
    st, names, stats = XrdCl.dirlist_stat(b.fs, b.path)
    if !XrdCl.isOK(st)
        note_error!(b, st)
        return Tuple{String,StorageInfo}[]
    end
    return [
        (n, StorageInfo(s.size, s.modtime, XrdCl.isdir(s))) for (n, s) in zip(names, stats)
    ]
end

"""
`kXR_rm` unlinks a file and `kXR_rmdir` removes a directory; which one the path
needs is the server's business, so the other is tried rather than spending a
`stat` to find out.
"""
function storage_remove(b::XRootDBackend)
    st, _ = XrdCl.rm(b.fs, b.path)
    XrdCl.isOK(st) && return :ok
    dst, _ = XrdCl.rmdir(b.fs, b.path)
    XrdCl.isOK(dst) && return :ok
    return note_error!(b, st)
end

function storage_mkdir(b::XRootDBackend)
    mode = XrdCl.Access.UR | XrdCl.Access.UW | XrdCl.Access.UX
    st, _ = mkdir(b.fs, b.path, mode; mkpath=true)
    XrdCl.isOK(st) && return :ok
    # A directory that already exists satisfies the caller. Servers disagree on
    # which error code says so, so ask what is actually there.
    code, info = storage_stat(b)
    (code == :ok && info !== nothing && info.isdir) && return :ok
    return note_error!(b, st)
end

function storage_move(b::XRootDBackend, dst_url::AbstractString; overwrite::Bool=false)
    dst = parse_url(dst_url)
    dst.scheme in ("root", "roots") || return :unsupported
    (dst.host == b.url.host && dst.port == b.url.port) || return :unsupported
    # `kXR_mv` carries no "replace" flag and servers disagree over whether a
    # rename may land on an occupied name at all, so the client settles it:
    # refuse without asking, or clear the way first.
    if XrdCl.isOK(first(XrdCl.stat(b.fs, dst.path)))
        if !overwrite
            b.lasterror = "destination exists: $dst_url"
            return :error
        end
        rst, _ = XrdCl.rm(b.fs, dst.path)
        XrdCl.isOK(rst) || return note_error!(b, rst)
    end
    st, _ = mv(b.fs, b.path, dst.path)
    return XrdCl.isOK(st) ? :ok : note_error!(b, st)
end

# The xroot protocol has no server-side copy; a copy between two xroot
# endpoints is a third-party copy (`XRootD.Tools.tpc_copy`).
storage_copy(::XRootDBackend, ::AbstractString; overwrite::Bool=false) = :unsupported
