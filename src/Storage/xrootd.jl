# XRootD backend — delegates to the XrdCl File/FileSystem client.

"XRootD (`root(s)://`) backend over the native client."
struct XRootDBackend <: Backend
    url::StorageURL
    fs::XrdCl.FileSystem
    path::String
    creds::Dict{Symbol,Any}
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
        u, fs, u.path, merge(creds, Dict{Symbol,Any}(:insecure_tls => insecure_tls))
    )
end

function storage_stat(b::XRootDBackend)
    st, info = XrdCl.stat(b.fs, b.path)
    XrdCl.isOK(st) || return :error, nothing
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
        while remaining > 0
            n = min(IO_CHUNK, remaining)
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
        buf = Vector{UInt8}(undef, IO_CHUNK)
        while true
            n = fill_chunk!(source, buf, IO_CHUNK)
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

function storage_list(b::XRootDBackend)
    st, names, stats = XrdCl.dirlist_stat(b.fs, b.path)
    XrdCl.isOK(st) || return Tuple{String,StorageInfo}[]
    return [
        (n, StorageInfo(s.size, s.modtime, XrdCl.isdir(s))) for (n, s) in zip(names, stats)
    ]
end

function storage_remove(b::XRootDBackend)
    st, _ = XrdCl.rm(b.fs, b.path)
    return XrdCl.isOK(st) ? :ok : :error
end

function storage_mkdir(b::XRootDBackend)
    mode = XrdCl.Access.UR | XrdCl.Access.UW | XrdCl.Access.UX
    st, _ = mkdir(b.fs, b.path, mode; mkpath=true)
    XrdCl.isOK(st) && return :ok
    # A directory that already exists satisfies the caller. Servers disagree on
    # which error code says so, so ask what is actually there.
    code, info = storage_stat(b)
    return (code == :ok && info !== nothing && info.isdir) ? :ok : :error
end

function storage_move(b::XRootDBackend, dst_url::AbstractString; overwrite::Bool=false)
    dst = parse_url(dst_url)
    dst.scheme in ("root", "roots") || return :unsupported
    (dst.host == b.url.host && dst.port == b.url.port) || return :unsupported
    st, _ = mv(b.fs, b.path, dst.path)
    return XrdCl.isOK(st) ? :ok : :error
end

# The xroot protocol has no server-side copy; a copy between two xroot
# endpoints is a third-party copy (`XRootD.Tools.tpc_copy`).
storage_copy(::XRootDBackend, ::AbstractString; overwrite::Bool=false) = :unsupported
