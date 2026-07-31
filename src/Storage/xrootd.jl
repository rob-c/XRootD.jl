# XRootD backend — delegates to the XrdCl File/FileSystem client.

"XRootD (`root(s)://`) backend over the native client."
struct XRootDBackend <: Backend
    url::StorageURL
    fs::XrdCl.FileSystem
    path::String
end

function XRootDBackend(u::StorageURL; insecure_tls::Bool=false)
    base = "$(u.scheme)://$(u.host):$(u.port)"
    return XRootDBackend(u, XrdCl.FileSystem(base; insecure_tls=insecure_tls), u.path)
end

function storage_stat(b::XRootDBackend)
    st, info = XrdCl.stat(b.fs, b.path)
    XrdCl.isOK(st) || return :error, nothing
    return :ok, StorageInfo(info.size, info.modtime, XrdCl.isdir(info))
end

"""
Stream the object into `sink`. A server that stops before the requested range
is served has *stopped*, not *finished*: the short transfer is reported as
`:truncated` rather than returning the clean prefix as a complete object.
"""
function storage_read(b::XRootDBackend, sink::IO; offset::Integer=0, length=nothing)
    fileurl = "$(b.url.scheme)://$(b.url.host):$(b.url.port)/$(b.path)"
    f = XrdCl.File(fileurl, XrdCl.OpenFlags.Read)
    f === nothing && return :error
    try
        st, info = XrdCl.stat(f)
        XrdCl.isOK(st) || return :error
        total = length === nothing ? info.size - offset : Int64(length)
        pos = Int64(offset)
        chunk = 1 << 20
        remaining = total
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
    fileurl = "$(b.url.scheme)://$(b.url.host):$(b.url.port)/$(b.path)"
    f = XrdCl.File()
    st, _ = open(f, fileurl, XrdCl.OpenFlags.Write | XrdCl.OpenFlags.Delete)
    XrdCl.isOK(st) || return :error
    ok = true
    try
        pos = Int64(0)
        chunk = 1 << 20
        while true
            data = read(source, chunk)
            isempty(data) && break
            wst, _ = write(f, data, Base.length(data), pos)
            if !XrdCl.isOK(wst)
                ok = false
                break
            end
            pos += Base.length(data)
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
