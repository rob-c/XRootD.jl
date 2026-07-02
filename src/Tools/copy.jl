# The copy engine: pump bytes between any two Storage backends, with optional
# post-copy checksum verification and recursive tree copy.

"""
    copyfile(src_url, dst_url; force=false, verify=false) -> (ok::Bool, message::String)

Copy one object from `src_url` to `dst_url`; both may be local paths,
`root(s)://`, `http(s)://`/`dav(s)://`, or `s3(s)://`. `force` overwrites an
existing destination. `verify` recomputes a CRC32c over both ends and
compares after the copy.
"""
function copyfile(
    src_url::AbstractString, dst_url::AbstractString; force::Bool=false, verify::Bool=false
)
    src = storage_for(src_url)
    dst = storage_for(dst_url)

    if !force
        code, _ = storage_stat(dst)
        code == :ok && return false, "destination exists (use force): $dst_url"
    end

    buf = IOBuffer()
    rcode = storage_read(src, buf)
    rcode == :ok || return false, "read failed ($rcode): $src_url"
    data = take!(buf)

    wcode = storage_write(dst, IOBuffer(data))
    wcode == :ok || return false, "write failed ($wcode): $dst_url"

    if verify
        vbuf = IOBuffer()
        vcode = storage_read(dst, vbuf)
        vcode == :ok || return false, "verify read failed ($vcode): $dst_url"
        if CRC32c.crc32c(take!(vbuf)) != CRC32c.crc32c(data)
            return false, "checksum mismatch after copy"
        end
    end
    return true, "copied $(length(data)) bytes"
end

"""
    copytree(src_url, dst_url; force=false, verify=false) -> (ok::Bool, message::String)

Recursively copy a directory tree from `src_url` to `dst_url`, recreating
the structure under the destination. Both must be directory-capable backends
(local or `root://`).
"""
function copytree(
    src_url::AbstractString, dst_url::AbstractString; force::Bool=false, verify::Bool=false
)
    src = storage_for(src_url)
    entries = storage_list(src)
    isempty(entries) && return copyfile(src_url, dst_url; force, verify)  # a file, not a tree

    ensure_dir(dst_url)
    copied = 0
    for (name, info) in entries
        child_src = joinurl(src_url, name)
        child_dst = joinurl(dst_url, name)
        ok, msg = if info.isdir
            copytree(child_src, child_dst; force, verify)
        else
            copyfile(child_src, child_dst; force, verify)
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

"Create `url` as a directory if the backend supports it."
function ensure_dir(url::AbstractString)
    u = Storage.parse_url(url)
    if u.scheme in ("root", "roots")
        fs = XrdCl.FileSystem("$(u.scheme)://$(u.host):$(u.port)")
        XrdCl.mkdir(fs, u.path, XrdCl.Access.UR | XrdCl.Access.UW | XrdCl.Access.UX)
    elseif u.scheme == "file"
        mkpath(u.path)
    end
    return nothing
end
