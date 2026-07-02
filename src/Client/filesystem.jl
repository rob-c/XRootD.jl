# The FileSystem API — 0.2.x signatures over the native Session layer.
# Every operation returns `(XRootDStatus, result)`; `result` is `nothing`
# for mutations. `timeout` arguments are accepted for 0.2.x compatibility;
# per-request timeouts arrive with the resilience work (plan 05).

"""
    FileSystem(url::String)

Handle for filesystem operations against an XRootD server, e.g.
`FileSystem("root://localhost:1094")`. Connects lazily on first use and
reconnects if the connection is lost.
"""
mutable struct FileSystem
    url::String
    host::String
    port::Int
    conn::Union{Session.Connection,Nothing}
end

function FileSystem(url::String, isServer::Bool=false)
    m = match(r"^roots?://([^/:@]+)(?::(\d+))?", url)
    m === nothing && throw(ArgumentError("not a root:// URL: $(repr(url))"))
    host = String(something(m.captures[1]))
    portstr = m.captures[2]
    port = portstr === nothing ? 1094 : parse(Int, portstr)
    return FileSystem(url, host, port, nothing)
end

"Connect lazily; reconnect when the previous connection died."
function connection!(fs::FileSystem)
    conn = fs.conn
    if conn === nothing || !isopen(conn)
        conn = Session.connect(fs.host, fs.port)
        fs.conn = conn
    end
    return conn
end

"Run one request, converting connection failures into error statuses."
function perform(fs::FileSystem, req::Wire.Request)
    hdr, body = try
        Session.roundtrip(connection!(fs), req)
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), UInt8[]
    end
    return status_from(hdr, body), body
end

"""
    ping(fs::FileSystem, timeout::UInt16=0x0000)

Check that the server is alive. Returns `(status, nothing)`.
"""
function ping(fs::FileSystem, timeout::UInt16=0x0000)
    st, _ = perform(fs, Wire.PingRequest())
    return st, nothing
end

"""
    Base.stat(fs::FileSystem, path::String, timeout::UInt16=0x0000)

Stat a file or directory. Returns `(status, StatInfo | nothing)`.
"""
function Base.stat(fs::FileSystem, path::String, timeout::UInt16=0x0000)
    st, body = perform(fs, Wire.StatRequest(path))
    isOK(st) || return st, nothing
    return st, StatInfo(String(copy(body)))
end

"""
    locate(fs::FileSystem, path::String, flags::Integer, timeout::UInt16=0x0000)

List the locations of a file or directory (`flags` from `OpenFlags`, e.g.
`OpenFlags.Refresh`). Returns `(status, Vector{Location} | nothing)`.
"""
function locate(fs::FileSystem, path::String, flags::Integer, timeout::UInt16=0x0000)
    st, body = perform(fs, Wire.LocateRequest(path; options=UInt16(flags)))
    isOK(st) || return st, nothing
    locs = [Location(t.address, t.node, t.access) for t in Wire.parse_locate(body)]
    return st, locs
end

"""
    query(fs::FileSystem, code::Integer, arg::String, timeout::UInt16=0x0000)

Query server information (`code` from `QueryCode`). Returns
`(status, String | nothing)`.
"""
function query(fs::FileSystem, code::Integer, arg::String, timeout::UInt16=0x0000)
    st, body = perform(fs, Wire.QueryRequest(UInt16(code), arg))
    isOK(st) || return st, nothing
    return st, rstrip(String(copy(body)), '\0')
end

"""
    Base.readdir(fs::FileSystem, path::String, flags::Integer=DirListFlags.None;
                 join::Bool=false, sort::Bool=false)

List directory entries. Returns `(status, Vector{String} | nothing)`.
"""
function Base.readdir(
    fs::FileSystem,
    path::String,
    flags::Integer=DirListFlags.None;
    join::Bool=false,
    sort::Bool=false,
)
    wants_stat = (flags & DirListFlags.Stat) != 0
    options = wants_stat ? Wire.kXR_dstat : 0x00
    st, body = perform(fs, Wire.DirlistRequest(path; options=options))
    isOK(st) || return st, nothing
    entries = Wire.parse_dirlist(body).entries
    join && (entries = joinpath.(Ref(path), entries))
    sort && sort!(entries)
    return st, entries
end

"Directory listing with per-entry StatInfo (one round trip when the server honors dstat)."
function dirlist_stat(fs::FileSystem, path::String)
    st, body = perform(fs, Wire.DirlistRequest(path; options=Wire.kXR_dstat))
    isOK(st) || return st, nothing, nothing
    listing = Wire.parse_dirlist(body)
    if listing.stats !== nothing
        stats = [StatInfo_from_parts(s) for s in listing.stats]
        return st, listing.entries, stats
    end
    # Server ignored kXR_dstat: fall back to one stat per entry.
    stats = StatInfo[]
    for name in listing.entries
        st_i, info = stat(fs, joinpath(path, name))
        isOK(st_i) || return st_i, nothing, nothing
        push!(stats, info)
    end
    return st, listing.entries, stats
end

function StatInfo_from_parts(s)
    octmode = s.has_ext ? symbolic_mode(s.mode) : ""
    return StatInfo(
        s.id, s.size, s.flags, s.mtime, s.ctime, s.atime, s.mode, octmode, s.owner, s.group
    )
end

"""
    Base.walkdir(fs::FileSystem, root::AbstractString; topdown=true)

Walk the directory tree rooted at `root`, yielding
`(path, dirs, files)` tuples like `Base.walkdir`. Errors close the channel
with an `ErrorException`.
"""
function Base.walkdir(fs::FileSystem, root::AbstractString; topdown::Bool=true)
    function _walkdir(chnl, dir)
        st, entries, stats = dirlist_stat(fs, dir)
        if !isOK(st)
            try
                throw(ErrorException("$st"))
            catch err
                close(chnl, err)
            end
            return nothing
        end
        dirs = String[]
        files = String[]
        for (name, info) in zip(entries, stats)
            push!(isdir(info) ? dirs : files, name)
        end
        topdown && push!(chnl, (dir, dirs, files))
        for d in dirs
            _walkdir(chnl, joinpath(dir, d))
        end
        topdown || push!(chnl, (dir, dirs, files))
        return nothing
    end
    return Channel{Tuple{String,Vector{String},Vector{String}}}(
        chnl -> _walkdir(chnl, String(root))
    )
end

"""
    Base.rm(fs::FileSystem, path::String, timeout::UInt16=0x0000)

Delete a file. Returns `(status, nothing)`.
"""
function Base.rm(fs::FileSystem, path::String, timeout::UInt16=0x0000)
    st, _ = perform(fs, Wire.RmRequest(path))
    return st, nothing
end

"""
    Base.mv(fs::FileSystem, src::String, dest::String, timeout::UInt16=0x0000)

Move or rename a file or directory. Returns `(status, nothing)`.
"""
function Base.mv(fs::FileSystem, src::String, dest::String, timeout::UInt16=0x0000)
    st, _ = perform(fs, Wire.MvRequest(src, dest))
    return st, nothing
end

"""
    Base.mkdir(fs::FileSystem, path::String, mode::Integer=Access.None,
               timeout::UInt16=0x0000)

Create a directory (no parents; the server rejects missing intermediate
directories). Returns `(status, nothing)`.
"""
function Base.mkdir(
    fs::FileSystem, path::String, mode::Integer=Access.None, timeout::UInt16=0x0000
)
    st, _ = perform(fs, Wire.MkdirRequest(path; mode=UInt16(mode)))
    return st, nothing
end

"""
    rmdir(fs::FileSystem, path::String, timeout::UInt16=0x0000)

Remove an empty directory. Returns `(status, nothing)`.
"""
function rmdir(fs::FileSystem, path::String, timeout::UInt16=0x0000)
    st, _ = perform(fs, Wire.RmdirRequest(path))
    return st, nothing
end

"""
    Base.chmod(fs::FileSystem, path::String, mode, timeout::UInt16=0x0000)

Change permission bits (`mode` is octal-style, e.g. `0o644`, or composed
`Access` flags — the encodings coincide). Returns `(status, nothing)`.
"""
function Base.chmod(fs::FileSystem, path::String, mode, timeout::UInt16=0x0000)
    st, _ = perform(fs, Wire.ChmodRequest(path, UInt16(mode)))
    return st, nothing
end

"""
    Base.truncate(fs::FileSystem, path::String, size::Int64, timeout::UInt16=0x0000)

Truncate a file to `size` bytes. Returns `(status, nothing)`.
"""
function Base.truncate(fs::FileSystem, path::String, size::Int64, timeout::UInt16=0x0000)
    st, _ = perform(fs, Wire.TruncateRequest(path, size))
    return st, nothing
end

"""
    protocol(fs::FileSystem, timeout::UInt16=0x0000)

Get the server's protocol information. Returns
`(status, ProtocolInfo | nothing)`.
"""
function protocol(fs::FileSystem, timeout::UInt16=0x0000)
    st, body = perform(fs, Wire.ProtocolRequest())
    isOK(st) || return st, nothing
    p = Wire.decode_protocol(body)
    return st, ProtocolInfo(p.pval, p.flags)
end

# ---- copy ----

const COPY_CHUNK = 1 << 20   # 1 MiB read/write pump chunks

"Open a file on `conn`; returns (status, fhandle)."
function open_file(conn::Session.Connection, path::String, options::UInt16, mode::UInt16)
    hdr, body = Session.roundtrip(conn, Wire.OpenRequest(path; mode=mode, options=options))
    st = status_from(hdr, body)
    isOK(st) || return st, nothing
    return st, Wire.decode_open(body).fhandle
end

function close_file(conn::Session.Connection, fhandle::NTuple{4,UInt8})
    hdr, body = Session.roundtrip(conn, Wire.CloseRequest(fhandle))
    return status_from(hdr, body)
end

"""
    Base.copy(fs::FileSystem, src::String, dest::String; force::Bool=false)

Copy a file server-side by pumping it through the client in
`$(COPY_CHUNK >> 20)` MiB chunks (the copy engine with parallel in-flight
chunks arrives in plan 07). `force` overwrites an existing destination.
Returns `(status, nothing)`.
"""
function Base.copy(fs::FileSystem, src::String, dest::String; force::Bool=false)
    conn = try
        connection!(fs)
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
    end

    st, src_fh = open_file(conn, src, Wire.kXR_open_read, 0x0000)
    src_fh === nothing && return st, nothing

    dst_options = Wire.kXR_open_updt | Wire.kXR_mkpath
    dst_options |= force ? Wire.kXR_delete : Wire.kXR_new
    st, dst_fh = open_file(conn, dest, dst_options, UInt16(0o644))
    if dst_fh === nothing
        close_file(conn, src_fh)
        return st, nothing
    end

    offset = Int64(0)
    st = XRootDStatus()
    while true
        hdr, body = Session.roundtrip(
            conn, Wire.ReadRequest(src_fh, offset, Int32(COPY_CHUNK))
        )
        st = status_from(hdr, body)
        (isError(st) || isempty(body)) && break
        whdr, wbody = Session.roundtrip(conn, Wire.WriteRequest(dst_fh, offset, body))
        st = status_from(whdr, wbody)
        isError(st) && break
        offset += length(body)
        length(body) < COPY_CHUNK && break
    end

    close_file(conn, src_fh)
    close_st = close_file(conn, dst_fh)
    isOK(st) && (st = close_st)
    return st, nothing
end
