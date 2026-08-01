# The FileSystem API — 0.2.x signatures over the native Session layer.
# Every operation returns `(XRootDStatus, result)`; `result` is `nothing`
# for mutations. `timeout` arguments are accepted for 0.2.x compatibility;
# per-request timeouts arrive with the resilience work (plan 05).

"""
    FileSystem(url::String; insecure_tls::Bool=false, kwargs...)

Handle for filesystem operations against an XRootD server, e.g.
`FileSystem("root://localhost:1094")`. The URL grammar is
`root://[user@]host[:port]` (`xroot://` is an accepted alias); a user named in
the URL becomes the login account. A `roots://` URL upgrades the connection to
TLS. Connects lazily on first use and reconnects if the connection is lost. `insecure_tls` skips certificate-chain verification
(self-signed test servers only).

Remaining keywords are credentials, forwarded to every connection this
handle makes: `token`, `keytab`, `cert`/`key` (X.509), `x509`
(see [`XRootD.Session.connect`](@ref)).
"""
mutable struct FileSystem
    url::String
    host::String
    port::Int
    want_tls::Bool
    insecure_tls::Bool
    creds::Dict{Symbol,Any}
    conn::Union{Session.Connection,Nothing}
end

function FileSystem(url::String, isServer::Bool=false; insecure_tls::Bool=false, kwargs...)
    u = Session.parse_root_url(url)
    creds = Dict{Symbol,Any}(kwargs)
    # A user named in the URL is the login account; an explicit keyword wins.
    isempty(u.username) || get!(creds, :username, u.username)
    return FileSystem(
        url, u.host, u.port, u.scheme == "roots", insecure_tls, creds, nothing
    )
end

"Connect lazily; reconnect when the previous connection died."
function connection!(fs::FileSystem)
    conn = fs.conn
    if conn === nothing || !isopen(conn)
        conn = Session.connect(
            fs.host,
            fs.port;
            want_tls=fs.want_tls,
            insecure_tls=fs.insecure_tls,
            fs.creds...,
        )
        fs.conn = conn
    end
    return conn
end

# Opcodes safe to replay after a transport failure without risk of a
# double-effect (reads and metadata queries). Mutations are replayed only
# when the request provably never reached the server (a connect failure
# before any bytes were sent).
const _IDEMPOTENT = Set{UInt16}([
    Wire.kXR_ping,
    Wire.kXR_stat,
    Wire.kXR_dirlist,
    Wire.kXR_locate,
    Wire.kXR_query,
    Wire.kXR_protocol,
    Wire.kXR_readlink,
    Wire.kXR_fattr,     # get/list are idempotent; set/del are too (last-writer-wins)
])

"Default reconnect+retry patience window (matches libxrdc XRDC_DEFAULT_MAX_STALL_MS)."
const DEFAULT_MAX_STALL_MS = 30_000

function max_stall_ms()
    v = get(ENV, "XRDC_MAX_STALL_MS", "")
    isempty(v) && return DEFAULT_MAX_STALL_MS
    n = tryparse(Int, v)
    return n === nothing ? DEFAULT_MAX_STALL_MS : n
end

"""
Run one request with redirect following and bounded reconnect-and-replay.
`kXR_redirect` steers the (fresh) connection to the target host; a transport
sever reconnects to the home endpoint and replays idempotent operations
within the stall window. Returns `(XRootDStatus, body)`.
"""
function perform(fs::FileSystem, req::Wire.Request; max_hops::Int=8)
    idempotent = Wire.requestid(req) in _IDEMPOTENT
    deadline = time() + max_stall_ms() / 1000
    hops = 0
    while true
        conn = try
            connection!(fs)
        catch err
            # Never connected: safe to retry any op while the window is open.
            (time() < deadline) && (sleep(0.2); continue)
            return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), UInt8[]
        end

        hdr, body = try
            Session.roundtrip(conn, req)
        catch err
            fs.conn = nothing
            if idempotent && time() < deadline
                sleep(0.2)
                continue
            end
            return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), UInt8[]
        end

        if hdr.status == Wire.kXR_redirect
            hops += 1
            hops > max_hops &&
                return XRootDStatus(hdr.status, 0, 0, "too many redirects"), body
            r = try
                Wire.decode_redirect(body)
            catch err
                # A redirect we cannot parse names no destination. Report it
                # as a failed operation rather than letting the decode throw
                # out of an API whose callers read statuses.
                return XRootDStatus(
                    0x0001,
                    0x0000,
                    0,
                    "malformed kXR_redirect: $(sprint(showerror, err))",
                ),
                body
            end
            isempty(r.host) &&
                return XRootDStatus(0x0001, 0x0000, 0, "kXR_redirect names no host"), body
            close(conn)
            fs.host = Session.unbracket(r.host)
            fs.port, fs.want_tls = redirect_endpoint(r, fs.port, fs.want_tls)
            fs.conn = nothing
            # The redirector's opaque data is meant for the target — most
            # often the token that makes the retried request acceptable there.
            req = Wire.with_cgi(req, r.cgi)
            continue
        end

        # A synthetic transport-loss status (our roundtrip signals it on the
        # closed connection): reconnect and replay when idempotent.
        if hdr.status == Wire.kXR_error &&
            is_transport_loss(body) &&
            idempotent &&
            time() < deadline
            fs.conn = nothing
            sleep(0.2)
            continue
        end

        return status_from(hdr, body), body
    end
end

"""
Where a `kXR_redirect` points, given the endpoint the client is on now.

A negative port is how the protocol says "and speak TLS there": the target
port is its magnitude (XRootD ≥ 5, which is also how a manager sends a client
to a `roots://` data server). A zero port names no port, so the current one
stands. TLS never goes back off — a client that asked for `roots://` is not
downgraded because a redirector happened to send a positive port.
"""
function redirect_endpoint(r, port::Int, want_tls::Bool)
    target = Int(r.port)
    target == 0 && return port, want_tls
    target < 0 && return -target, true
    return target, want_tls
end

"Recognize the reader task's synthetic connection-lost error body."
function is_transport_loss(body::AbstractVector{UInt8})
    length(body) < 4 && return false
    return occursin("lost", Wire.decode_error(body).message)
end

"""
    decoded(f, st, body) -> (XRootDStatus, result | nothing)

Decode a response body with `f`, reporting a malformed reply as an error
status rather than an exception. A server's bytes are untrusted input and
callers of this API read statuses: a listing with an unpaired stat line or a
truncated stat must fail the operation, not the caller.
"""
function decoded(f::Function, st::XRootDStatus, body::AbstractVector{UInt8})
    try
        return st, f(body)
    catch err
        (err isa ArgumentError || err isa BoundsError) || rethrow()
        return XRootDStatus(
            Wire.kXR_error, 0x0000, 0, "malformed response: $(sprint(showerror, err))"
        ),
        nothing
    end
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
    return decoded(st, body) do b
        return StatInfo(String(copy(b)))
    end
end

"""
    locate(fs::FileSystem, path::String, flags::Integer, timeout::UInt16=0x0000)

List the locations of a file or directory (`flags` from `OpenFlags`, e.g.
`OpenFlags.Refresh`). Returns `(status, Vector{Location} | nothing)`.
"""
function locate(fs::FileSystem, path::String, flags::Integer, timeout::UInt16=0x0000)
    st, body = perform(fs, Wire.LocateRequest(path; options=UInt16(flags)))
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        return [Location(t.address, t.node, t.access) for t in Wire.parse_locate(b)]
    end
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
    return decoded(st, body) do b
        entries = Wire.parse_dirlist(b).entries
        join && (entries = joinpath.(Ref(path), entries))
        sort && sort!(entries)
        return entries
    end
end

"Directory listing with per-entry StatInfo (one round trip when the server honors dstat)."
function dirlist_stat(fs::FileSystem, path::String)
    st, body = perform(fs, Wire.DirlistRequest(path; options=Wire.kXR_dstat))
    isOK(st) || return st, nothing, nothing
    st, listing = decoded(Wire.parse_dirlist, st, body)
    listing === nothing && return st, nothing, nothing
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
               timeout::UInt16=0x0000; mkpath::Bool=false)

Create a directory. Missing intermediate directories are rejected by the
server unless `mkpath` is set (`kXR_mkdirpath`). Returns `(status, nothing)`.
"""
function Base.mkdir(
    fs::FileSystem,
    path::String,
    mode::Integer=Access.None,
    timeout::UInt16=0x0000;
    mkpath::Bool=false,
)
    st, _ = perform(fs, Wire.MkdirRequest(path; mode=UInt16(mode), mkpath=mkpath))
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
    return decoded(st, body) do b
        p = Wire.decode_protocol(b)
        return ProtocolInfo(p.pval, p.flags)
    end
end

# ---- copy ----

const COPY_CHUNK = 1 << 20   # 1 MiB read/write pump chunks

"Open a file on `conn`; returns (status, fhandle)."
function open_file(conn::Session.Connection, path::String, options::UInt16, mode::UInt16)
    hdr, body = Session.roundtrip(conn, Wire.OpenRequest(path; mode=mode, options=options))
    st = status_from(hdr, body)
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        return Wire.decode_open(b).fhandle
    end
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

# ---- extended operations (plan 05) ----

"An attribute-level `kXR_fattr` failure, which the request status reports as success."
function fattr_error(name::AbstractString, rc::Integer)
    return XRootDStatus(
        Wire.kXR_error, UInt16(rc), 0, "attribute $(repr(String(name))): kXR error $(rc)"
    )
end

"""
    fattr_rc(st, body, name) -> XRootDStatus

Promote the per-attribute status of a `kXR_fattr` Get/Set/Del reply into the
operation status. The request-level status is `kXR_ok` even when the attribute
itself failed (a missing name gives `kXR_AttrNotFound`), so ignoring the nvec
`rc` would report a no-op as a success (libxrdc `fattr.c`).
"""
function fattr_rc(st::XRootDStatus, body::AbstractVector{UInt8}, name::AbstractString)
    st, rc = decoded(Wire.parse_fattr_status, st, body)
    rc === nothing && return st
    return rc == 0 ? st : fattr_error(name, rc)
end

"""
    getxattr(fs::FileSystem, path::String, name::String)

Read one extended attribute. Returns `(status, Vector{UInt8} | nothing)`.
"""
function getxattr(fs::FileSystem, path::String, name::String)
    st, body = perform(fs, Wire.FattrRequest(Wire.kXR_fattrGet, path; names=[name]))
    isOK(st) || return st, nothing
    st = fattr_rc(st, body, name)
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        return Wire.parse_fattr_get(b, 1)[1].value
    end
end

"""
    setxattr(fs::FileSystem, path::String, name::String, value::Vector{UInt8})

Create or overwrite one extended attribute. Returns `(status, nothing)`.
"""
function setxattr(fs::FileSystem, path::String, name::String, value::Vector{UInt8})
    st, body = perform(
        fs, Wire.FattrRequest(Wire.kXR_fattrSet, path; names=[name], values=[value])
    )
    isOK(st) || return st, nothing
    return fattr_rc(st, body, name), nothing
end

"""
    listxattr(fs::FileSystem, path::String)

List extended-attribute names. Returns `(status, Vector{String} | nothing)`.
"""
function listxattr(fs::FileSystem, path::String)
    st, body = perform(fs, Wire.FattrRequest(Wire.kXR_fattrList, path))
    isOK(st) || return st, nothing
    return st, Wire.parse_fattr_list(body)
end

"""
    removexattr(fs::FileSystem, path::String, name::String)

Delete one extended attribute. Returns `(status, nothing)`.
"""
function removexattr(fs::FileSystem, path::String, name::String)
    st, body = perform(fs, Wire.FattrRequest(Wire.kXR_fattrDel, path; names=[name]))
    isOK(st) || return st, nothing
    return fattr_rc(st, body, name), nothing
end

"""
    statvfs(fs::FileSystem, path::String)

Query virtual-filesystem (space) information. Returns
`(status, NamedTuple | nothing)` with `raw`/`nodes`/`free_kb`/`utilization`.
"""
function statvfs(fs::FileSystem, path::String)
    st, body = perform(fs, Wire.StatRequest(path; options=Wire.kXR_vfs))
    isOK(st) || return st, nothing
    return st, Wire.parse_statvfs(body)
end

"""
    checksum(fs::FileSystem, path::String)

Query the server's checksum for `path` (`kXR_query`/`kXR_Qcksum`). Returns
`(status, String | nothing)` — typically `"<algo> <hexdigest>"`.
"""
function checksum(fs::FileSystem, path::String)
    st, body = perform(fs, Wire.QueryRequest(Wire.kXR_Qcksum, path))
    isOK(st) || return st, nothing
    return st, rstrip(String(copy(body)), '\0')
end

"""
    prepare(fs::FileSystem, paths::Vector{String}; stage=true, evict=false, cancel=false)

Issue a `kXR_prepare` for `paths`. Returns `(status, String | nothing)`
(the response is an opaque request handle for staging).
"""
function prepare(
    fs::FileSystem,
    paths::Vector{String};
    stage::Bool=true,
    evict::Bool=false,
    cancel::Bool=false,
)
    options = 0x00
    stage && (options |= Wire.kXR_stage)
    cancel && (options |= Wire.kXR_cancel)
    optionX = evict ? UInt16(0x0001) : UInt16(0x0000)
    st, body = perform(fs, Wire.PrepareRequest(paths; options, optionX))
    isOK(st) || return st, nothing
    return st, rstrip(String(copy(body)), '\0')
end

"""
    symlink(fs::FileSystem, target::String, link::String)

Create a symbolic link `link` → `target` (vendor extension; requires a
server advertising `xrdfs.ext`). Returns `(status, nothing)`.
"""
function symlink(fs::FileSystem, target::String, link::String)
    st, _ = perform(fs, Wire.SymlinkRequest(target, link))
    return st, nothing
end

"""
    hardlink(fs::FileSystem, oldpath::String, newpath::String)

Create a hard link `newpath` → `oldpath` (vendor extension). Returns
`(status, nothing)`.
"""
function hardlink(fs::FileSystem, oldpath::String, newpath::String)
    st, _ = perform(fs, Wire.LinkRequest(oldpath, newpath))
    return st, nothing
end

"""
    readlink(fs::FileSystem, path::String)

Read a symbolic link's target (vendor extension). Returns
`(status, String | nothing)`.
"""
function readlink(fs::FileSystem, path::String)
    st, body = perform(fs, Wire.ReadlinkRequest(path))
    isOK(st) || return st, nothing
    return st, rstrip(String(copy(body)), '\0')
end
