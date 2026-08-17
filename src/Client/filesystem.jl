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

"""
A handle prints the endpoint it talks to and the *kinds* of credential it was
given, never the credentials themselves: a `FileSystem` reaches an exception
message, a `@show`, or a log line far more often than anyone intends, and one
of those is enough to leak a bearer token
([`XRootD.Session.redact`](@ref)).
"""
function Base.show(io::IO, fs::FileSystem)
    print(io, "FileSystem(", repr(Session.redact_url(fs.url)))
    fs.want_tls && print(io, ", tls")
    fs.insecure_tls && print(io, ", insecure_tls")
    isempty(fs.creds) || print(io, ", ", Session.redact(fs.creds))
    print(io, fs.conn === nothing ? ", unconnected" : ", connected")
    return print(io, ")")
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
    Wire.kXR_statx,
    Wire.kXR_fattr,     # get/list are idempotent; set/del are too (last-writer-wins)
])

"""
Default reconnect+retry patience window (matches libxrdc
XRDC_DEFAULT_MAX_STALL_MS). The window bounds how long an operation may keep
trying; [`XRootD.Session.max_retries`](@ref) bounds how *often* inside it.
"""
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

Retries back off ([`XRootD.Session.backoff!`](@ref)) and are bounded twice
over — by the window and by the attempt count — so a peer that refuses
instantly cannot be asked hundreds of times inside the window, and a fleet
that lost the same server does not come back to it in one burst.

A redirect is not a retry: following one is the protocol working, so it spends
the hop budget rather than the retry budget.
"""
function perform(fs::FileSystem, req::Wire.Request; max_hops::Int=Session.redirect_limit())
    idempotent = Wire.requestid(req) in _IDEMPOTENT
    deadline = time() + max_stall_ms() / 1000
    hops = 0
    attempt = 0
    while true
        conn = try
            connection!(fs)
        catch err
            # Never connected: safe to retry any op while the budget holds.
            attempt += 1
            Session.backoff!(attempt, deadline) && continue
            return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), UInt8[]
        end

        hdr, body = try
            Session.roundtrip(conn, req)
        catch err
            fs.conn = nothing
            attempt += 1
            if idempotent && Session.backoff!(attempt, deadline)
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
        if hdr.status == Wire.kXR_error && is_transport_loss(body) && idempotent
            attempt += 1
            if Session.backoff!(attempt, deadline)
                fs.conn = nothing
                continue
            end
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
    Base.lstat(fs::FileSystem, path::String, timeout::UInt16=0x0000)

Stat `path` without following it: a symlink stats as the link itself rather
than as its target (`kXR_statNoFollow`). Returns
`(status, StatInfo | nothing)`.
"""
function Base.lstat(fs::FileSystem, path::String, timeout::UInt16=0x0000)
    st, body = perform(fs, Wire.StatRequest(path; options=Wire.kXR_statNoFollow))
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        return StatInfo(String(copy(b)))
    end
end

"""
    statx(fs::FileSystem, paths::Vector{String})

Stat many paths in one exchange (`kXR_statx`). The answer is one
[`StatFlags`](@ref) per path, in the order asked — type and access bits only,
which is what makes a whole directory's worth of names one round trip instead
of one each. Returns `(status, Vector{StatFlags} | nothing)`.
"""
function statx(fs::FileSystem, paths::Vector{String})
    isempty(paths) && return XRootDStatus(), StatFlags[]
    st, body = perform(fs, Wire.StatxRequest(paths))
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        return [StatFlags(f) for f in Wire.parse_statx(b, length(paths))]
    end
end

"""
    locate(fs::FileSystem, path::String, flags::Integer, timeout::UInt16=0x0000)

List the locations of a file or directory (`flags` from `OpenFlags`, e.g.
`OpenFlags.Refresh`). Returns `(status, Vector{Location} | nothing)`.

The path goes to the server verbatim, which includes XrdCl's convention of
prefixing it with `*` — `"*/store/f.root"` asks a redirector to pick a server
where the file *could be created* rather than failing because it does not
exist yet, and `"*"` alone asks for any server at all.
"""
function locate(fs::FileSystem, path::String, flags::Integer, timeout::UInt16=0x0000)
    st, body = perform(fs, Wire.LocateRequest(path; options=UInt16(flags)))
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        return [Location(t.address, t.node, t.access) for t in Wire.parse_locate(b)]
    end
end

"`true` when a `locate` answer names a manager rather than a data server."
ismanager(l::Location) = l.node in ('M', 'm')

"`true` when a `locate` answer names a data server."
isserver(l::Location) = !ismanager(l)

"""
Split a `locate` answer's `host:port` (or `[v6]:port`) address, falling back
to `port` when it names none.
"""
function split_address(address::AbstractString, port::Int)
    parts = rsplit(address, ':'; limit=2)
    length(parts) == 2 || return Session.unbracket(address), port
    p = tryparse(Int, parts[2])
    p === nothing && return Session.unbracket(address), port
    return Session.unbracket(parts[1]), p
end

"A handle for one of `fs`'s subordinates, carrying the same TLS choice and credentials."
function subordinate(fs::FileSystem, l::Location)
    host, port = split_address(l.address, fs.port)
    scheme = fs.want_tls ? "roots" : "root"
    return FileSystem(
        "$scheme://$(l.address)",
        host,
        port,
        fs.want_tls,
        fs.insecure_tls,
        copy(fs.creds),
        nothing,
    )
end

"""
    deep_locate(fs::FileSystem, path::String, flags::Integer=OpenFlags.None)

Locate `path` across the whole federation, resolving managers down to the
data servers behind them: every manager in the answer is asked the same
question in turn, and only the servers survive into the result. A plain
`locate` against a redirector names the redirector, which is rarely what the
caller wanted to know. Returns `(status, Vector{Location} | nothing)`.

A subordinate that cannot be reached is skipped rather than failing the
whole call — a federation with a node down still knows where the other
replicas are.
"""
function deep_locate(fs::FileSystem, path::String, flags::Integer=OpenFlags.None)
    st, roots = locate(fs, path, flags)
    isOK(st) || return st, nothing
    seen = Dict{String,Location}()
    order = String[]
    pending = collect(roots)
    while !isempty(pending)
        loc = popfirst!(pending)
        known = get(seen, loc.address, nothing)
        if known !== nothing
            # A supervisor answers as a manager to the tier above it and as a
            # server to the tier below; keeping only the first answer would
            # drop a node that does hold the file.
            ismanager(known) && !ismanager(loc) && (seen[loc.address] = loc)
            continue
        end
        seen[loc.address] = loc
        push!(order, loc.address)
        ismanager(loc) || continue
        child = subordinate(fs, loc)
        cst, kids = locate(child, path, flags)
        close(child)
        isOK(cst) && kids !== nothing && append!(pending, kids)
    end
    return st, [seen[a] for a in order if !ismanager(seen[a])]
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
    query_config(fs::FileSystem, names::AbstractString...)

Look up server configuration values (`kXR_query`/`kXR_Qconfig`): one value
per name asked, newline-separated in the same order. Returns
`(status, Dict{String,String} | nothing)`.

A name the server has no value for is absent from the result, the way a
missing key is absent from a `Dict`. Splitting on `\\n` rather than by lines
keeps the remaining names lined up with their values when an earlier one
comes back empty.
"""
function query_config(fs::FileSystem, names::AbstractString...)
    wanted = isempty(names) ? ["version"] : collect(String, names)
    st, body = perform(fs, Wire.QueryRequest(Wire.kXR_Qconfig, join(wanted, "\n")))
    isOK(st) || return st, nothing
    values = split(rstrip(String(copy(body)), '\0'), '\n')
    return st,
    Dict{String,String}(
        name => String(strip(value)) for
        (name, value) in zip(wanted, values) if !isempty(strip(value))
    )
end

"""
    set_property(fs::FileSystem, directive::AbstractString)

Set a server-side property of this connection (`kXR_set`). Returns
`(status, nothing)`. See [`appid`](@ref) for the directive every client
sends.
"""
function set_property(fs::FileSystem, directive::AbstractString)
    st, _ = perform(fs, Wire.SetRequest(directive))
    return st, nothing
end

"""
    appid(fs::FileSystem, name::AbstractString)

Label this connection in the server's monitoring stream, so an operator
looking at the server can tell whose traffic it is. Returns
`(status, nothing)`.
"""
appid(fs::FileSystem, name::AbstractString) = set_property(fs, "appid $name")

"""
    endsess(fs::FileSystem)

End the server's session for this connection (`kXR_endsess`), releasing its
state instead of leaving it to time out. Returns `(status, nothing)`.

The connection is not usable afterwards, so it is dropped: the next
operation on `fs` opens a fresh one.
"""
function endsess(fs::FileSystem)
    conn = fs.conn
    conn === nothing && return XRootDStatus(), nothing
    st, _ = perform(fs, Wire.EndsessRequest(conn.sessid))
    close(conn)
    fs.conn = nothing
    return st, nothing
end

"""
    Base.close(fs::FileSystem)

Drop the connection this handle holds. A later operation reconnects, so this
releases the server's resources without invalidating `fs`.
"""
function Base.close(fs::FileSystem)
    conn = fs.conn
    conn === nothing || close(conn)
    fs.conn = nothing
    return nothing
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

"""
    dirlist_checksum(fs::FileSystem, path::String; algorithm::AbstractString="")

List a directory with a checksum per entry (`kXR_dcksm`). Returns
`(status, entries, stats, cksums)`, where `cksums[i]` is the
`(; algorithm, value)` the server computed for `entries[i]` — or `nothing`
for an entry it had no digest for, a directory being the usual reason.

`algorithm` (`"adler32"`, `"crc32c"`, `"md5"`, `"sha1"`, `"sha256"`, ...)
rides in as the `cks.type=` CGI, the same selector [`checksum`](@ref) uses;
without it the server picks its default. An algorithm the server does not
have is an error on the whole listing, not a per-entry `nothing`.

`kXR_dcksm` implies `kXR_dstat`, so the stat lines come back too — in the
extended nine-field form the checksum token is appended to.

A server that ignored the option answers `cksums === nothing`. That is
reported as it stands rather than papered over with one [`checksum`](@ref)
query per entry: digesting a directory is work the caller should ask for
knowingly, unlike the per-entry `stat` [`dirlist_stat`](@ref) falls back on.
"""
function dirlist_checksum(fs::FileSystem, path::String; algorithm::AbstractString="")
    req = Wire.DirlistRequest(
        cksum_path(path, algorithm); options=Wire.kXR_dstat | Wire.kXR_dcksm
    )
    st, body = perform(fs, req)
    isOK(st) || return st, nothing, nothing, nothing
    st, listing = decoded(Wire.parse_dirlist, st, body)
    listing === nothing && return st, nothing, nothing, nothing
    parts = listing.stats
    stats = if parts === nothing
        nothing
    else
        StatInfo[StatInfo_from_parts(s) for s in parts]
    end
    return st, listing.entries, stats, listing.cksums
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
    Base.ispath(fs::FileSystem, path::String) -> Bool

`true` when `path` exists. A server that answers `kXR_NotFound` says so;
any other failure — unreachable, unauthorized — is not an answer about
existence and throws.
"""
function Base.ispath(fs::FileSystem, path::String)
    st, _ = stat(fs, path)
    isOK(st) && return true
    st.code == ErrorCode.NotFound && return false
    return throw(ErrorException("cannot tell whether $(repr(path)) exists: $st"))
end

"""
    exists_error(st::XRootDStatus) -> Bool

Whether `st` is a server saying "it is already there". `EEXIST` canonically
maps to `kXR_ItExists`, but not every server agrees — nginx-xrootd's open
handler answers `kXR_FileLocked` with the same meaning — so an operation
that treats existence as success has to accept both.
"""
function exists_error(st::XRootDStatus)
    return st.code == ErrorCode.ItExists || st.code == ErrorCode.FileLocked
end

"""
    Base.isdir(fs::FileSystem, path::String) -> Bool

`true` when `path` exists and is a directory.
"""
function Base.isdir(fs::FileSystem, path::String)
    st, info = stat(fs, path)
    return isOK(st) && isdir(info)
end

"""
    Base.isfile(fs::FileSystem, path::String) -> Bool

`true` when `path` exists and is a regular file.
"""
function Base.isfile(fs::FileSystem, path::String)
    st, info = stat(fs, path)
    return isOK(st) && isfile(info)
end

"""
    Base.filesize(fs::FileSystem, path::String) -> Int64

The size of `path` in bytes, or `-1` when it cannot be stat'd — the same
answer shape as `Base.filesize` on an unreadable local path.
"""
function Base.filesize(fs::FileSystem, path::String)
    st, info = stat(fs, path)
    return isOK(st) ? info.size : Int64(-1)
end

"""
    Base.touch(fs::FileSystem, path::String, mode::Integer=0o644)

Create `path` if it is not there, leaving an existing file alone (and its
contents untouched — this is not a truncating open). Returns
`(status, nothing)`.

There is no wire operation for "update the mtime", so an existing file is
left exactly as it is rather than being rewritten to move its timestamp.
"""
function Base.touch(fs::FileSystem, path::String, mode::Integer=0o644)
    conn = try
        connection!(fs)
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
    end
    options = Wire.kXR_open_updt | Wire.kXR_new
    st, fhandle = open_file(conn, path, options, UInt16(mode))
    if fhandle === nothing
        # Already there is the outcome `touch` wanted, not a failure.
        exists_error(st) && return XRootDStatus(), nothing
        return st, nothing
    end
    return close_file(conn, fhandle), nothing
end

"""
    Base.rm(fs::FileSystem, path::String, timeout::UInt16=0x0000; recursive::Bool=false)

Delete a file, or with `recursive` a whole tree — depth-first, so a
directory is only removed once it is empty. Returns `(status, nothing)`.

A recursive removal stops at the first failure and reports it, leaving what
it has already deleted deleted: there is no wire operation that would let it
be undone, and continuing past an error would only widen the damage.
"""
function Base.rm(
    fs::FileSystem, path::String, timeout::UInt16=0x0000; recursive::Bool=false
)
    recursive && return rmtree(fs, path)
    st, _ = perform(fs, Wire.RmRequest(path))
    return st, nothing
end

"Depth-first removal of `path` and everything below it."
function rmtree(fs::FileSystem, path::String)
    st, entries, stats = dirlist_stat(fs, path)
    if !isOK(st)
        # Not a directory: the plain file case, which is one request.
        st_f, _ = perform(fs, Wire.RmRequest(path))
        return st_f, nothing
    end
    for (name, info) in zip(entries, stats)
        child = joinpath(path, name)
        cst, _ = isdir(info) ? rmtree(fs, child) : rm(fs, child)
        isOK(cst) || return cst, nothing
    end
    return rmdir(fs, path)
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
    Base.mkpath(fs::FileSystem, path::String, mode::Integer=Access.None)

Create `path` and every missing directory above it, and succeed when it is
already there. Returns `(status, nothing)`.

One request: `kXR_mkdir`/`kXR_mkdirpath` is what makes the parents, so this
is `mkdir` with the flag set and `kXR_ItExists` swallowed — not a walk up
the path testing each component.
"""
function Base.mkpath(fs::FileSystem, path::String, mode::Integer=Access.None)
    st, _ = mkdir(fs, path, mode; mkpath=true)
    exists_error(st) && return XRootDStatus(), nothing
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
    xattrs(fs::FileSystem, path::String)

Every extended attribute of `path` at once. Returns
`(status, Dict{String,Vector{UInt8}} | nothing)`.

Two round trips — `kXR_fattrList` for the names, then one `kXR_fattrGet` for
all of them — because the list reply carries names only. A path with no
attributes answers with an empty dict, not a failure.

The Get reply's values come back in the order they were asked for, which is
what pairs them with the names again; an attribute that failed individually
(deleted between the two calls, say) is left out rather than reported as
empty.
"""
function xattrs(fs::FileSystem, path::String)
    st, names = listxattr(fs, path)
    isOK(st) || return st, nothing
    isempty(names) && return st, Dict{String,Vector{UInt8}}()
    st, body = perform(fs, Wire.FattrRequest(Wire.kXR_fattrGet, path; names=names))
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        attrs = Wire.parse_fattr_get(b, length(names))
        return Dict{String,Vector{UInt8}}(
            name => a.value for (name, a) in zip(names, attrs) if a.rc == 0
        )
    end
end

"""
    cksum_path(path, algorithm) -> String

Append the `cks.type=` CGI that selects a checksum algorithm, respecting a
query string the path already carries. An empty `algorithm` leaves the path
alone and takes whatever the server has configured as its default.
"""
function cksum_path(path::AbstractString, algorithm::AbstractString)
    isempty(algorithm) && return String(path)
    sep = occursin('?', path) ? '&' : '?'
    return "$(path)$(sep)cks.type=$(algorithm)"
end

"""
    checksum(fs::FileSystem, path::String; algorithm::AbstractString="")

Query the server's checksum for `path` (`kXR_query`/`kXR_Qcksum`). Returns
`(status, String | nothing)` — typically `"<algo> <hexdigest>"`.

`algorithm` (`"adler32"`, `"md5"`, `"crc32c"`, ...) picks one of the digests
the server supports; without it the server answers with its default.
"""
function checksum(fs::FileSystem, path::String; algorithm::AbstractString="")
    st, body = perform(fs, Wire.QueryRequest(Wire.kXR_Qcksum, cksum_path(path, algorithm)))
    isOK(st) || return st, nothing
    return st, rstrip(String(copy(body)), '\0')
end

"""
    checksum_cancel(fs::FileSystem, path::String)

Withdraw a checksum the server is still computing
(`kXR_query`/`kXR_Qckscan`). Returns `(status, nothing)`.
"""
function checksum_cancel(fs::FileSystem, path::String)
    st, _ = perform(fs, Wire.QueryRequest(Wire.kXR_Qckscan, path))
    return st, nothing
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
    evict(fs::FileSystem, paths::Vector{String})

Ask the server to drop `paths` from its disk cache, the opposite of staging
them in. Returns `(status, String | nothing)`.

`prepare` with the evict bit and without `kXR_stage`: asking to stage and to
evict in one request would be asking the server to undo the same request.
"""
evict(fs::FileSystem, paths::Vector{String}) = prepare(fs, paths; stage=false, evict=true)

"""
    gpfile(fs::FileSystem, path::String; options::Integer=0, buffsz::Integer=0)

Send a `kXR_gpfile` — "grouped parallel fetch" — for `path`. Returns
`(status, Vector{UInt8} | nothing)`: the reply body as it arrives, because
the request has no documented answer to decode.

Expect `kXR_Unsupported`. The opcode was retired in XRootD v5 and no server
this package was checked against implements it; upstream's own request
struct carries the comment `// ??? This is all wrong; correct when
implemented`, so what goes on the wire here is that declaration taken
literally ([`Wire.GPFileRequest`](@ref)) rather than a guess dressed up as a
protocol. `readv` is what the operation's purpose became, and
[`readv`](@ref) is what a caller wanting several extents in one round trip
should use.

Two things are still worth doing before the refusal comes back. A server
that would answer says so with `kXR_supgpf` — [`supports_gpfile`](@ref) of a
[`protocol`](@ref) reply — so a caller can ask first. And a server that set
`kXR_tlsGPF` has said this request in particular must travel encrypted: on a
cleartext session it is refused here rather than sent, the same rule the
session-wide TLS demands follow.
"""
function gpfile(fs::FileSystem, path::String; options::Integer=0, buffsz::Integer=0)
    conn = try
        connection!(fs)
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
    end
    if (conn.flags & Wire.kXR_tlsGPF) != 0 && !Session.istls(conn)
        return XRootDStatus(
            Wire.kXR_error,
            ErrorCode.TLSRequired,
            0,
            "$(fs.host):$(fs.port) requires TLS for kXR_gpfile (kXR_tlsGPF)",
        ),
        nothing
    end
    st, body = perform(fs, Wire.GPFileRequest(path; options=options, buffsz=buffsz))
    isOK(st) || return st, nothing
    return st, body
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
