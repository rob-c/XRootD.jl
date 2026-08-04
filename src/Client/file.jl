# The File API — 0.2.x semantics (including its cursor rules) over the
# native Session layer, plus the v5 parity additions: sync, vector reads and
# writes, and CRC32c-verified paged I/O.

"""
    File()
    File(url::String, flags=0x0000, mode=0x0000) -> File | nothing

A remote file. The one-argument constructors open
`root://[user@]host[:port]//path` immediately and return `nothing` when the
open fails (0.2.x contract); `File()` creates a closed handle for use with
[`Base.open`](@ref).

The read cursor follows the 0.2.x rules: `read` does NOT advance it (an
explicit `offset` repositions it); `readline`/`readlines` advance it;
[`eof`](@ref Base.eof) compares it against the size captured at open.

The open is remembered — url, resolved options, mode and connection
keywords — so that a handle lost with its connection can be reopened
([`reopen!`](@ref)).

A file opened with `conn` borrows that session instead of dialing one of its
own, which is what puts two handles on one connection — the precondition
[`clone`](@ref) has. A borrowed connection outlives the file: closing the
file closes its handle and leaves the session to whoever opened it.
"""
mutable struct File
    conn::Union{Session.Connection,Nothing}
    fhandle::NTuple{4,UInt8}
    currentOffset::Int64
    filesize::Int64
    isopen::Bool
    url::String
    options::UInt16
    mode::UInt16
    opts::Dict{Symbol,Any}
    cpsize::Int32
    # The extra kXR_bind data sub-streams this file's bulk I/O rides on (empty =
    # the control link only). `data_streams` (default 1) binds these at open;
    # `rr` round-robins reads and writes across the live ones per request.
    pathids::Vector{UInt8}
    rr::Int
    owns_conn::Bool
end

function File()
    return File(
        nothing,
        Wire.NULL_FHANDLE,
        0,
        0,
        false,
        "",
        0x0000,
        0x0000,
        Dict{Symbol,Any}(),
        0,
        UInt8[],
        0,
        true,
    )
end

function File(url::String, flags=0x0000, mode=0x0000; kwargs...)
    f = File()
    st, _ = open(f, url, flags, mode; kwargs...)
    return isOK(st) ? f : nothing
end

"""
Like [`show(::IO, ::FileSystem)`](@ref), the open keywords are printed by name
and not by value: `opts` is kept for reopening after a lost connection, so it
holds whatever credential the file was opened with.
"""
function Base.show(io::IO, f::File)
    print(io, "File(", repr(Session.redact_url(f.url)))
    print(io, f.isopen ? ", open at $(f.currentOffset)/$(f.filesize)" : ", closed")
    isempty(f.opts) || print(io, ", ", Session.redact(f.opts))
    return print(io, ")")
end

"Parse `root://[user@]host[:port]//path` into (host, port, path)."
function parse_file_url(url::AbstractString)
    u = file_url(url)
    return u.host, u.port, u.path
end

"The parsed form of a file URL: like [`Session.parse_root_url`](@ref), but a
file is a path, so a URL that names none is not one."
function file_url(url::AbstractString)
    u = Session.parse_root_url(url)
    isempty(u.path) && throw(ArgumentError("no path in file URL: $(repr(url))"))
    return u
end

closed_status() = XRootDStatus(0x0001, 0x0000, 0, "file is not open")

# Requests a read-only handle may replay after its connection was reopened.
const _FILE_IDEMPOTENT = Set{UInt16}([
    Wire.kXR_read, Wire.kXR_readv, Wire.kXR_pgread, Wire.kXR_stat, Wire.kXR_query
])

"""
Run one request on the file's connection, mapping failures to statuses.
`maxbytes` bounds the reply the Session layer will accumulate (0 = unbounded);
every read passes the largest reply its request can legitimately produce.

A read on a handle whose connection has gone is retried against a reopened
handle ([`reopen!`](@ref)) — the file handle the request carries is stale by
then, so the request is rebuilt around the new one.
"""
function fperform(f::File, req::Wire.Request; maxbytes::Integer=0)
    f.isopen || return closed_status(), UInt8[]
    conn = f.conn
    conn === nothing && return closed_status(), UInt8[]
    hdr, body = try
        Session.roundtrip(conn, req; maxbytes=maxbytes)
    catch err
        return retry_reopened(f, req, maxbytes, sprint(showerror, err))
    end
    if hdr.status == Wire.kXR_error && is_transport_loss(body)
        return retry_reopened(f, req, maxbytes, status_from(hdr, body).message)
    end
    return status_from(hdr, body), body
end

"""
Replay `req` on a reopened handle until it answers or the retry budget runs
out; `message` is the loss to report if it never does. The budget is the
FileSystem lane's — the same window ([`max_stall_ms`](@ref)), the same attempt
count and backoff ([`XRootD.Session.backoff!`](@ref)) — because a link that
flaps once usually flaps again, and one replay lands in the same gap that
killed the first attempt.

Only a read-only handle qualifies ([`recoverable`](@ref)), and only for the
requests that can be replayed without a second effect: reopening a handle that
was being written to would discard what the writer had already put there.
"""
function retry_reopened(f::File, req::Wire.Request, maxbytes::Integer, message::String)
    lost = XRootDStatus(0x0001, 0x0000, 0, message)
    (Wire.requestid(req) in _FILE_IDEMPOTENT && recoverable(f)) || return lost, UInt8[]
    deadline = time() + max_stall_ms() / 1000
    attempt = 0
    while true
        attempt += 1
        # Every replay is a retry, including the first: the link went away a
        # moment ago, and coming straight back is how a whole farm rediscovers
        # the same dead server at the same instant.
        Session.backoff!(attempt, deadline) || return lost, UInt8[]
        answer = replay_once(f, req, maxbytes)
        answer === nothing || return answer
    end
end

"""
One reopen-and-replay: the answer, or `nothing` when the handle could not be
recovered or lost its connection again — which is a retryable failure, not a
result to hand back.
"""
function replay_once(f::File, req::Wire.Request, maxbytes::Integer)
    isOK(reopen!(f)) || return nothing
    conn = f.conn
    conn === nothing && return nothing
    # The replay drops any data path with the handle: both belonged to the
    # session that went away, and the reopened one has bound neither.
    replay = Wire.with_fhandle(Wire.without_pathid(req), f.fhandle)
    hdr, body = try
        Session.roundtrip(conn, replay; maxbytes=maxbytes)
    catch
        return nothing
    end
    hdr.status == Wire.kXR_error && is_transport_loss(body) && return nothing
    return status_from(hdr, body), body
end

"""
    Base.open(f::File, url::String, flags=0x0000, mode=0x0000; conn=nothing)

Open `url` on `f`. `flags` composes `OpenFlags` (an open with no access
bits requests `OpenFlags.Read`); `mode` sets permission bits for created
files. Keywords are forwarded to [`XRootD.Session.connect`](@ref) —
`insecure_tls`, `token`, `keytab`, `cert`/`key`. Returns `(status, nothing)`.

A `kXR_redirect` answer is followed for up to `max_hops` hops
(`\$XRD_REDIRECTLIMIT`, default 8): opening through a manager is the normal
way a client reaches a data server, and the redirector's opaque data travels
with the path to the target.

`conn` opens the file on a session that is already up — the connection
keywords are then not used, and the file does not close the session when it
closes. A file handle is only valid on the connection that issued it, so
this is how two handles come to be usable together, as [`clone`](@ref)
requires. A redirect cannot be followed on a borrowed session: leaving it
would defeat the reason it was borrowed, so the open fails instead.
"""
function Base.open(
    f::File,
    url::String,
    flags=0x0000,
    mode=0x0000;
    max_hops::Int=Session.redirect_limit(),
    conn::Union{Session.Connection,Nothing}=nothing,
    data_streams::Integer=Session.data_streams(),
    kwargs...,
)
    f.isopen && return XRootDStatus(0x0001, 0x0000, 0, "file already open"), nothing
    u = file_url(url)
    host, port, path = u.host, u.port, u.path
    want_tls = u.scheme == "roots"
    # A user named in the URL is the login account; an explicit keyword wins.
    opts = Dict{Symbol,Any}(kwargs)
    isempty(u.username) || get!(opts, :username, u.username)
    access =
        Wire.kXR_open_read | Wire.kXR_open_updt | Wire.kXR_open_apnd | Wire.kXR_open_wrto
    options = UInt16(flags)
    (options & access) == 0 && (options |= Wire.kXR_open_read)
    f.url = url
    f.options = options
    f.opts = opts
    f.owns_conn = conn === nothing
    hops = 0
    while true
        link = if conn !== nothing
            conn
        else
            try
                Session.connect(host, port; want_tls=want_tls, opts...)
            catch err
                return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
            end
        end
        hdr, body = try
            Session.roundtrip(link, Wire.OpenRequest(path; mode=UInt16(mode), options=options))
        catch err
            f.owns_conn && close(link)
            return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
        end

        if hdr.status == Wire.kXR_redirect
            f.owns_conn || return XRootDStatus(
                hdr.status,
                0x0000,
                0,
                "$path is not on the session it was opened on: the server redirects",
            ),
            nothing
            close(link)
            hops += 1
            hops > max_hops &&
                return XRootDStatus(hdr.status, 0, 0, "too many redirects"), nothing
            r = try
                Wire.decode_redirect(body)
            catch err
                return XRootDStatus(
                    0x0001,
                    0x0000,
                    0,
                    "malformed kXR_redirect: $(sprint(showerror, err))",
                ),
                nothing
            end
            isempty(r.host) &&
                return XRootDStatus(0x0001, 0x0000, 0, "kXR_redirect names no host"),
                nothing
            host = Session.unbracket(r.host)
            port, want_tls = redirect_endpoint(r, port, want_tls)
            path = Wire.merge_cgi(path, r.cgi)
            continue
        end

        st = status_from(hdr, body)
        if isError(st)
            f.owns_conn && close(link)
            return st, nothing
        end
        st, opened = decoded(Wire.decode_open, st, body)
        if opened === nothing
            f.owns_conn && close(link)
            return st, nothing
        end
        f.conn = link
        f.fhandle = opened.fhandle
        f.isopen = true
        f.currentOffset = 0
        f.cpsize = opened.cpsize
        # Recorded here rather than beside the other reopen state: a mode that
        # does not fit the wire field must fail where the request is built, so
        # the connection it was going to travel on gets closed.
        f.mode = UInt16(mode)
        # `kXR_retstat` answers the open with the stat line, which is the size
        # the cursor rules need — one round trip instead of two.
        if opened.stat !== nothing
            f.filesize = opened.stat.size
        else
            stst, si = stat(f)
            f.filesize = isOK(stst) && si !== nothing ? si.size : 0
        end
        # Bind the default data sub-stream(s) for this file's bulk I/O. Only on
        # a session the file owns — a borrowed connection's streams belong to
        # whoever opened it — and never fatal: a server that will not bind one
        # leaves the transfer on the control link, which still works. Only the
        # new link's TLS handshake is configurable, so no login credential is
        # forwarded (the bind presents the session id, it does not re-login).
        if f.owns_conn && data_streams >= 1
            bindkw = filter(
                p -> first(p) in
                     (:insecure_tls, :cert, :key, :cafile, :x509, :connect_timeout),
                opts,
            )
            for _ in 1:data_streams
                bst, _ = bind_data_path!(f; bindkw...)
                isOK(bst) || break
            end
        end
        return st, nothing
    end
end

"""
    compression(f::File) -> Int32

The compression page size the server reported at open, or `0` when the file
is not compressed.
"""
compression(f::File) = f.cpsize

"""
    recoverable(f::File) -> Bool

Whether a handle lost with its connection can be got back. Only a read-only
open can: reopening a file opened for writing would silently discard
everything written since — a truncating or `kXR_new` open would fail or
destroy the file, and even an append could not say where the writes that
were in flight ended up. The caller has to decide what to redo, so the
client does not decide for it.
"""
function recoverable(f::File)
    isempty(f.url) && return false
    write_bits =
        Wire.kXR_open_updt | Wire.kXR_open_apnd | Wire.kXR_open_wrto | Wire.kXR_delete
    return (f.options & write_bits) == 0
end

"""
    reopen!(f::File) -> XRootDStatus

Reopen `f` from the URL it was opened with, after its connection was lost.
The cursor and the file size survive; the handle does not — the new one comes
from the new open, and it may well be on a different server, since the
original URL is what re-resolves through the manager.

Fails without trying on a handle [`recoverable`](@ref) says no to.
"""
function reopen!(f::File)
    recoverable(f) ||
        return XRootDStatus(0x0001, 0x0000, 0, "handle is not recoverable: reopen it")
    conn = f.conn
    # A borrowed session belongs to whoever opened it — the reopen dials its
    # own rather than closing someone else's.
    conn === nothing || !f.owns_conn || close(conn)
    offset = f.currentOffset
    f.conn = nothing
    f.isopen = false
    st, _ = open(f, f.url, f.options, f.mode; f.opts...)
    isOK(st) && (f.currentOffset = offset)
    return st
end

"""
    Base.close(f::File; fsize::Integer=0)

Close the file handle, and the connection under it unless that connection
was borrowed from another file (`open(...; conn=)`). Returns
`(status, nothing)`.

A non-zero `fsize` makes the close verify the length first: a file that came
out a different size than the writer meant to write is rejected AND removed,
which is how a transfer says "all of it or none of it". The handle and its
connection are released either way — a failed verification is a file that is
gone, not one still open.
"""
function Base.close(f::File; fsize::Integer=0)
    f.isopen || return XRootDStatus(), nothing
    st, _ = fperform(f, Wire.CloseRequest(f.fhandle; fsize=fsize))
    conn = f.conn
    conn === nothing || !f.owns_conn || close(conn)
    f.conn = nothing
    f.isopen = false
    f.currentOffset = 0
    f.filesize = 0
    return st, nothing
end

"""
    Base.isopen(f::File) -> Bool
"""
Base.isopen(f::File) = f.isopen

"""
    Base.eof(f::File) -> Bool

`true` once the read cursor has passed the size captured at open.
"""
Base.eof(f::File) = f.currentOffset >= f.filesize

"""
    Base.stat(f::File, force::Bool=true)

Stat the open file by handle. Returns `(status, StatInfo | nothing)`.
"""
function Base.stat(f::File, force::Bool=true)
    st, body = fperform(f, Wire.StatRequest(""; fhandle=f.fhandle))
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        return StatInfo(String(copy(b)))
    end
end

"""
    Base.truncate(f::File, size::Integer)

Truncate the open file to `size` bytes. Returns `(status, nothing)`.
"""
function Base.truncate(f::File, size::Integer)
    st, _ = fperform(f, Wire.TruncateRequest("", Int64(size), f.fhandle))
    return st, nothing
end

"""
    bind_data_path!(f::File; kwargs...) -> (XRootDStatus, UInt8)

Give `f` a second connection to its server, so that its reads and writes move
their bytes there instead of over the link that carries every other request.
Returns the path id, or an error status and `0x00` if the server would not
bind one.

Worth doing when a transfer has to share a session with work that must stay
responsive — a directory listing during a multi-gigabyte read, or several
files streaming off one session at once. A single file read on an otherwise
idle session gains nothing: the same bytes cross the same network.

Keywords go to [`XRootD.Session.bind_data_path!`](@ref) and configure only
the new link's TLS handshake; the bind presents the session's id rather than
logging in again, so no credential is re-sent.

The binding is a property of the connection, not of the file: a handle that
has to be reopened after its connection is lost falls back to the control
link, and can be bound again.
"""
function bind_data_path!(f::File; kwargs...)
    f.isopen || return closed_status(), 0x00
    conn = f.conn
    conn === nothing && return closed_status(), 0x00
    pathid = try
        Session.bind_data_path!(conn; kwargs...)
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), 0x00
    end
    push!(f.pathids, pathid)
    return XRootDStatus(), pathid
end

"""
The data path this file's next request should name, or `0x00` for the control
link. With one bound path — the default — that path carries every read and
write; with several, requests are handed out round-robin so the bulk spreads
across the links. A reopen replaces the session and voids the ids it issued,
so liveness is checked per request rather than trusting what was stored: a
path the connection no longer has is skipped, and a file that has lost all of
them falls back to the control link.
"""
function data_pathid(f::File)
    isempty(f.pathids) && return 0x00
    conn = f.conn
    conn === nothing && return 0x00
    live = filter(p -> Session.has_data_path(conn, p), f.pathids)
    isempty(live) && return 0x00
    f.rr += 1
    return live[(f.rr - 1) % length(live) + 1]
end

"""
    Base.read(f::File, size, offset=0)

Read up to `size` bytes. `offset == 0` reads at the current cursor,
otherwise the cursor is set to `offset` first; the cursor is NOT advanced
by the read (0.2.x contract). Returns `(status, Vector{UInt8} | nothing)`.
"""
function Base.read(f::File, size, offset=0)
    if offset != 0
        f.currentOffset = offset
    end
    st, body = fperform(
        f,
        Wire.ReadRequest(f.fhandle, f.currentOffset, Int32(size); pathid=data_pathid(f));
        maxbytes=Int(size),
    )
    isOK(st) || return st, nothing
    return st, body
end

"""
    Base.unsafe_read(f::File, ptr::Ptr, size, offset=0)

Read up to `size` bytes at `offset` (used directly, independent of the
cursor) into `ptr`. Returns `(status, nbytes)` — 0 on failure.
"""
function Base.unsafe_read(f::File, ptr::Ptr, size, offset=0)
    st, body = fperform(
        f,
        Wire.ReadRequest(f.fhandle, Int64(offset), Int32(size); pathid=data_pathid(f));
        maxbytes=Int(size),
    )
    isOK(st) || return st, 0
    n = length(body)
    GC.@preserve body unsafe_copyto!(Ptr{UInt8}(ptr), pointer(body), n)
    return st, n
end

"""
    Base.write(f::File, data::Array{UInt8}, size, offset=0)
    Base.write(f::File, data::String, offset=0)

Write `size` bytes of `data` at `offset`. Returns `(status, nothing)`.
"""
function Base.write(f::File, data::Array{UInt8}, size, offset=0)
    payload = size == length(data) ? data : data[1:size]
    st, _ = fperform(
        f, Wire.WriteRequest(f.fhandle, Int64(offset), payload; pathid=data_pathid(f))
    )
    return st, nothing
end

function Base.write(f::File, data::String, offset=0)
    return write(f, Vector{UInt8}(codeunits(data)), ncodeunits(data), offset)
end

"""
    Base.readline(f::File, size=0, offset=0, chunk=0)

Read one line, keeping the trailing `"\\n"` (absent on the final line);
returns `""` with an OK status at EOF. Advances the cursor. `size` bounds
the line length; `chunk` the read granularity (default 2 MiB).
Returns `(status, String | nothing)`.
"""
function Base.readline(f::File, size=0, offset=0, chunk=0)
    if offset != 0
        f.currentOffset = offset
    end
    chunk == 0 && (chunk = 2 * 1024 * 1024)
    size == 0 && (size = typemax(Int32))
    size < chunk && (chunk = size)
    pos = f.currentOffset
    pos_end = pos + size
    line = UInt8[]
    st = XRootDStatus()
    while pos < pos_end
        rst, body = fperform(
            f,
            Wire.ReadRequest(f.fhandle, pos, Int32(chunk); pathid=data_pathid(f));
            maxbytes=Int(chunk),
        )
        st = rst
        isError(st) && return st, nothing
        isempty(body) && break
        pos += length(body)
        nl = findfirst(==(0x0a), body)
        if nl === nothing
            append!(line, body)
        else
            append!(line, view(body, 1:nl))
            break
        end
    end
    f.currentOffset += length(line)
    return st, String(line)
end

"""
    Base.readlines(f::File, size=0, offset=0, chunk=0)

Read all remaining lines (see [`Base.readline`](@ref)). Returns
`(status, Vector{String} | nothing)`.
"""
function Base.readlines(f::File, size=0, offset=0, chunk=0)
    # A handle that is not open is at EOF by construction, so the loop below
    # would report an empty file rather than a closed one.
    f.isopen || return closed_status(), nothing
    offset != 0 && (f.currentOffset = offset)
    lines = String[]
    while !eof(f)
        st, line = readline(f, size, 0, chunk)
        # A failure part-way through is not a short file: a caller cannot tell
        # the lines that were there from the ones that were not read.
        isError(st) && return st, nothing
        push!(lines, line)
    end
    return XRootDStatus(), lines
end

"""
    sync(f::File)

Commit outstanding writes to disk (`kXR_sync`). Returns `(status, nothing)`.
"""
function sync(f::File)
    st, _ = fperform(f, Wire.SyncRequest(f.fhandle))
    return st, nothing
end

"Turn a request-construction or decode failure into a 0.2.x error status."
local_error(err) = XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err))

"""
    readv(f::File, chunks::Vector{<:Tuple{Integer,Integer}})

Scatter-gather read: `chunks` is `(offset, size)` pairs. Returns
`(status, Vector{Vector{UInt8}} | nothing)` with the data per chunk in
request order.

A reply that decodes to fewer segments than were requested is a stopped
transfer, not a short one: it fails rather than returning partial data.
"""
function readv(f::File, chunks::Vector{<:Tuple{Integer,Integer}})
    req = try
        Wire.ReadVRequest([
            (; fhandle=f.fhandle, offset=Int64(off), rlen=Int32(len)) for
            (off, len) in chunks
        ])
    catch err
        return local_error(err), nothing
    end
    st, body = fperform(f, req; maxbytes=Wire.readv_reply_cap(req))
    isOK(st) || return st, nothing
    segments = try
        Wire.parse_readv(body)
    catch err
        return local_error(err), nothing
    end
    if length(segments) != length(chunks)
        return XRootDStatus(
            0x0001,
            0x0000,
            0,
            "readv returned $(length(segments)) of $(length(chunks)) segments",
        ),
        nothing
    end
    return st, [Vector{UInt8}(seg.data) for seg in segments]
end

"""
    writev(f::File, chunks::Vector{<:Tuple{Integer,Vector{UInt8}}}; do_sync::Bool=false)

Scatter-gather write, all-or-nothing: `chunks` is `(offset, data)` pairs;
`do_sync` fsyncs after the write. Returns `(status, nothing)`.
"""
function writev(
    f::File, chunks::Vector{<:Tuple{Integer,Vector{UInt8}}}; do_sync::Bool=false
)
    req = try
        Wire.WriteVRequest(
            [(; fhandle=f.fhandle, offset=Int64(off), data=data) for (off, data) in chunks];
            do_sync=do_sync,
        )
    catch err
        return local_error(err), nothing
    end
    st, _ = fperform(f, req)
    return st, nothing
end

"""
    clone(dst::File, src::File, ranges::Vector{<:Tuple{Integer,Integer,Integer}})

Server-side range copy (`kXR_clone`): each `(src_offset, length,
dst_offset)` copies `length` bytes of `src` into `dst` without them crossing
this client. Returns `(status, nothing)`.

Both handles must be open on the same connection — a file handle means
nothing on any other session, which is what `open(src, url, flags;
conn=dst.conn)` is for — and `dst` must have been opened for writing. The
server answers one status for the whole request: there is no per-range
outcome, and a failure part-way through leaves the ranges it already copied
in place.

`kXR_clone` (3032) is an nginx-xrootd extension, not stock XRootD: the
opcode sits one past `kXR_REQFENCE` in `XProtocol.hh`, so a server that does
not implement it answers `kXR_InvalidRequest`. What it saves is the round
trip through the client that [`XRootD.Tools`](@ref)' copy engine would
otherwise make — the same bargain third-party copy strikes, at range
granularity within one server.
"""
function clone(dst::File, src::File, ranges::Vector{<:Tuple{Integer,Integer,Integer}})
    dst.isopen && src.isopen || return closed_status(), nothing
    dst.conn === src.conn || return XRootDStatus(
        0x0001,
        0x0000,
        0,
        "clone: source and destination are open on different connections",
    ),
    nothing
    req = try
        Wire.CloneRequest(
            dst.fhandle,
            Wire.CloneItem[
                (;
                    fhandle=src.fhandle,
                    src_offset=Int64(so),
                    src_len=Int64(len),
                    dst_offset=Int64(dof),
                ) for (so, len, dof) in ranges
            ],
        )
    catch err
        return local_error(err), nothing
    end
    st, _ = fperform(dst, req)
    return st, nothing
end

"""
    pgread(f::File, size, offset=0)

Paged read with per-page CRC32c verification (`kXR_pgread`, protocol v5).
Returns `(status, Vector{UInt8} | nothing)`; a CRC mismatch yields an error
status.
"""
function pgread(f::File, size, offset=0)
    f.isopen || return closed_status(), nothing
    conn = f.conn
    conn === nothing && return closed_status(), nothing
    req = Wire.PgReadRequest(f.fhandle, Int64(offset), Int32(size))
    hdr, body = try
        Session.roundtrip(conn, req; maxbytes=Wire.pgread_reply_cap(req))
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
    end
    hdr.status == Wire.kXR_status || return status_from(hdr, body), nothing
    out = UInt8[]
    cursor = 1
    try
        while cursor <= length(body)
            s = Wire.decode_status_body(view(body, cursor:(cursor + 23)))
            pages = view(body, (cursor + 24):(cursor + 23 + Int(s.pgdlen)))
            append!(out, Wire.decode_pages(pages, s.offset))
            cursor += 24 + Int(s.pgdlen)
        end
    catch err
        msg = sprint(showerror, err)
        return XRootDStatus(0x0001, 0x0000, 0, "pgread integrity failure: $msg"), nothing
    end
    return XRootDStatus(), out
end

"""
Send one `kXR_pgwrite` and return `(status, cse)` where `cse` is the reply's
checksum-error trailer (empty when the server took every page). `reqflags` is
`Wire.kXR_pgRetry` for a resend of a single corrupt page.
"""
function pgwrite_once(f::File, offset::Int64, data::Vector{UInt8}, reqflags::UInt8)
    f.isopen || return closed_status(), UInt8[]
    conn = f.conn
    conn === nothing && return closed_status(), UInt8[]
    req = Wire.PgWriteRequest(f.fhandle, offset, data; reqflags=reqflags)
    hdr, body = try
        Session.roundtrip(conn, req; maxbytes=Wire.pgwrite_reply_cap(req))
    catch err
        return local_error(err), UInt8[]
    end
    hdr.status == Wire.kXR_status || return status_from(hdr, body), UInt8[]
    s = try
        Wire.decode_status_body(view(body, 1:min(Wire.STATUS_BODY_LEN, length(body))))
    catch err
        return local_error(err), UInt8[]
    end
    n = Int(s.pgdlen)
    n == 0 && return XRootDStatus(), UInt8[]
    if length(body) < Wire.STATUS_BODY_LEN + n
        return XRootDStatus(0x0001, 0x0000, 0, "pgwrite: truncated checksum-error trailer"),
        UInt8[]
    end
    return XRootDStatus(),
    Vector{UInt8}(body[(Wire.STATUS_BODY_LEN + 1):(Wire.STATUS_BODY_LEN + n)])
end

"""
Resend the page at file offset `pgoff` (sliced out of `data`, which starts at
file offset `base`) with `kXR_pgRetry`, up to `Wire.PGW_MAX_RETRY` times.
Returns an OK status once the server accepts the page, an integrity error if
it stays corrupt past the budget.
"""
function pgwrite_retry_page(f::File, data::Vector{UInt8}, base::Int64, pgoff::Int64)
    doff = pgoff - base
    if doff < 0 || doff >= length(data)
        return XRootDStatus(
            0x0001, 0x0000, 0, "pgwrite: corrupt-page offset $pgoff outside the request"
        )
    end
    n = Wire.page_span(pgoff, length(data) - doff)
    page = data[(doff + 1):(doff + n)]
    for _ in 1:(Wire.PGW_MAX_RETRY)
        st, cse = pgwrite_once(f, pgoff, page, Wire.kXR_pgRetry)
        isOK(st) || return st
        isempty(cse) && return st
    end
    return XRootDStatus(
        0x0001,
        0x0000,
        0,
        "pgwrite: page at offset $pgoff still corrupt after " *
        "$(Wire.PGW_MAX_RETRY) retries",
    )
end

"""
    pgwrite(f::File, data::Vector{UInt8}, offset=0)

Paged write with per-page CRC32c (`kXR_pgwrite`, protocol v5). The server
stores the data and answers with a checksum-error trailer listing any page
whose CRC32c did not survive the wire; each of those pages is retransmitted
with `kXR_pgRetry` until the server accepts it or the bounded retry budget is
exhausted, which fails the write (libxrdc `pgwrite_handle_cse`). Returns
`(status, nothing)`.
"""
function pgwrite(f::File, data::Vector{UInt8}, offset=0)
    st, cse = pgwrite_once(f, Int64(offset), data, 0x00)
    isOK(st) || return st, nothing
    isempty(cse) && return st, nothing
    bad = try
        Wire.parse_pgwrite_cse(cse)
    catch err
        return local_error(err), nothing
    end
    for pgoff in bad
        rst = pgwrite_retry_page(f, data, Int64(offset), pgoff)
        isOK(rst) || return rst, nothing
    end
    return XRootDStatus(), nothing
end

# ---- per-handle queries and extended attributes ----

"""
    visa(f::File)

Ask the server what it will let this handle do (`kXR_query`/`kXR_Qvisa`).
Returns `(status, String | nothing)`.

The answer describes the open file — where it actually is, and the access
the server granted — which a client following a redirect through a manager
has no other way to learn.
"""
function visa(f::File)
    st, body = fperform(f, Wire.QueryRequest(Wire.kXR_Qvisa; fhandle=f.fhandle))
    isOK(st) || return st, nothing
    return st, rstrip(String(copy(body)), '\0')
end

"""
    checksum(f::File; algorithm::AbstractString="")

The server's checksum for the open file (`kXR_query`/`kXR_Qcksum`). Returns
`(status, String | nothing)` — typically `"<algo> <hexdigest>"`.

`kXR_Qcksum` names a path rather than a handle, so this asks about the URL
the file was opened with; `algorithm` picks the digest.
"""
function checksum(f::File; algorithm::AbstractString="")
    isempty(f.url) && return closed_status(), nothing
    path = cksum_path(file_url(f.url).path, algorithm)
    st, body = fperform(f, Wire.QueryRequest(Wire.kXR_Qcksum, path))
    isOK(st) || return st, nothing
    return st, rstrip(String(copy(body)), '\0')
end

"""
    getxattr(f::File, name::String)

Read one extended attribute of the open file. Returns
`(status, Vector{UInt8} | nothing)`.
"""
function getxattr(f::File, name::String)
    st, body = fperform(
        f, Wire.FattrRequest(Wire.kXR_fattrGet, ""; fhandle=f.fhandle, names=[name])
    )
    isOK(st) || return st, nothing
    st = fattr_rc(st, body, name)
    isOK(st) || return st, nothing
    return decoded(st, body) do b
        return Wire.parse_fattr_get(b, 1)[1].value
    end
end

"""
    setxattr(f::File, name::String, value::Vector{UInt8})

Create or overwrite one extended attribute of the open file. Returns
`(status, nothing)`.
"""
function setxattr(f::File, name::String, value::Vector{UInt8})
    st, body = fperform(
        f,
        Wire.FattrRequest(
            Wire.kXR_fattrSet, ""; fhandle=f.fhandle, names=[name], values=[value]
        ),
    )
    isOK(st) || return st, nothing
    return fattr_rc(st, body, name), nothing
end

"""
    listxattr(f::File)

List the extended-attribute names of the open file. Returns
`(status, Vector{String} | nothing)`.
"""
function listxattr(f::File)
    st, body = fperform(f, Wire.FattrRequest(Wire.kXR_fattrList, ""; fhandle=f.fhandle))
    isOK(st) || return st, nothing
    return st, Wire.parse_fattr_list(body)
end

"""
    removexattr(f::File, name::String)

Delete one extended attribute of the open file. Returns `(status, nothing)`.
"""
function removexattr(f::File, name::String)
    st, body = fperform(
        f, Wire.FattrRequest(Wire.kXR_fattrDel, ""; fhandle=f.fhandle, names=[name])
    )
    isOK(st) || return st, nothing
    return fattr_rc(st, body, name), nothing
end

# ---- checkpoints (kXR_chkpoint, protocol v5) ----

"""
    checkpoint_begin(f::File)

Open a checkpoint on the file: from here until a commit or a rollback, the
server keeps enough of the old contents to undo every write made through
[`checkpoint_write`](@ref) and [`checkpoint_truncate`](@ref). Returns
`(status, nothing)`.

One checkpoint per handle — a second `Begin` fails rather than nesting.
"""
function checkpoint_begin(f::File)
    st, _ = fperform(f, Wire.ChkPointRequest(f.fhandle, Wire.kXR_ckpBegin))
    return st, nothing
end

"""
    checkpoint_commit(f::File)

Make the writes made under the open checkpoint permanent and release the
undo data. Returns `(status, nothing)`.
"""
function checkpoint_commit(f::File)
    st, _ = fperform(f, Wire.ChkPointRequest(f.fhandle, Wire.kXR_ckpCommit))
    return st, nothing
end

"""
    checkpoint_rollback(f::File)

Undo every write made under the open checkpoint, putting the file back as it
was when the checkpoint opened. Returns `(status, nothing)`.
"""
function checkpoint_rollback(f::File)
    st, _ = fperform(f, Wire.ChkPointRequest(f.fhandle, Wire.kXR_ckpRollback))
    return st, nothing
end

"""
    checkpoint_query(f::File)

How much a checkpoint on this file may hold. Returns
`(status, (; capacity, used) | nothing)` — `capacity` bounds the undo, not
the file, and `used` is how much of it the open checkpoint holds.
"""
function checkpoint_query(f::File)
    st, body = fperform(f, Wire.ChkPointRequest(f.fhandle, Wire.kXR_ckpQuery))
    isOK(st) || return st, nothing
    return decoded(Wire.parse_checkpoint, st, body)
end

"""
    checkpoint_write(f::File, data::Vector{UInt8}, offset=0)

Write inside the open checkpoint (`kXR_ckpXeq` carrying a `kXR_write`), so
that a rollback takes it back. Returns `(status, nothing)`.
"""
function checkpoint_write(f::File, data::Vector{UInt8}, offset=0)
    inner = Wire.WriteRequest(f.fhandle, Int64(offset), data)
    st, _ = fperform(f, Wire.checkpoint_exec(f.fhandle, inner))
    return st, nothing
end

"""
    checkpoint_truncate(f::File, size::Integer)

Truncate inside the open checkpoint (`kXR_ckpXeq` carrying a
`kXR_truncate`), so that a rollback restores the bytes it dropped. Returns
`(status, nothing)`.
"""
function checkpoint_truncate(f::File, size::Integer)
    inner = Wire.TruncateRequest("", Int64(size), f.fhandle)
    st, _ = fperform(f, Wire.checkpoint_exec(f.fhandle, inner))
    return st, nothing
end

"""
    checkpoint(body::Function, f::File)

Run `body` inside a checkpoint: commit when it returns, roll back when it
throws. The `do` form of the four operations above.

```julia
checkpoint(f) do
    checkpoint_write(f, data, 0)
end
```

Returns `(status, result)` where `result` is what `body` returned — or the
rollback's own status when `body` threw, with the original exception
rethrown after the file has been put back.
"""
function checkpoint(body::Function, f::File)
    st, _ = checkpoint_begin(f)
    isOK(st) || return st, nothing
    result = try
        body()
    catch
        checkpoint_rollback(f)
        rethrow()
    end
    st, _ = checkpoint_commit(f)
    return st, result
end
