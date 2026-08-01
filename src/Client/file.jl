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
"""
mutable struct File
    conn::Union{Session.Connection,Nothing}
    fhandle::NTuple{4,UInt8}
    currentOffset::Int64
    filesize::Int64
    isopen::Bool
end

File() = File(nothing, (0x00, 0x00, 0x00, 0x00), 0, 0, false)

function File(url::String, flags=0x0000, mode=0x0000; kwargs...)
    f = File()
    st, _ = open(f, url, flags, mode; kwargs...)
    return isOK(st) ? f : nothing
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

"""
Run one request on the file's connection, mapping failures to statuses.
`maxbytes` bounds the reply the Session layer will accumulate (0 = unbounded);
every read passes the largest reply its request can legitimately produce.
"""
function fperform(f::File, req::Wire.Request; maxbytes::Integer=0)
    f.isopen || return closed_status(), UInt8[]
    conn = f.conn
    conn === nothing && return closed_status(), UInt8[]
    hdr, body = try
        Session.roundtrip(conn, req; maxbytes=maxbytes)
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), UInt8[]
    end
    return status_from(hdr, body), body
end

"""
    Base.open(f::File, url::String, flags=0x0000, mode=0x0000)

Open `url` on `f`. `flags` composes `OpenFlags` (an open with no access
bits requests `OpenFlags.Read`); `mode` sets permission bits for created
files. Keywords are forwarded to [`XRootD.Session.connect`](@ref) —
`insecure_tls`, `token`, `keytab`, `cert`/`key`. Returns `(status, nothing)`.

A `kXR_redirect` answer is followed for up to `max_hops` hops: opening
through a manager is the normal way a client reaches a data server, and the
redirector's opaque data travels with the path to the target.
"""
function Base.open(
    f::File, url::String, flags=0x0000, mode=0x0000; max_hops::Int=8, kwargs...
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
    hops = 0
    while true
        conn = try
            Session.connect(host, port; want_tls=want_tls, opts...)
        catch err
            return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
        end
        hdr, body = try
            Session.roundtrip(conn, Wire.OpenRequest(path; mode=UInt16(mode), options=options))
        catch err
            close(conn)
            return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
        end

        if hdr.status == Wire.kXR_redirect
            close(conn)
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
            close(conn)
            return st, nothing
        end
        st, opened = decoded(Wire.decode_open, st, body)
        if opened === nothing
            close(conn)
            return st, nothing
        end
        f.conn = conn
        f.fhandle = opened.fhandle
        f.isopen = true
        f.currentOffset = 0
        stst, si = stat(f)
        f.filesize = isOK(stst) && si !== nothing ? si.size : 0
        return st, nothing
    end
end

"""
    Base.close(f::File)

Close the file handle and its connection. Returns `(status, nothing)`.
"""
function Base.close(f::File)
    f.isopen || return XRootDStatus(), nothing
    st, _ = fperform(f, Wire.CloseRequest(f.fhandle))
    conn = f.conn
    conn === nothing || close(conn)
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
        f, Wire.ReadRequest(f.fhandle, f.currentOffset, Int32(size)); maxbytes=Int(size)
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
        f, Wire.ReadRequest(f.fhandle, Int64(offset), Int32(size)); maxbytes=Int(size)
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
    st, _ = fperform(f, Wire.WriteRequest(f.fhandle, Int64(offset), payload))
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
            f, Wire.ReadRequest(f.fhandle, pos, Int32(chunk)); maxbytes=Int(chunk)
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
