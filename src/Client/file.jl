# The File API — 0.2.x semantics (including its cursor rules) over the
# native Session layer, plus the v5 parity additions: sync, vector reads and
# writes, and CRC32c-verified paged I/O.

"""
    File()
    File(url::String, flags=0x0000, mode=0x0000) -> File | nothing

A remote file. The one-argument constructors open
`root://host[:port]//path` immediately and return `nothing` when the open
fails (0.2.x contract); `File()` creates a closed handle for use with
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

function File(url::String, flags=0x0000, mode=0x0000)
    f = File()
    st, _ = open(f, url, flags, mode)
    return isOK(st) ? f : nothing
end

"Parse `root://host[:port]//path` into (host, port, path)."
function parse_file_url(url::AbstractString)
    m = match(r"^roots?://([^/:@]+)(?::(\d+))?(/.*)$", url)
    m === nothing && throw(ArgumentError("not a root:// file URL: $(repr(url))"))
    host = String(something(m.captures[1]))
    portstr = m.captures[2]
    port = portstr === nothing ? 1094 : parse(Int, portstr)
    raw = String(something(m.captures[3]))
    path = startswith(raw, "//") ? raw[2:end] : raw
    return host, port, path
end

closed_status() = XRootDStatus(0x0001, 0x0000, 0, "file is not open")

"Run one request on the file's connection, mapping failures to statuses."
function fperform(f::File, req::Wire.Request)
    f.isopen || return closed_status(), UInt8[]
    conn = f.conn
    conn === nothing && return closed_status(), UInt8[]
    hdr, body = try
        Session.roundtrip(conn, req)
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), UInt8[]
    end
    return status_from(hdr, body), body
end

"""
    Base.open(f::File, url::String, flags=0x0000, mode=0x0000)

Open `url` on `f`. `flags` composes `OpenFlags` (an open with no access
bits requests `OpenFlags.Read`); `mode` sets permission bits for created
files. Returns `(status, nothing)`.
"""
function Base.open(f::File, url::String, flags=0x0000, mode=0x0000)
    f.isopen && return XRootDStatus(0x0001, 0x0000, 0, "file already open"), nothing
    host, port, path = parse_file_url(url)
    conn = try
        Session.connect(host, port)
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
    end
    access =
        Wire.kXR_open_read | Wire.kXR_open_updt | Wire.kXR_open_apnd | Wire.kXR_open_wrto
    options = UInt16(flags)
    (options & access) == 0 && (options |= Wire.kXR_open_read)
    hdr, body = Session.roundtrip(
        conn, Wire.OpenRequest(path; mode=UInt16(mode), options=options)
    )
    st = status_from(hdr, body)
    if isError(st)
        close(conn)
        return st, nothing
    end
    f.conn = conn
    f.fhandle = Wire.decode_open(body).fhandle
    f.isopen = true
    f.currentOffset = 0
    stst, si = stat(f)
    f.filesize = isOK(stst) && si !== nothing ? si.size : 0
    return st, nothing
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
    return st, StatInfo(String(copy(body)))
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
    st, body = fperform(f, Wire.ReadRequest(f.fhandle, f.currentOffset, Int32(size)))
    isOK(st) || return st, nothing
    return st, body
end

"""
    Base.unsafe_read(f::File, ptr::Ptr, size, offset=0)

Read up to `size` bytes at `offset` (used directly, independent of the
cursor) into `ptr`. Returns `(status, nbytes)` — 0 on failure.
"""
function Base.unsafe_read(f::File, ptr::Ptr, size, offset=0)
    st, body = fperform(f, Wire.ReadRequest(f.fhandle, Int64(offset), Int32(size)))
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
        rst, body = fperform(f, Wire.ReadRequest(f.fhandle, pos, Int32(chunk)))
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
`(status, Vector{String})`.
"""
function Base.readlines(f::File, size=0, offset=0, chunk=0)
    offset != 0 && (f.currentOffset = offset)
    lines = String[]
    st = XRootDStatus()
    while !eof(f)
        st, line = readline(f, size, 0, chunk)
        isError(st) && break
        push!(lines, line)
    end
    return st, lines
end

"""
    sync(f::File)

Commit outstanding writes to disk (`kXR_sync`). Returns `(status, nothing)`.
"""
function sync(f::File)
    st, _ = fperform(f, Wire.SyncRequest(f.fhandle))
    return st, nothing
end

"""
    readv(f::File, chunks::Vector{<:Tuple{Integer,Integer}})

Scatter-gather read: `chunks` is `(offset, size)` pairs. Returns
`(status, Vector{Vector{UInt8}} | nothing)` with the data per chunk in
request order.
"""
function readv(f::File, chunks::Vector{<:Tuple{Integer,Integer}})
    segments = [
        (; fhandle=f.fhandle, offset=Int64(off), rlen=Int32(len)) for (off, len) in chunks
    ]
    st, body = fperform(f, Wire.ReadVRequest(segments))
    isOK(st) || return st, nothing
    return st, [Vector{UInt8}(seg.data) for seg in Wire.parse_readv(body)]
end

"""
    writev(f::File, chunks::Vector{<:Tuple{Integer,Vector{UInt8}}}; do_sync::Bool=false)

Scatter-gather write, all-or-nothing: `chunks` is `(offset, data)` pairs;
`do_sync` fsyncs after the write. Returns `(status, nothing)`.
"""
function writev(
    f::File, chunks::Vector{<:Tuple{Integer,Vector{UInt8}}}; do_sync::Bool=false
)
    segments = [
        (; fhandle=f.fhandle, offset=Int64(off), data=data) for (off, data) in chunks
    ]
    st, _ = fperform(f, Wire.WriteVRequest(segments; do_sync=do_sync))
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
    hdr, body = try
        Session.roundtrip(conn, Wire.PgReadRequest(f.fhandle, Int64(offset), Int32(size)))
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
    pgwrite(f::File, data::Vector{UInt8}, offset=0)

Paged write with per-page CRC32c (`kXR_pgwrite`, protocol v5). A non-empty
checksum-error trailer in the reply (corrupt pages on the server side)
yields an error status. Returns `(status, nothing)`.
"""
function pgwrite(f::File, data::Vector{UInt8}, offset=0)
    f.isopen || return closed_status(), nothing
    conn = f.conn
    conn === nothing && return closed_status(), nothing
    hdr, body = try
        Session.roundtrip(conn, Wire.PgWriteRequest(f.fhandle, Int64(offset), data))
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
    end
    hdr.status == Wire.kXR_status || return status_from(hdr, body), nothing
    s = try
        Wire.decode_status_body(view(body, 1:min(24, length(body))))
    catch err
        return XRootDStatus(0x0001, 0x0000, 0, sprint(showerror, err)), nothing
    end
    if s.pgdlen != 0
        return XRootDStatus(
            0x0001, 0x0000, 0, "pgwrite reported $(s.pgdlen) bytes of corrupt-page info"
        ),
        nothing
    end
    return XRootDStatus(), nothing
end
