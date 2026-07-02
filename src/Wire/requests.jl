# Concrete request codecs. Field layouts: nginx-xrootd wire_core_requests.h;
# default flag/capability values: bootstrap_pack.h (the exact bytes libxrdc
# sends during connection bring-up).

"""
    ProtocolRequest(; flags::UInt8 = kXR_secreqs | kXR_ableTLS)

`kXR_protocol` — the first request after the handshake. Announces the client
protocol version (`kXR_PROTOCOLVERSION`), capability `flags` (pass
`kXR_secreqs | kXR_ableTLS | kXR_wantTLS` to require TLS), and that a login
follows (`kXR_ExpLogin`).
"""
struct ProtocolRequest <: Request
    clientpv::UInt32
    flags::UInt8
    expect::UInt8
end

function ProtocolRequest(; flags::UInt8=kXR_secreqs | kXR_ableTLS)
    return ProtocolRequest(kXR_PROTOCOLVERSION, flags, kXR_ExpLogin)
end

requestid(::ProtocolRequest) = kXR_protocol

function body!(frame::Vector{UInt8}, r::ProtocolRequest)
    set_u32!(frame, 5, r.clientpv)
    frame[9] = r.flags
    frame[10] = r.expect
    return frame
end

"""
    LoginRequest(username::AbstractString;
                 pid::Integer = getpid(),
                 capver::UInt8 = kXR_ver005 | kXR_asyncap)

`kXR_login` — starts the session. `username` is NUL-padded/truncated into the
8-byte wire field; `pid` is informational; `capver` advertises a v5,
async-capable client. `dlen = 0` (anonymous — credentials go in a subsequent
`kXR_auth`).
"""
struct LoginRequest <: Request
    username::String
    pid::Int32
    capver::UInt8
end

function LoginRequest(
    username::AbstractString; pid::Integer=getpid(), capver::UInt8=kXR_ver005 | kXR_asyncap
)
    return LoginRequest(String(username), Int32(pid), capver)
end

requestid(::LoginRequest) = kXR_login

function body!(frame::Vector{UInt8}, r::LoginRequest)
    set_u32!(frame, 5, reinterpret(UInt32, r.pid))
    set_padded_string!(frame, 9, 8, r.username)
    frame[19] = r.capver   # bytes 17 (ability2), 18 (ability), 20 (rsvd) stay 0
    return frame
end

"""
    AuthRequest(credtype::AbstractString, cred::Vector{UInt8})

`kXR_auth` — answers a `kXR_authmore`/security requirement with a credential.
`credtype` is the 4-byte protocol tag (`"unix"`, `"ztn"`, `"sss"`); `cred` is
the raw credential payload (e.g. the JWT bytes for ztn).
"""
struct AuthRequest <: Request
    credtype::String
    cred::Vector{UInt8}

    function AuthRequest(credtype::AbstractString, cred::Vector{UInt8})
        if ncodeunits(credtype) > 4
            throw(ArgumentError("credtype must be ≤ 4 bytes, got $(repr(credtype))"))
        end
        return new(String(credtype), cred)
    end
end

requestid(::AuthRequest) = kXR_auth

function body!(frame::Vector{UInt8}, r::AuthRequest)
    set_padded_string!(frame, 17, 4, r.credtype)   # bytes 5:16 reserved
    return frame
end

payload(r::AuthRequest) = r.cred

"""
    PingRequest()

`kXR_ping` — liveness probe; empty body, empty payload.
"""
struct PingRequest <: Request end

requestid(::PingRequest) = kXR_ping

"""
    StatRequest(path::AbstractString;
                options::UInt8 = 0x00,
                fhandle::NTuple{4,UInt8} = (0x00, 0x00, 0x00, 0x00))

`kXR_stat` — stat a path (the usual case) or an open file handle (empty
`path` + real `fhandle`). `options = kXR_vfs` requests virtual-filesystem
(statvfs) information instead. The response body is the ASCII stat line
`"<id> <size> <flags> <mtime>"` (see [`parse_stat_line`](@ref)).
"""
struct StatRequest <: Request
    path::String
    options::UInt8
    fhandle::NTuple{4,UInt8}
end

function StatRequest(
    path::AbstractString;
    options::UInt8=0x00,
    fhandle::NTuple{4,UInt8}=(0x00, 0x00, 0x00, 0x00),
)
    return StatRequest(String(path), options, fhandle)
end

requestid(::StatRequest) = kXR_stat

function body!(frame::Vector{UInt8}, r::StatRequest)
    frame[5] = r.options                       # bytes 6:16 reserved (zero)
    set_bytes!(frame, 17, collect(r.fhandle))
    return frame
end

payload(r::StatRequest) = codeunits(r.path)

"""
    DirlistRequest(path::AbstractString; options::UInt8 = kXR_dstat)

`kXR_dirlist` — list a directory. The default `kXR_dstat` asks for per-entry
stat lines (the server then prepends the `".\\n0 0 0 0\\n"` sentinel — see
[`parse_dirlist`](@ref)). Large listings arrive chunked via `kXR_oksofar`;
accumulating chunks is the Session layer's job.
"""
struct DirlistRequest <: Request
    path::String
    options::UInt8
end

function DirlistRequest(path::AbstractString; options::UInt8=kXR_dstat)
    return DirlistRequest(String(path), options)
end

requestid(::DirlistRequest) = kXR_dirlist

function body!(frame::Vector{UInt8}, r::DirlistRequest)
    frame[20] = r.options   # body bytes 1:15 reserved; options is byte 16
    return frame
end

payload(r::DirlistRequest) = codeunits(r.path)

# ---- filesystem mutations (wire_write_extended_requests.h) ----

"""
    MkdirRequest(path; mode::UInt16 = 0x0000, mkpath::Bool = false)

`kXR_mkdir` — create a directory with POSIX permission bits `mode`;
`mkpath` creates missing parents (`kXR_mkdirpath`).
"""
struct MkdirRequest <: Request
    path::String
    mode::UInt16
    mkpath::Bool
end

function MkdirRequest(path::AbstractString; mode::UInt16=0x0000, mkpath::Bool=false)
    return MkdirRequest(String(path), mode, mkpath)
end

requestid(::MkdirRequest) = kXR_mkdir

function body!(frame::Vector{UInt8}, r::MkdirRequest)
    frame[5] = r.mkpath ? kXR_mkdirpath : 0x00
    set_u16!(frame, 19, r.mode)
    return frame
end

payload(r::MkdirRequest) = codeunits(r.path)

"""
    RmRequest(path)

`kXR_rm` — delete a file.
"""
struct RmRequest <: Request
    path::String
end

RmRequest(path::AbstractString) = RmRequest(String(path))
requestid(::RmRequest) = kXR_rm
payload(r::RmRequest) = codeunits(r.path)

"""
    RmdirRequest(path)

`kXR_rmdir` — remove an empty directory.
"""
struct RmdirRequest <: Request
    path::String
end

RmdirRequest(path::AbstractString) = RmdirRequest(String(path))
requestid(::RmdirRequest) = kXR_rmdir
payload(r::RmdirRequest) = codeunits(r.path)

"""
    MvRequest(src, dst)

`kXR_mv` — rename/move. Wire payload is `src * " " * dst` with
`arg1len = ncodeunits(src)` in body bytes 15:16 (libxrdc `ops_fs.c`).
"""
struct MvRequest <: Request
    src::String
    dst::String
end

MvRequest(src::AbstractString, dst::AbstractString) = MvRequest(String(src), String(dst))
requestid(::MvRequest) = kXR_mv

function body!(frame::Vector{UInt8}, r::MvRequest)
    set_u16!(frame, 19, UInt16(ncodeunits(r.src)))
    return frame
end

payload(r::MvRequest) = codeunits(r.src * " " * r.dst)

"""
    ChmodRequest(path, mode::UInt16)

`kXR_chmod` — set POSIX permission bits (the kXR mode bits equal the low 9
POSIX bits, so octal literals pass through unchanged).
"""
struct ChmodRequest <: Request
    path::String
    mode::UInt16
end

function ChmodRequest(path::AbstractString, mode::UInt16)
    return ChmodRequest(String(path), mode)
end

requestid(::ChmodRequest) = kXR_chmod

function body!(frame::Vector{UInt8}, r::ChmodRequest)
    set_u16!(frame, 19, r.mode)
    return frame
end

payload(r::ChmodRequest) = codeunits(r.path)

"""
    TruncateRequest(path, size::Int64)

`kXR_truncate` — truncate a file by path to `size` bytes. (Handle-based
truncation of an open file uses the fhandle field with an empty path.)
"""
struct TruncateRequest <: Request
    path::String
    size::Int64
    fhandle::NTuple{4,UInt8}
end

function TruncateRequest(path::AbstractString, size::Integer)
    return TruncateRequest(String(path), Int64(size), (0x00, 0x00, 0x00, 0x00))
end

requestid(::TruncateRequest) = kXR_truncate

function body!(frame::Vector{UInt8}, r::TruncateRequest)
    set_bytes!(frame, 5, collect(r.fhandle))
    set_u64!(frame, 9, reinterpret(UInt64, r.size))
    return frame
end

payload(r::TruncateRequest) = codeunits(r.path)

"""
    LocateRequest(path; options::UInt16 = 0x0000)

`kXR_locate` — list replica locations. Response: space-separated
`XY<host:port>` tokens (see [`parse_locate`](@ref)).
"""
struct LocateRequest <: Request
    path::String
    options::UInt16
end

function LocateRequest(path::AbstractString; options::UInt16=0x0000)
    return LocateRequest(String(path), options)
end

requestid(::LocateRequest) = kXR_locate

function body!(frame::Vector{UInt8}, r::LocateRequest)
    set_u16!(frame, 5, r.options)
    return frame
end

payload(r::LocateRequest) = codeunits(r.path)

"""
    QueryRequest(infotype::UInt16, args)

`kXR_query` — query server information: `kXR_QStats`, `kXR_Qspace`,
`kXR_Qcksum`, `kXR_Qconfig`, ... `args` is the query argument text.
"""
struct QueryRequest <: Request
    infotype::UInt16
    args::String
end

function QueryRequest(infotype::UInt16, args::AbstractString)
    return QueryRequest(infotype, String(args))
end

requestid(::QueryRequest) = kXR_query

function body!(frame::Vector{UInt8}, r::QueryRequest)
    set_u16!(frame, 5, r.infotype)
    return frame
end

payload(r::QueryRequest) = codeunits(r.args)

# ---- file access (wire_core_requests.h) ----

"""
    OpenRequest(path; mode::UInt16 = 0x0000, options::UInt16)

`kXR_open` — open `path`. `options` composes `kXR_open_read`,
`kXR_open_updt`, `kXR_new`, `kXR_delete` (truncate), `kXR_mkpath`,
`kXR_retstat`, ...; `mode` sets permission bits for created files.
Response: [`decode_open`](@ref).
"""
struct OpenRequest <: Request
    path::String
    mode::UInt16
    options::UInt16
end

function OpenRequest(path::AbstractString; mode::UInt16=0x0000, options::UInt16)
    return OpenRequest(String(path), mode, options)
end

requestid(::OpenRequest) = kXR_open

function body!(frame::Vector{UInt8}, r::OpenRequest)
    set_u16!(frame, 5, r.mode)
    set_u16!(frame, 7, r.options)
    return frame
end

payload(r::OpenRequest) = codeunits(r.path)

"""
    ReadRequest(fhandle, offset::Int64, rlen::Int32)

`kXR_read` — read `rlen` bytes at `offset` from the open file `fhandle`.
Response body: the raw bytes (large reads arrive chunked via `kXR_oksofar`).
"""
struct ReadRequest <: Request
    fhandle::NTuple{4,UInt8}
    offset::Int64
    rlen::Int32
end

requestid(::ReadRequest) = kXR_read

function body!(frame::Vector{UInt8}, r::ReadRequest)
    set_bytes!(frame, 5, collect(r.fhandle))
    set_u64!(frame, 9, reinterpret(UInt64, r.offset))
    set_u32!(frame, 17, reinterpret(UInt32, r.rlen))
    return frame
end

"""
    WriteRequest(fhandle, offset::Int64, data::Vector{UInt8})

`kXR_write` — write `data` at `offset` to the open file `fhandle`.
"""
struct WriteRequest <: Request
    fhandle::NTuple{4,UInt8}
    offset::Int64
    data::Vector{UInt8}
end

requestid(::WriteRequest) = kXR_write

function body!(frame::Vector{UInt8}, r::WriteRequest)
    set_bytes!(frame, 5, collect(r.fhandle))
    set_u64!(frame, 9, reinterpret(UInt64, r.offset))
    return frame
end

payload(r::WriteRequest) = r.data

"""
    CloseRequest(fhandle)

`kXR_close` — close an open file handle.
"""
struct CloseRequest <: Request
    fhandle::NTuple{4,UInt8}
end

requestid(::CloseRequest) = kXR_close

function body!(frame::Vector{UInt8}, r::CloseRequest)
    set_bytes!(frame, 5, collect(r.fhandle))
    return frame
end

"""
    SyncRequest(fhandle)

`kXR_sync` — fsync an open file handle.
"""
struct SyncRequest <: Request
    fhandle::NTuple{4,UInt8}
end

requestid(::SyncRequest) = kXR_sync

function body!(frame::Vector{UInt8}, r::SyncRequest)
    set_bytes!(frame, 5, collect(r.fhandle))
    return frame
end

# ---- vector I/O (readahead_list / write_list; libxrdc ops_file_rw.c) ----

"One readv segment request: where to read and how much."
const ReadVSegment = @NamedTuple{fhandle::NTuple{4,UInt8}, offset::Int64, rlen::Int32}

"One writev segment: where to write and the bytes."
const WriteVSegment = @NamedTuple{
    fhandle::NTuple{4,UInt8}, offset::Int64, data::Vector{UInt8}
}

"""
    ReadVRequest(segments::Vector{ReadVSegment})

`kXR_readv` — scatter-gather read. The payload is one 16-byte
`readahead_list` entry per segment (`fhandle[4] + rlen[4] + offset[8]`, all
big-endian). The response interleaves a 16-byte echo header (carrying the
ACTUAL length) and the data per segment — see [`parse_readv`](@ref).
"""
struct ReadVRequest <: Request
    segments::Vector{ReadVSegment}
end

requestid(::ReadVRequest) = kXR_readv

function payload(r::ReadVRequest)
    pl = zeros(UInt8, 16 * length(r.segments))
    for (i, seg) in enumerate(r.segments)
        off = 16 * (i - 1) + 1
        set_bytes!(pl, off, collect(seg.fhandle))
        set_u32!(pl, off + 4, reinterpret(UInt32, seg.rlen))
        set_u64!(pl, off + 8, reinterpret(UInt64, seg.offset))
    end
    return pl
end

"""
    WriteVRequest(segments::Vector{WriteVSegment}; do_sync::Bool=false)

`kXR_writev` — scatter-gather write, all-or-nothing. The payload is the
16-byte `write_list` descriptor block back-to-back, FOLLOWED by the
concatenated data for every segment (the server recovers the count from
`n*16 + sum(wlen) == dlen`; libxrdc `xrdc_file_writev`). `do_sync` sets
`kXR_wv_doSync` (fsync each touched handle).
"""
struct WriteVRequest <: Request
    segments::Vector{WriteVSegment}
    do_sync::Bool
end

function WriteVRequest(segments::Vector{WriteVSegment}; do_sync::Bool=false)
    return WriteVRequest(segments, do_sync)
end

requestid(::WriteVRequest) = kXR_writev

function body!(frame::Vector{UInt8}, r::WriteVRequest)
    frame[5] = r.do_sync ? kXR_wv_doSync : 0x00
    return frame
end

function payload(r::WriteVRequest)
    ndesc = 16 * length(r.segments)
    pl = zeros(UInt8, ndesc + sum(seg -> length(seg.data), r.segments))
    cursor = ndesc + 1
    for (i, seg) in enumerate(r.segments)
        off = 16 * (i - 1) + 1
        set_bytes!(pl, off, collect(seg.fhandle))
        set_u32!(pl, off + 4, UInt32(length(seg.data)))
        set_u64!(pl, off + 8, reinterpret(UInt64, seg.offset))
        set_bytes!(pl, cursor, seg.data)
        cursor += length(seg.data)
    end
    return pl
end

# ---- paged I/O (per-page CRC32c; libxrdc ops_file_pg.c) ----

"""
    PgReadRequest(fhandle, offset::Int64, rlen::Int32)

`kXR_pgread` — paged read with per-page CRC32c integrity. The response uses
`kXR_status` framing (see [`decode_status_body`](@ref) /
[`decode_pages`](@ref)), not the plain `kXR_ok` path.
"""
struct PgReadRequest <: Request
    fhandle::NTuple{4,UInt8}
    offset::Int64
    rlen::Int32
end

requestid(::PgReadRequest) = kXR_pgread

function body!(frame::Vector{UInt8}, r::PgReadRequest)
    set_bytes!(frame, 5, collect(r.fhandle))
    set_u64!(frame, 9, reinterpret(UInt64, r.offset))
    set_u32!(frame, 17, reinterpret(UInt32, r.rlen))
    return frame
end

"""
    PgWriteRequest(fhandle, offset::Int64, data::Vector{UInt8}; reqflags::UInt8=0x00)

`kXR_pgwrite` — paged write. The payload is built with
[`encode_pages`](@ref) (`[crc32c][page ≤4096]` units aligned to the file
offset). `reqflags = kXR_pgRetry` marks a corrupt-page resend.
"""
struct PgWriteRequest <: Request
    fhandle::NTuple{4,UInt8}
    offset::Int64
    data::Vector{UInt8}
    reqflags::UInt8
end

function PgWriteRequest(
    fhandle::NTuple{4,UInt8}, offset::Int64, data::Vector{UInt8}; reqflags::UInt8=0x00
)
    return PgWriteRequest(fhandle, offset, data, reqflags)
end

requestid(::PgWriteRequest) = kXR_pgwrite

function body!(frame::Vector{UInt8}, r::PgWriteRequest)
    set_bytes!(frame, 5, collect(r.fhandle))
    set_u64!(frame, 9, reinterpret(UInt64, r.offset))
    frame[17] = 0x00        # pathid
    frame[18] = r.reqflags
    return frame
end

payload(r::PgWriteRequest) = encode_pages(r.data, r.offset)
