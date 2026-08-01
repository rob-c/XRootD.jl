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
    check_vector_limits(nseg, total, what)

Reject a vector request that exceeds the client's segment-count
([`VEC_MAXSEGS`](@ref)) or aggregate-byte ([`VEC_MAXBYTES`](@ref)) caps, or
that carries no segments at all (libxrdc `brix_file_readv` / `brix_file_writev`
apply the same bounds before touching the wire). `what` names the operation in
the error message.
"""
function check_vector_limits(nseg::Integer, total::Integer, what::AbstractString)
    if nseg < 1 || nseg > VEC_MAXSEGS
        throw(ArgumentError("$what: bad segment count $nseg (want 1..$(VEC_MAXSEGS))"))
    end
    if total < 0 || total > VEC_MAXBYTES
        throw(ArgumentError("$what: payload $total exceeds $(VEC_MAXBYTES) bytes"))
    end
    return nothing
end

"""
    ReadVRequest(segments::Vector{ReadVSegment})

`kXR_readv` — scatter-gather read. The payload is one 16-byte
`readahead_list` entry per segment (`fhandle[4] + rlen[4] + offset[8]`, all
big-endian). The response interleaves a 16-byte echo header (carrying the
ACTUAL length) and the data per segment — see [`parse_readv`](@ref).

The segment count and the total requested length are bounded by
[`check_vector_limits`](@ref).
"""
struct ReadVRequest <: Request
    segments::Vector{ReadVSegment}

    function ReadVRequest(segments::Vector{ReadVSegment})
        total = 0
        for seg in segments
            seg.rlen < 0 && throw(ArgumentError("readv: negative rlen $(seg.rlen)"))
            total += Int(seg.rlen)
        end
        check_vector_limits(length(segments), total, "readv")
        return new(segments)
    end
end

"""
    readv_reply_cap(r::ReadVRequest) -> Int

The largest legitimate `kXR_readv` reply for `r`: one 16-byte echo header per
segment plus at most the requested bytes. The Session layer refuses to
accumulate beyond this.
"""
function readv_reply_cap(r::ReadVRequest)
    return 16 * length(r.segments) + sum(Int(seg.rlen) for seg in r.segments; init=0)
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

`kXR_writev` — scatter-gather write, all-or-nothing. Per the official
protocol, `dlen` covers ONLY the `write_list` descriptor block (stock
servers enforce `dlen % 16 == 0` and answer `kXR_ArgInvalid: "Write vector
is invalid"` otherwise); the concatenated segment data streams after the
frame as a [`trailer`](@ref). libxrdc counted the data inside `dlen` until
this framing was confirmed against stock xrootd 5.8 and its own standalone
`writev.c` handler; `brix_file_writev` now sends the descriptors-only form
too. `do_sync` sets `kXR_wv_doSync`.

The segment count and the total payload are bounded by
[`check_vector_limits`](@ref).
"""
struct WriteVRequest <: Request
    segments::Vector{WriteVSegment}
    do_sync::Bool

    function WriteVRequest(segments::Vector{WriteVSegment}, do_sync::Bool)
        total = sum(length(seg.data) for seg in segments; init=0)
        check_vector_limits(length(segments), total, "writev")
        return new(segments, do_sync)
    end
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
    pl = zeros(UInt8, 16 * length(r.segments))
    for (i, seg) in enumerate(r.segments)
        off = 16 * (i - 1) + 1
        set_bytes!(pl, off, collect(seg.fhandle))
        set_u32!(pl, off + 4, UInt32(length(seg.data)))
        set_u64!(pl, off + 8, reinterpret(UInt64, seg.offset))
    end
    return pl
end

function trailer(r::WriteVRequest)
    return reduce(vcat, (seg.data for seg in r.segments); init=UInt8[])
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
    pgread_reply_cap(r::PgReadRequest) -> Int

The largest legitimate `kXR_pgread` reply for `r`: the requested bytes plus a
4-byte CRC32c and a 24-byte `kXR_status` body per page (the worst case is one
partial frame per page). Bounding the accumulation this way also bounds a
server that answers with an unending stream of empty partial frames.
"""
function pgread_reply_cap(r::PgReadRequest)
    # +2 pages of slack: the first page may be short when the offset is not
    # page aligned, and the server may close with an empty final frame.
    npages = cld(Int(r.rlen), kXR_pgPageSZ) + 2
    return Int(r.rlen) + npages * (4 + STATUS_BODY_LEN)
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

"""
    pgwrite_reply_cap(r::PgWriteRequest) -> Int

The largest legitimate `kXR_pgwrite` reply for `r`: the `kXR_status` body plus
a checksum-error trailer ([`parse_pgwrite_cse`](@ref)) naming at most every
page the request wrote.
"""
function pgwrite_reply_cap(r::PgWriteRequest)
    npages = cld(length(r.data), kXR_pgPageSZ) + 1
    return STATUS_BODY_LEN + PGW_CSE_HDRLEN + 8 * npages
end

# ---- request signing (kXR_sigver; libxrdc sigver.c) ----

"""
    SigverRequest(expectrid::UInt16, seqno::UInt64, hmac::Vector{UInt8};
                  crypto::UInt8 = kXR_SHA256_sig, nodata::Bool = false)

`kXR_sigver` — a signing PREFIX sent before a request that a high-security
server (`sec_level ≥ 2`) requires to be signed. `expectrid` is the next
request's opcode, `seqno` a per-connection monotonic counter, and the
payload the 32-byte HMAC-SHA256 over `seqno_be(8) || request_hdr(24) ||
payload`. Conformant servers send no reply on success.
"""
struct SigverRequest <: Request
    expectrid::UInt16
    seqno::UInt64
    hmac::Vector{UInt8}
    crypto::UInt8
    nodata::Bool
end

function SigverRequest(
    expectrid::UInt16,
    seqno::UInt64,
    hmac::Vector{UInt8};
    crypto::UInt8=kXR_SHA256_sig,
    nodata::Bool=false,
)
    return SigverRequest(expectrid, seqno, hmac, crypto, nodata)
end

requestid(::SigverRequest) = kXR_sigver

function body!(frame::Vector{UInt8}, r::SigverRequest)
    set_u16!(frame, 5, r.expectrid)
    frame[7] = 0x00                              # version kXR_Ver_00
    frame[8] = r.nodata ? kXR_nodata_sig : 0x00
    set_u64!(frame, 9, r.seqno)
    frame[17] = r.crypto
    return frame
end

payload(r::SigverRequest) = r.hmac

# ---- extended filesystem operations ----

"""
    FattrRequest(subcode, path; names=String[], values=Vector{UInt8}[],
                 options=0x00, fhandle=(0,0,0,0))

`kXR_fattr` — extended-attribute operations. `subcode` is `kXR_fattrGet` /
`Set` / `Del` / `List`. Path-based payload is `"<path>\\0"` followed by the
nvec (`[int16 rc=0][name\\0]` per name) and, for Set, the vvec
(`[int32 BE vlen][value]` per value). Layouts: libxrdc `fattr.c`.
"""
struct FattrRequest <: Request
    subcode::UInt8
    path::String
    names::Vector{String}
    values::Vector{Vector{UInt8}}
    options::UInt8
    fhandle::NTuple{4,UInt8}
end

function FattrRequest(
    subcode::UInt8,
    path::AbstractString;
    names::Vector{<:AbstractString}=String[],
    values::Vector{<:AbstractVector{UInt8}}=Vector{UInt8}[],
    options::UInt8=0x00,
    fhandle::NTuple{4,UInt8}=(0x00, 0x00, 0x00, 0x00),
)
    return FattrRequest(
        subcode, String(path), String.(names), Vector{UInt8}.(values), options, fhandle
    )
end

requestid(::FattrRequest) = kXR_fattr

function body!(frame::Vector{UInt8}, r::FattrRequest)
    set_bytes!(frame, 5, collect(r.fhandle))
    frame[9] = r.subcode
    frame[10] = UInt8(length(r.names))
    frame[11] = r.options
    return frame
end

function payload(r::FattrRequest)
    io = IOBuffer()
    write(io, codeunits(r.path))
    write(io, 0x00)                       # path NUL terminator
    for name in r.names
        write(io, 0x00, 0x00)             # int16 rc = 0
        write(io, codeunits(name))
        write(io, 0x00)                   # name NUL terminator
    end
    if r.subcode == kXR_fattrSet
        for val in r.values
            len = zeros(UInt8, 4)
            set_u32!(len, 1, UInt32(length(val)))
            write(io, len)
            write(io, val)
        end
    end
    return take!(io)
end

"""
    SetattrRequest(path; flags, atime=(0,0), mtime=(0,0), uid=-1, gid=-1)

`kXR_setattr` (vendor ext) — set timestamps and/or owner. 44-byte
big-endian prefix (flags, atime s/ns, mtime s/ns, uid, gid) then the
NUL-terminated path.
"""
struct SetattrRequest <: Request
    path::String
    flags::Int32
    atime_s::Int64
    atime_ns::Int64
    mtime_s::Int64
    mtime_ns::Int64
    uid::Int32
    gid::Int32
end

function SetattrRequest(
    path::AbstractString;
    flags::Integer,
    atime::Tuple{Integer,Integer}=(0, 0),
    mtime::Tuple{Integer,Integer}=(0, 0),
    uid::Integer=-1,
    gid::Integer=-1,
)
    return SetattrRequest(
        String(path),
        Int32(flags),
        Int64(atime[1]),
        Int64(atime[2]),
        Int64(mtime[1]),
        Int64(mtime[2]),
        Int32(uid),
        Int32(gid),
    )
end

requestid(::SetattrRequest) = kXR_setattr

function payload(r::SetattrRequest)
    p = zeros(UInt8, SETATTR_PREFIX_LEN)
    set_u32!(p, 1, reinterpret(UInt32, r.flags))
    set_u64!(p, 5, reinterpret(UInt64, r.atime_s))
    set_u64!(p, 13, reinterpret(UInt64, r.atime_ns))
    set_u64!(p, 21, reinterpret(UInt64, r.mtime_s))
    set_u64!(p, 29, reinterpret(UInt64, r.mtime_ns))
    set_u32!(p, 37, reinterpret(UInt32, r.uid))
    set_u32!(p, 41, reinterpret(UInt32, r.gid))
    return vcat(p, Vector{UInt8}(codeunits(r.path)), UInt8[0x00])
end

"""
    SymlinkRequest(target, link)

`kXR_symlink` (vendor ext) — create `link` pointing at `target`. Payload
`target * " " * link`, `arg1len = ncodeunits(target)`.
"""
struct SymlinkRequest <: Request
    target::String
    link::String
end

SymlinkRequest(t::AbstractString, l::AbstractString) = SymlinkRequest(String(t), String(l))
requestid(::SymlinkRequest) = kXR_symlink
function body!(frame::Vector{UInt8}, r::SymlinkRequest)
    return (set_u16!(frame, 19, UInt16(ncodeunits(r.target))); frame)
end
payload(r::SymlinkRequest) = codeunits(r.target * " " * r.link)

"""
    LinkRequest(oldpath, newpath)

`kXR_link` (vendor ext) — hard-link `newpath` to `oldpath`. Payload
`old * " " * new`, `arg1len = ncodeunits(old)`.
"""
struct LinkRequest <: Request
    oldpath::String
    newpath::String
end

LinkRequest(o::AbstractString, n::AbstractString) = LinkRequest(String(o), String(n))
requestid(::LinkRequest) = kXR_link
function body!(frame::Vector{UInt8}, r::LinkRequest)
    return (set_u16!(frame, 19, UInt16(ncodeunits(r.oldpath))); frame)
end
payload(r::LinkRequest) = codeunits(r.oldpath * " " * r.newpath)

"""
    ReadlinkRequest(path)

`kXR_readlink` (vendor ext) — read a symlink's target. Response body is the
target string (dlen bytes).
"""
struct ReadlinkRequest <: Request
    path::String
end

ReadlinkRequest(p::AbstractString) = ReadlinkRequest(String(p))
requestid(::ReadlinkRequest) = kXR_readlink
payload(r::ReadlinkRequest) = codeunits(r.path)

"""
    PrepareRequest(paths; options=kXR_stage, prty=0, port=0, optionX=0)

`kXR_prepare` — stage/evict/cancel one or more paths. Payload is the
newline-separated path list.
"""
struct PrepareRequest <: Request
    paths::Vector{String}
    options::UInt8
    prty::UInt8
    port::UInt16
    optionX::UInt16
end

function PrepareRequest(
    paths::Vector{<:AbstractString};
    options::UInt8=kXR_stage,
    prty::UInt8=0x00,
    port::UInt16=0x0000,
    optionX::UInt16=0x0000,
)
    return PrepareRequest(String.(paths), options, prty, port, optionX)
end

requestid(::PrepareRequest) = kXR_prepare

function body!(frame::Vector{UInt8}, r::PrepareRequest)
    frame[5] = r.options
    frame[6] = r.prty
    set_u16!(frame, 7, r.port)
    set_u16!(frame, 9, r.optionX)
    return frame
end

payload(r::PrepareRequest) = codeunits(join(r.paths, "\n"))

"""
    merge_cgi(path, cgi) -> String

Attach opaque `cgi` to `path`, picking the separator the path needs: `?`
when it carries none yet, `&` when it already does. An empty `cgi` leaves
the path alone.
"""
function merge_cgi(path::AbstractString, cgi::AbstractString)
    isempty(cgi) && return String(path)
    return String(path) * (occursin('?', path) ? "&" : "?") * String(cgi)
end

"""
    with_cgi(r::Request, cgi::AbstractString) -> Request

Return `r` with `cgi` merged onto its path. A redirector answers with opaque
data of its own (the `kXR_redirect` body is `port` + `host[?cgi]`) and the
client has to present it to the target — that is how a manager hands the
data server it picked a one-shot token. The caller's own CGI is kept and the
redirector's appended, because both sides put meaning in it.

Requests that name no path, or two, are returned unchanged.
"""
with_cgi(r::Request, ::AbstractString) = r

for T in (
    ChmodRequest,
    DirlistRequest,
    FattrRequest,
    LocateRequest,
    MkdirRequest,
    OpenRequest,
    ReadlinkRequest,
    RmRequest,
    RmdirRequest,
    SetattrRequest,
    StatRequest,
    TruncateRequest,
)
    args = [f === :path ? :(merge_cgi(r.path, cgi)) : :(r.$f) for f in fieldnames(T)]
    @eval with_cgi(r::$T, cgi::AbstractString) = isempty(cgi) ? r : $T($(args...))
end
