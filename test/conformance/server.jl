# A strict, spec-checking XRootD server for pure-Julia conformance testing.
#
# Unlike the permissive mock in test/session/test_connection.jl, this server
# PARSES what the client sends the way stock XrdXrootd does — every framing
# rule the protocol states is checked and any breach is recorded in
# `srv.violations`, which the tests assert stays empty. It also keeps a real
# in-memory file, so a write path can be verified by reading back the bytes
# the server actually stored rather than by trusting an "ok" status.
#
# Decoding here is deliberately independent of src/Wire/responses.jl (page
# units, CRC32c, readv/writev descriptors are re-derived from the primitives)
# so the tests cannot pass by agreeing with the encoder's own bugs.

using Sockets
using CRC32c: crc32c
using XRootD: Wire, Session

const CONF_PAGE = Wire.kXR_pgPageSZ
const CONF_FHANDLE = (0x00, 0x00, 0x00, 0x07)

"10 000 deterministic bytes — two full 4 KiB pages plus a short one."
const CONF_CONTENT = UInt8[(37 * i + 11) % 256 for i in 1:10_000]

"""
A conformance server: one in-memory file plus response-shaping knobs the
tests flip between operations. `violations` collects every protocol breach
seen from the client; `ops` records the requestid of each request served, in
order, so tests can assert on the *sequence* a client emitted (a `kXR_sync`
before `kXR_close`, a `kXR_pgRetry` after a checksum error).
"""
Base.@kwdef mutable struct ConfServer
    data::Vector{UInt8} = UInt8[]
    violations::Vector{String} = String[]
    ops::Vector{UInt16} = UInt16[]
    logins::Vector{String} = String[]
    # response shaping
    read_chunk::Int = 0         # >0: split read replies into kXR_oksofar chunks
    wait_once::Bool = false     # answer the next read with kXR_wait 1, then normally
    async_read::Bool = false    # deliver the next read via kXR_attn/kXR_asynresp
    unsolicited::Bool = false   # precede the next reply with a frame for no one
    over_answer::Int = 0        # >0: return this many bytes MORE than requested
    huge_dlen::Bool = false     # claim a body past Wire.DLEN_MAX, then hang up (sticky)
    stall::Bool = false         # accept the request and never answer
    read_limit::Int = 0         # >0: never serve bytes at or past this file offset
    corrupt_page::Bool = false  # flip a CRC bit in the next pgread reply
    short_pgdlen::Bool = false  # announce a page unit that is cut off
    drop_readv::Set{Int} = Set{Int}()   # readv segments at these offsets are omitted
    bad_once::Set{Int} = Set{Int}()     # pgwrite pages reported corrupt on first try
    bad_always::Set{Int} = Set{Int}()   # pgwrite pages reported corrupt forever
    fail_write::Bool = false
    fail_sync::Bool = false
    fail_close::Bool = false
    # kXR_bind data paths
    paths::Dict{UInt8,IO} = Dict{UInt8,IO}()    # bound path id → its socket
    next_pathid::UInt8 = 0x01
    refuse_bind::Bool = false   # answer the next kXR_bind with an error
    bind_zero::Bool = false     # hand out path id 0, the control link's own
end

"The 16-byte session id this server hands out at login and demands at bind."
const CONF_SESSID = UInt8.(1:16)

"Record a protocol breach; the tests fail on a non-empty violation list."
flag!(srv::ConfServer, msg::AbstractString) = push!(srv.violations, String(msg))

"Reset the shaping knobs and the recorded history, keeping the file content."
function conf_reset!(srv::ConfServer)
    empty!(srv.violations)
    empty!(srv.ops)
    empty!(srv.logins)
    srv.read_chunk = 0
    srv.wait_once = false
    srv.async_read = false
    srv.unsolicited = false
    srv.over_answer = 0
    srv.huge_dlen = false
    srv.stall = false
    srv.read_limit = 0
    srv.corrupt_page = false
    srv.short_pgdlen = false
    empty!(srv.drop_readv)
    empty!(srv.bad_once)
    empty!(srv.bad_always)
    srv.fail_write = false
    srv.fail_sync = false
    srv.fail_close = false
    srv.refuse_bind = false
    srv.bind_zero = false
    return srv
end

# ---- byte helpers (independent of the Wire encoders under test) ----

cs_be32(v::Integer) = Wire.set_u32!(zeros(UInt8, 4), 1, UInt32(v))
cs_be64(v::Integer) = Wire.set_u64!(zeros(UInt8, 8), 1, UInt64(v))
cs_i64(b::AbstractVector{UInt8}, i) = Int(reinterpret(Int64, Wire.get_u64(b, i)))
cs_i32(b::AbstractVector{UInt8}, i) = Int(reinterpret(Int32, Wire.get_u32(b, i)))

function cs_hdr(sid::UInt16, status::UInt16, dlen::Integer)
    h = zeros(UInt8, 8)
    Wire.set_u16!(h, 1, sid)
    Wire.set_u16!(h, 3, status)
    Wire.set_u32!(h, 5, UInt32(dlen))
    return h
end

function cs_ok(sock, sid, body=UInt8[])
    return write(sock, vcat(cs_hdr(sid, Wire.kXR_ok, length(body)), body))
end

function cs_error(sock, sid, errnum, msg)
    body = vcat(cs_be32(errnum), Vector{UInt8}(codeunits(msg)))
    return write(sock, vcat(cs_hdr(sid, Wire.kXR_error, length(body)), body))
end

"""
Split `data` into `[crc32c][page]` units aligned to the FILE offset: the
first unit runs only to the next 4 KiB boundary. Re-derived from crc32c
rather than reusing `Wire.encode_pages`, which is what these tests check.
"""
function cs_page_units(data::AbstractVector{UInt8}, offset::Integer)
    out = UInt8[]
    pos = 0
    while pos < length(data)
        n = min(CONF_PAGE - (offset + pos) % CONF_PAGE, length(data) - pos)
        page = data[(pos + 1):(pos + n)]
        append!(out, cs_be32(crc32c(page)))
        append!(out, page)
        pos += n
    end
    return out
end

"One kXR_status frame: header (dlen=24) + CRC'd 24-byte body + `pages` trailer."
function cs_status(sid::UInt16, reqid::UInt16, resptype::UInt8, offset, pages)
    sb = zeros(UInt8, Wire.STATUS_BODY_LEN)
    Wire.set_u16!(sb, 5, sid)
    sb[7] = UInt8(reqid - 3000)
    sb[8] = resptype
    Wire.set_u32!(sb, 13, UInt32(length(pages)))
    Wire.set_u64!(sb, 17, UInt64(offset))
    Wire.set_u32!(sb, 1, crc32c(sb[5:24]))
    return vcat(cs_hdr(sid, Wire.kXR_status, Wire.STATUS_BODY_LEN), sb, pages)
end

# ---- request intake ----

"Read one request: the 24-byte header plus exactly `dlen` payload bytes."
function cs_take(sock)
    frame = read(sock, 24)
    length(frame) == 24 || throw(EOFError())
    dlen = Int(Wire.get_u32(frame, 21))
    payload = dlen > 0 ? read(sock, dlen) : UInt8[]
    length(payload) == dlen || throw(EOFError())
    return frame, payload
end

"""
Read one request, taking a path-routed `kXR_write`'s data off the bound
socket instead of the control link. `dlen` counts those bytes wherever they
travel, which is the rule this parses strictly: a client that also put them
in the frame would leave `dlen` bytes of data to be read as the next request
header.
"""
function cs_take_routed(srv::ConfServer, sock)
    frame = read(sock, 24)
    length(frame) == 24 || throw(EOFError())
    dlen = Int(Wire.get_u32(frame, 21))
    src = sock
    if Wire.get_u16(frame, 3) == Wire.kXR_write && frame[17] != 0x00
        src = get(srv.paths, frame[17], nothing)
        if src === nothing
            flag!(srv, "kXR_write: names unbound path id $(frame[17])")
            src = sock
        end
    end
    payload = dlen > 0 ? read(src, dlen) : UInt8[]
    length(payload) == dlen || throw(EOFError())
    return frame, payload
end

"""
The socket a reply for `pathid` goes out on: the bound data path, or the
control link for path 0. A `kXR_read` answered on the wrong link would still
reach the client — both are its sockets — so the tests assert the reply
arrives where it was asked for by having the server refuse to guess.
"""
function cs_reply_sock(srv::ConfServer, sock, pathid::UInt8)
    pathid == 0x00 && return sock
    out = get(srv.paths, pathid, nothing)
    out === nothing && flag!(srv, "reply: unbound path id $pathid")
    return out === nothing ? sock : out
end

"Check the fhandle a request carries; `at` is its byte offset in the frame."
function check_fhandle(srv::ConfServer, frame, what; at::Int=5)
    fh = (frame[at], frame[at + 1], frame[at + 2], frame[at + 3])
    fh == CONF_FHANDLE || flag!(srv, "$what: unknown fhandle $fh")
    return nothing
end

function apply_write!(srv::ConfServer, offset::Int, bytes::AbstractVector{UInt8})
    need = offset + length(bytes)
    length(srv.data) < need && append!(srv.data, zeros(UInt8, need - length(srv.data)))
    srv.data[(offset + 1):need] = bytes
    return nothing
end

# ---- per-request handlers ----

"""
Handshake, `kXR_protocol` and `kXR_login`, checked byte for byte. `srv` is any
conformance server with `violations` and `logins` lists — this file's, the
namespace server's and the redirector's alike, which bring a connection up
identically. The username every connection logs in as is recorded, so a test
can assert which identity was presented and to whom.

`bind_ok` also accepts a connection that ends its bring-up with `kXR_bind`
instead of `kXR_login` — an extra data path for a session that already
exists. Returns the path id assigned, or `0x00` for an ordinary login, so
the caller knows which kind of connection it is now serving.
"""
function serve_bringup(srv, sock; bind_ok::Bool=false)
    hello = read(sock, 20)
    length(hello) == 20 || throw(EOFError())
    hello[1:12] == zeros(UInt8, 12) || flag!(srv, "handshake: leading words not zero")
    Wire.get_u32(hello, 13) == 4 || flag!(srv, "handshake: bad length word")
    Wire.get_u32(hello, 17) == Wire.ROOTD_PQ || flag!(srv, "handshake: bad protocol token")
    write(sock, vcat(cs_hdr(0x0000, Wire.kXR_ok, 8), cs_be32(0x310), cs_be32(1)))
    pf, _ = cs_take(sock)
    Wire.get_u16(pf, 3) == Wire.kXR_protocol ||
        flag!(srv, "bring-up: expected kXR_protocol")
    write(
        sock, vcat(cs_hdr(Wire.get_u16(pf, 1), Wire.kXR_ok, 8), cs_be32(0x520), cs_be32(1))
    )
    lf, _ = cs_take(sock)
    rid = Wire.get_u16(lf, 3)
    if bind_ok && rid == Wire.kXR_bind
        return serve_bind(srv, sock, Wire.get_u16(lf, 1), lf)
    end
    rid == Wire.kXR_login || flag!(srv, "bring-up: expected kXR_login")
    # The username sits in the 8-byte NUL-padded header field, not the body.
    push!(srv.logins, String(rstrip(String(copy(lf[9:16])), '\0')))
    write(sock, vcat(cs_hdr(Wire.get_u16(lf, 1), Wire.kXR_ok, 16), CONF_SESSID))
    return 0x00
end

"""
`kXR_bind`: the request carries the 16-byte session id the login reply gave
out, and the answer is a one-byte path id. A bind that names an id this
server never issued is a breach — the whole point of the field is that a
second socket cannot join a session it cannot prove it belongs to.
"""
function serve_bind(srv::ConfServer, sock, sid::UInt16, frame)
    push!(srv.ops, Wire.kXR_bind)
    frame[5:20] == CONF_SESSID || flag!(srv, "kXR_bind: wrong session id")
    all(==(0x00), frame[21:24]) || flag!(srv, "kXR_bind: dlen is not zero")
    if srv.refuse_bind
        cs_error(sock, sid, 3000, "no data paths available")
        throw(EOFError())
    end
    pathid = srv.bind_zero ? 0x00 : srv.next_pathid
    write(sock, vcat(cs_hdr(sid, Wire.kXR_ok, 1), pathid))
    # Path id 0 is the control link's own: a client that accepts it would
    # route this connection's data back onto the other one, so nothing more
    # can arrive here either way.
    pathid == 0x00 && throw(EOFError())
    srv.next_pathid += 0x01
    srv.paths[pathid] = sock
    return pathid
end

"""
`kXR_read`, including the optional-arguments form: a `dlen` of 8 or more
carries the path id in its first byte and seven reserved bytes behind it,
with any pre-read hints after that. The data-bearing reply then goes out on
that path, while the control link stays free.
"""
function serve_read(srv::ConfServer, sock, sid, frame, payload=UInt8[])
    check_fhandle(srv, frame, "kXR_read")
    offset, rlen = cs_i64(frame, 9), cs_i32(frame, 17)
    offset < 0 && flag!(srv, "kXR_read: negative offset $offset")
    rlen < 0 && flag!(srv, "kXR_read: negative rlen $rlen")
    pathid = 0x00
    if !isempty(payload)
        if length(payload) < 8
            flag!(srv, "kXR_read: alen $(length(payload)) is under the 8-byte minimum")
        else
            (length(payload) - 8) % 16 == 0 ||
                flag!(srv, "kXR_read: pre-read hints are not 16 bytes each")
            all(==(0x00), payload[2:8]) ||
                flag!(srv, "kXR_read: reserved bytes of the optional args are not zero")
            pathid = payload[1]
        end
    end
    # Only the data-bearing answer moves: a kXR_wait or an error is a control
    # response, and stock XrdXrootd keeps those on the control link.
    out = cs_reply_sock(srv, sock, pathid)
    if srv.wait_once
        srv.wait_once = false
        return write(sock, vcat(cs_hdr(sid, Wire.kXR_wait, 4), cs_be32(1)))
    end
    if srv.huge_dlen
        # Left set until the test clears it: a server that lies about dlen does
        # not correct itself between two reads, and a client that reconnects
        # after the hang-up must meet the same lie rather than a fixed server.
        write(sock, cs_hdr(sid, Wire.kXR_ok, Wire.DLEN_MAX + 1))
        throw(EOFError())                       # hang up behind the lie
    end
    srv.stall && return nothing
    limit = srv.read_limit > 0 ? min(srv.read_limit, length(srv.data)) : length(srv.data)
    lo, hi = offset + 1, min(offset + rlen, limit)
    data = lo <= hi ? srv.data[lo:hi] : UInt8[]
    srv.over_answer > 0 && (data = vcat(data, zeros(UInt8, srv.over_answer)))
    if srv.unsolicited
        srv.unsolicited = false
        write(sock, vcat(cs_hdr(0xffff, Wire.kXR_ok, 3), UInt8[0x6e, 0x6f, 0x21]))
    end
    if srv.async_read
        srv.async_read = false
        inner = vcat(cs_be32(Wire.kXR_asynresp), zeros(UInt8, 4))
        body = vcat(inner, cs_hdr(sid, Wire.kXR_ok, length(data)), data)
        return write(sock, vcat(cs_hdr(0x0000, Wire.kXR_attn, length(body)), body))
    end
    if srv.read_chunk > 0 && !isempty(data)
        pos = 1
        while pos + srv.read_chunk <= length(data)
            chunk = data[pos:(pos + srv.read_chunk - 1)]
            write(out, vcat(cs_hdr(sid, Wire.kXR_oksofar, length(chunk)), chunk))
            pos += srv.read_chunk
        end
        return cs_ok(out, sid, data[pos:end])
    end
    return cs_ok(out, sid, data)
end

function serve_write(srv::ConfServer, sock, sid, frame, payload)
    check_fhandle(srv, frame, "kXR_write")
    offset = cs_i64(frame, 9)
    offset < 0 && flag!(srv, "kXR_write: negative offset $offset")
    # byte 17 is the path id, 18:20 are reserved — the data itself has already
    # been taken off whichever link byte 17 named (`cs_take_routed`).
    all(==(0x00), frame[18:20]) || flag!(srv, "kXR_write: reserved bytes are not zero")
    srv.fail_write && return cs_error(sock, sid, 3016, "write failed")
    apply_write!(srv, offset, payload)
    return cs_ok(sock, sid)
end

function serve_readv(srv::ConfServer, sock, sid, payload)
    if length(payload) % 16 != 0
        flag!(srv, "kXR_readv: dlen $(length(payload)) is not a multiple of 16")
        return cs_error(sock, sid, 3000, "bad read vector")
    end
    nseg = length(payload) ÷ 16
    nseg == 0 && flag!(srv, "kXR_readv: empty vector")
    nseg > Wire.VEC_MAXSEGS && flag!(srv, "kXR_readv: $nseg segments over the cap")
    out = UInt8[]
    for i in 1:nseg
        base = 16 * (i - 1)
        fh = (payload[base + 1], payload[base + 2], payload[base + 3], payload[base + 4])
        fh == CONF_FHANDLE || flag!(srv, "kXR_readv: segment $i has fhandle $fh")
        rlen = cs_i32(payload, base + 5)
        offset = cs_i64(payload, base + 9)
        rlen < 0 && flag!(srv, "kXR_readv: segment $i has negative rlen")
        offset in srv.drop_readv && continue
        lo, hi = offset + 1, min(offset + rlen, length(srv.data))
        data = lo <= hi ? srv.data[lo:hi] : UInt8[]
        append!(out, payload[(base + 1):(base + 4)])
        append!(out, cs_be32(length(data)))
        append!(out, cs_be64(offset))
        append!(out, data)
    end
    return cs_ok(sock, sid, out)
end

"""
`kXR_writev` the way stock XrdXrootd parses it: `dlen` frames ONLY the
`N×16` descriptor block, and `sum(wlen)` bytes of data follow the frame. A
client that counts its data inside `dlen` desynchronizes here — which is the
point of parsing it this strictly.
"""
function serve_writev(srv::ConfServer, sock, sid, frame, payload)
    if length(payload) % 16 != 0
        flag!(srv, "kXR_writev: dlen $(length(payload)) is not a multiple of 16")
        return cs_error(sock, sid, 3000, "Write vector is invalid")
    end
    nseg = length(payload) ÷ 16
    nseg == 0 && flag!(srv, "kXR_writev: empty vector")
    descriptors = map(1:nseg) do i
        base = 16 * (i - 1)
        fh = (payload[base + 1], payload[base + 2], payload[base + 3], payload[base + 4])
        fh == CONF_FHANDLE || flag!(srv, "kXR_writev: segment $i has fhandle $fh")
        return (offset=cs_i64(payload, base + 9), wlen=cs_i32(payload, base + 5))
    end
    total = sum(d.wlen for d in descriptors; init=0)
    trailer = total > 0 ? read(sock, total) : UInt8[]
    length(trailer) == total || throw(EOFError())
    pos = 0
    for d in descriptors
        d.wlen < 0 && flag!(srv, "kXR_writev: negative wlen")
        apply_write!(srv, d.offset, view(trailer, (pos + 1):(pos + d.wlen)))
        pos += d.wlen
    end
    frame[5] in (0x00, Wire.kXR_wv_doSync) || flag!(srv, "kXR_writev: bad options byte")
    return cs_ok(sock, sid)
end

function serve_pgread(srv::ConfServer, sock, sid, frame)
    check_fhandle(srv, frame, "kXR_pgread")
    offset, rlen = cs_i64(frame, 9), cs_i32(frame, 17)
    lo, hi = offset + 1, min(offset + rlen, length(srv.data))
    data = lo <= hi ? srv.data[lo:hi] : UInt8[]
    if srv.short_pgdlen
        srv.short_pgdlen = false
        # a page unit cut off mid-CRC: the client must refuse, not guess
        return write(
            sock,
            cs_status(
                sid, Wire.kXR_pgread, Wire.kXR_FinalResult, offset, UInt8[0x00, 0x00]
            ),
        )
    end
    # one status frame per page unit, the last one Final
    pos, pgoff = 0, offset
    frames = Tuple{Int,Vector{UInt8}}[]
    while pos < length(data)
        n = min(CONF_PAGE - pgoff % CONF_PAGE, length(data) - pos)
        push!(frames, (pgoff, cs_page_units(view(data, (pos + 1):(pos + n)), pgoff)))
        pos += n
        pgoff += n
    end
    isempty(frames) && return write(
        sock, cs_status(sid, Wire.kXR_pgread, Wire.kXR_FinalResult, offset, UInt8[])
    )
    if srv.corrupt_page
        srv.corrupt_page = false
        frames[1][2][1] ⊻= 0xff                 # a bit-flip in the first CRC
    end
    for (i, (foff, pages)) in enumerate(frames)
        resptype = i == length(frames) ? Wire.kXR_FinalResult : Wire.kXR_PartialResult
        write(sock, cs_status(sid, Wire.kXR_pgread, resptype, foff, pages))
    end
    return nothing
end

"""
Validate a `kXR_pgwrite` payload as page units aligned to the request's file
offset, verifying every CRC32c, and store the pages. Returns the list of
file offsets the payload covered, or `nothing` when the framing is bad.
"""
function pgwrite_pages!(srv::ConfServer, offset::Int, payload::Vector{UInt8})
    offsets = Int[]
    pos, pgoff = 0, offset
    while pos < length(payload)
        if length(payload) - pos < 4
            flag!(srv, "kXR_pgwrite: page unit at $pgoff has no CRC")
            return nothing
        end
        n = min(CONF_PAGE - pgoff % CONF_PAGE, length(payload) - pos - 4)
        page = payload[(pos + 5):(pos + 4 + n)]
        if Wire.get_u32(payload, pos + 1) != crc32c(page)
            flag!(srv, "kXR_pgwrite: CRC32c mismatch on the page at $pgoff")
            return nothing
        end
        apply_write!(srv, pgoff, page)
        push!(offsets, pgoff)
        pos += 4 + n
        pgoff += n
    end
    return offsets
end

function serve_pgwrite(srv::ConfServer, sock, sid, frame, payload)
    check_fhandle(srv, frame, "kXR_pgwrite")
    offset = cs_i64(frame, 9)
    retry = (frame[18] & Wire.kXR_pgRetry) != 0
    offsets = pgwrite_pages!(srv, offset, payload)
    offsets === nothing && return cs_error(sock, sid, 3000, "bad page payload")
    retry &&
        length(offsets) > 1 &&
        flag!(srv, "kXR_pgRetry resent $(length(offsets)) pages")
    retry &&
        offset % CONF_PAGE != 0 &&
        offset != 0 &&
        flag!(srv, "kXR_pgRetry offset $offset is not page aligned")
    bad = Int[]
    for off in offsets
        if off in srv.bad_always
            push!(bad, off)
        elseif off in srv.bad_once
            delete!(srv.bad_once, off)
            push!(bad, off)
        end
    end
    # cseCRC[4] dlFirst[2] dlLast[2] then one big-endian offset per bad page
    trailer = isempty(bad) ? UInt8[] : zeros(UInt8, Wire.PGW_CSE_HDRLEN)
    for off in bad
        append!(trailer, cs_be64(off))
    end
    return write(
        sock, cs_status(sid, Wire.kXR_pgwrite, Wire.kXR_FinalResult, offset, trailer)
    )
end

function serve_conn(srv::ConfServer, sock)
    try
        pathid = serve_bringup(srv, sock; bind_ok=true)
        if pathid != 0x00
            # A bound data path carries data, never requests: it must stay
            # unread here, or the write bytes destined for it would be
            # consumed as request headers.
            while isopen(sock)
                sleep(0.02)
            end
            return nothing
        end
        while isopen(sock)
            frame, payload = cs_take_routed(srv, sock)
            sid, rid = Wire.get_u16(frame, 1), Wire.get_u16(frame, 3)
            sid == 0x0000 && flag!(srv, "$(Wire.request_name(rid)): streamid 0")
            push!(srv.ops, rid)
            if rid == Wire.kXR_open
                path = String(copy(payload))
                startswith(path, "/") || flag!(srv, "kXR_open: relative path $(repr(path))")
                cs_ok(sock, sid, collect(CONF_FHANDLE))
            elseif rid == Wire.kXR_stat
                # the fhandle form carries no path; the path form carries no handle
                isempty(payload) && check_fhandle(srv, frame, "kXR_stat"; at=17)
                line = "7 $(length(srv.data)) 48 1700000000"
                cs_ok(sock, sid, Vector{UInt8}(codeunits(line)))
            elseif rid == Wire.kXR_read
                serve_read(srv, sock, sid, frame, payload)
            elseif rid == Wire.kXR_write
                serve_write(srv, sock, sid, frame, payload)
            elseif rid == Wire.kXR_readv
                serve_readv(srv, sock, sid, payload)
            elseif rid == Wire.kXR_writev
                serve_writev(srv, sock, sid, frame, payload)
            elseif rid == Wire.kXR_pgread
                serve_pgread(srv, sock, sid, frame)
            elseif rid == Wire.kXR_pgwrite
                serve_pgwrite(srv, sock, sid, frame, payload)
            elseif rid == Wire.kXR_truncate
                check_fhandle(srv, frame, "kXR_truncate")
                size = cs_i64(frame, 9)
                size < 0 && flag!(srv, "kXR_truncate: negative size")
                resize!(srv.data, min(size, length(srv.data)))
                cs_ok(sock, sid)
            elseif rid == Wire.kXR_sync
                check_fhandle(srv, frame, "kXR_sync")
                srv.fail_sync ? cs_error(sock, sid, 3016, "sync failed") : cs_ok(sock, sid)
            elseif rid == Wire.kXR_close
                check_fhandle(srv, frame, "kXR_close")
                if srv.fail_close
                    cs_error(sock, sid, 3016, "close failed")
                else
                    cs_ok(sock, sid)
                end
            elseif rid == Wire.kXR_ping
                cs_ok(sock, sid)
            else
                flag!(srv, "unexpected request $(Wire.request_name(rid)) ($rid)")
                cs_error(sock, sid, 3000, "unsupported")
            end
        end
    catch
        # client hung up, or a deliberate hang-up from a shaping knob
    finally
        isopen(sock) && close(sock)
    end
    return nothing
end

"Start a conformance server; returns (srv, port)."
function start_conf_server(data::Vector{UInt8}=UInt8[])
    srv = ConfServer(; data=copy(data))
    listener = listen(ip"127.0.0.1", 0)
    _, port = getsockname(listener)
    @async while isopen(listener)
        local sock
        try
            sock = accept(listener)
        catch
            break
        end
        @async serve_conn(srv, sock)
    end
    return srv, Int(port)
end

"Every conformance file arms this stall deadline (ms)."
const CONF_STALL_MS = 15_000

"""
Open a File against the conformance server on `port`, with the whole-operation
stall deadline armed: a client that desynchronizes the stream — the way a
wrong `kXR_writev` framing would — then FAILS the test instead of hanging it.
"""
function conf_file(port::Int, flags=XRootD.XrdCl.OpenFlags.Update; stall_ms=CONF_STALL_MS)
    f = XRootD.XrdCl.File("root://127.0.0.1:$port//conf", flags)
    f === nothing && return nothing
    conn = f.conn
    conn === nothing || (conn.stall_deadline_ms = stall_ms)
    return f
end

"The requestids the server saw, as names, for order assertions."
op_names(srv::ConfServer) = [Wire.request_name(id) for id in srv.ops]
