# kXR_sigver request signing, secver 0 (XrdSecProtect). When the server's
# kXR_protocol trailer demands it, a request is preceded by a kXR_sigver
# frame carrying SHA-256(seqno_be(8) || request_hdr(24) || payload) encrypted
# with the session cipher — for sss that is XrdCryptoLite's bf32, the same
# CRC-then-Blowfish transform the credential itself used ([`bf32_encrypt`](@ref)).
# Which requests need signing comes from the trailer too: the advertised
# security level picks a tier, and the per-request secvec entries override it.
# Conformant servers reply only on failure, so nothing is read back here.

# Requests a signature could never protect — they precede the session key, or
# carry the signature itself (the server's own exempt list; BriX gsi_core.c).
const _SIGVER_EXEMPT = Set{UInt16}([
    Wire.kXR_login,
    Wire.kXR_protocol,
    Wire.kXR_auth,
    Wire.kXR_endsess,
    Wire.kXR_ping,
    Wire.kXR_sigver,
    Wire.kXR_bind,
])

# The modifying operations level 2 ("standard") signs. Levels above sign
# everything non-exempt; levels below sign nothing.
const _SIGVER_LEVEL2 = Set{UInt16}([
    Wire.kXR_open,
    Wire.kXR_write,
    Wire.kXR_pgwrite,
    Wire.kXR_writev,
    Wire.kXR_truncate,
    Wire.kXR_mkdir,
    Wire.kXR_rm,
    Wire.kXR_rmdir,
    Wire.kXR_mv,
    Wire.kXR_chmod,
    Wire.kXR_fattr,
    Wire.kXR_chkpoint,
    Wire.kXR_clone,
])

"""
    sigver_required(reqid, level; overrides = Dict{UInt16,UInt8}()) -> Bool

Whether `reqid` must be signed under advertised security `level`. The exempt
set is absolute — those requests exist below or beside the signing contract.
For everything else a secvec override decides first (`kXR_signIgnore` never,
`kXR_signNeeded` always) and `kXR_signLikely` — or no entry — falls back to
the level tiers: below 2 nothing, at 2 the modifying set, above 2 everything.
"""
function sigver_required(
    reqid::UInt16, level::Integer; overrides::Dict{UInt16,UInt8}=Dict{UInt16,UInt8}()
)
    reqid in _SIGVER_EXEMPT && return false
    o = get(overrides, reqid, Wire.kXR_signLikely)
    o == Wire.kXR_signIgnore && return false
    o == Wire.kXR_signNeeded && return true
    level < 2 && return false
    level == 2 && return reqid in _SIGVER_LEVEL2
    return true
end

"""
    sigver_hash(seqno::UInt64, header24, payload; nodata=false) -> Vector{UInt8}

The SHA-256 a secver-0 signature encrypts: over
`seqno_be(8) || request_header(24) || payload`, with the payload left out
when `nodata` (the write-data exclusion the server mirrors).
"""
function sigver_hash(
    seqno::UInt64,
    header24::AbstractVector{UInt8},
    payload::AbstractVector{UInt8};
    nodata::Bool=false,
)
    msg = Vector{UInt8}(undef, 8)
    for i in 0:7
        msg[i + 1] = (seqno >> (8 * (7 - i))) % UInt8
    end
    append!(msg, header24)
    nodata || append!(msg, payload)
    return sha256(msg)
end

"""
    sign_frame(conn, request_frame) -> Union{Vector{UInt8},Nothing}

Build the `kXR_sigver` prefix frame for an already-encoded `request_frame`
(24-byte header + payload) when the connection's signing contract covers
that opcode; `nothing` when it does not, or when no session key was ever
established. Write payloads are excluded from the hash unless the server
asked for data coverage (`kXR_secOData`). The prefix reuses the covered
request's streamid, and each signature consumes the next `sig_seqno`.
"""
function sign_frame(conn::Connection, request_frame::Vector{UInt8})
    key = conn.signing_key
    key === nothing && return nothing
    reqid = Wire.get_u16(request_frame, 3)
    sigver_required(reqid, conn.sec_level; overrides=conn.sec_overrides) || return nothing
    nodata =
        (reqid == Wire.kXR_write || reqid == Wire.kXR_pgwrite) &&
        (conn.sec_opts & Wire.kXR_secOData) == 0
    conn.sig_seqno += UInt64(1)
    hash = sigver_hash(
        conn.sig_seqno,
        @view(request_frame[1:Wire.REQUEST_HDRLEN]),
        @view(request_frame[(Wire.REQUEST_HDRLEN + 1):end]);
        nodata,
    )
    blob = bf32_encrypt(key, hash)
    sid = Wire.get_u16(request_frame, 1)
    return Wire.encode(Wire.SigverRequest(reqid, conn.sig_seqno, blob; nodata), sid)
end
