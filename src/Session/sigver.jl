# kXR_sigver request signing. When a high-security server (sec_level ≥ 2)
# requires an opcode to be signed, a kXR_sigver frame carrying
# HMAC-SHA256(signing_key, seqno_be(8) || request_hdr(24) || payload) is sent
# as a PREFIX to the covered request (libxrdc sigver.c). Conformant servers
# reply only on failure, so nothing is read back here.

"""
    sigver_hmac(key, seqno::UInt64, header24, payload) -> Vector{UInt8}

The HMAC-SHA256 a `kXR_sigver` frame carries: over
`seqno_be(8) || request_header(24) || payload`, byte-identical to the
server's verifier.
"""
function sigver_hmac(
    key::AbstractVector{UInt8},
    seqno::UInt64,
    header24::AbstractVector{UInt8},
    payload::AbstractVector{UInt8},
)
    msg = Vector{UInt8}(undef, 8)
    for i in 0:7
        msg[i + 1] = (seqno >> (8 * (7 - i))) % UInt8
    end
    append!(msg, header24)
    append!(msg, payload)
    return hmac_sha256(collect(key), msg)
end

"""
    sign_frame(conn, request_frame) -> Union{Vector{UInt8},Nothing}

Build the `kXR_sigver` prefix frame for an already-encoded `request_frame`
(24-byte header + payload) when the connection requires signing for that
opcode; `nothing` when signing is not needed. `conn` must carry
`signing_key`, `sec_level`, and a mutable `sig_seqno`.
"""
function sign_frame(conn::Connection, request_frame::Vector{UInt8})
    (conn.sec_level < 2 || conn.signing_key === nothing) && return nothing
    reqid = Wire.get_u16(request_frame, 3)
    sigver_required(reqid) || return nothing
    conn.sig_seqno += UInt64(1)
    header24 = @view request_frame[1:Wire.REQUEST_HDRLEN]
    payload = @view request_frame[(Wire.REQUEST_HDRLEN + 1):end]
    mac = sigver_hmac(something(conn.signing_key), conn.sig_seqno, header24, payload)
    sid = Wire.get_u16(request_frame, 1)
    return Wire.encode(Wire.SigverRequest(reqid, conn.sig_seqno, mac), sid)
end

# Opcodes that mutate state or open files must be signed at sec_level ≥ 2
# (mirrors the server's xrootd_gsi_sigver_required policy).
const _SIGNED_OPCODES = Set{UInt16}([
    Wire.kXR_open,
    Wire.kXR_write,
    Wire.kXR_writev,
    Wire.kXR_pgwrite,
    Wire.kXR_truncate,
    Wire.kXR_rm,
    Wire.kXR_rmdir,
    Wire.kXR_mkdir,
    Wire.kXR_mv,
    Wire.kXR_chmod,
    Wire.kXR_fattr,
    Wire.kXR_set,
    Wire.kXR_prepare,
])

sigver_required(reqid::UInt16) = reqid in _SIGNED_OPCODES
