# Frame-level codecs: the 20-byte client hello, the 24-byte ClientRequestHdr,
# and the 8-byte ServerResponseHdr (nginx-xrootd wire_core_requests.h,
# frame_hdr.h).

"Length in bytes of the ClientRequestHdr that starts every request frame."
const REQUEST_HDRLEN = 24

"Length in bytes of the ServerResponseHdr that starts every response frame."
const RESPONSE_HDRLEN = 8

"""
    HANDSHAKE

The fixed 20-byte `ClientInitHandShake` sent immediately after TCP connect:
three zero words, then `4`, then `ROOTD_PQ` (2012), all big-endian. The
server validates these exact bytes before anything else happens.
"""
const HANDSHAKE = let hs = zeros(UInt8, 20)
    set_u32!(hs, 13, UInt32(4))
    set_u32!(hs, 17, ROOTD_PQ)
    hs
end

"""
    Request

Abstract supertype of every client request. A concrete request defines:

- `requestid(req)::UInt16` — its `kXR_*` opcode (required);
- `body!(frame, req)` — write its parameters into bytes 5:20 of the 24-byte
  header (optional; default leaves them zero);
- `payload(req)::AbstractVector{UInt8}` — the bytes following the header
  (optional; default empty). `dlen` is derived from its length.

[`encode`](@ref) turns any `Request` into wire bytes.
"""
abstract type Request end

"""
    requestid(req::Request) -> UInt16

The `kXR_*` opcode of `req`. Every concrete request must implement this.
"""
function requestid end

"""
    body!(frame::Vector{UInt8}, req::Request) -> frame

Write the request's 16 parameter bytes into `frame[5:20]`. The default
writes nothing (all-zero body, e.g. `kXR_ping`).
"""
body!(frame::Vector{UInt8}, ::Request) = frame

"""
    payload(req::Request) -> AbstractVector{UInt8}

The payload bytes that follow the 24-byte header (default: none).
"""
payload(::Request) = UInt8[]

"""
    encode(req::Request, streamid::UInt16) -> Vector{UInt8}

Serialize `req` as a complete wire frame: 24-byte `ClientRequestHdr`
(streamid, opcode, 16 parameter bytes, dlen) followed by the payload.
`streamid` is owned by the Session layer, which stamps each in-flight
request with a distinct id and matches responses back by it.
"""
function encode(req::Request, streamid::UInt16)
    pl = payload(req)
    frame = zeros(UInt8, REQUEST_HDRLEN + length(pl))
    set_u16!(frame, 1, streamid)
    set_u16!(frame, 3, requestid(req))
    body!(frame, req)
    set_u32!(frame, 21, UInt32(length(pl)))
    isempty(pl) || set_bytes!(frame, REQUEST_HDRLEN + 1, pl)
    return frame
end

encode(req::Request, streamid::Integer) = encode(req, UInt16(streamid))

"""
    ResponseHeader

Decoded `ServerResponseHdr`: `streamid` echoes the request's id, `status` is
`kXR_ok` / `kXR_error` / `kXR_oksofar` / ..., and `dlen` bytes of body follow
on the wire.
"""
struct ResponseHeader
    streamid::UInt16
    status::UInt16
    dlen::UInt32
end

"""
    decode_header(bytes::AbstractVector{UInt8}) -> ResponseHeader

Decode the leading 8-byte `ServerResponseHdr` of a response frame.
"""
function decode_header(bytes::AbstractVector{UInt8})
    if length(bytes) < RESPONSE_HDRLEN
        throw(ArgumentError("response header needs 8 bytes, got $(length(bytes))"))
    end
    return ResponseHeader(get_u16(bytes, 1), get_u16(bytes, 3), get_u32(bytes, 5))
end
