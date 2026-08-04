# Operation status, mirroring the 0.2.x XRootDStatus surface (isOK/isError,
# printable). Wire responses map onto it via status_from.

"""
    XRootDStatus(status=0x0000, code=0x0000, errNo=0, message="")

Result status of an operation. `status == 0` means success ([`isOK`](@ref));
`code` carries the server's kXR error code and `errNo` the POSIX-style errno
when the server supplied one.
"""
struct XRootDStatus
    status::UInt16
    code::UInt16
    errNo::Int32
    message::String
end

XRootDStatus() = XRootDStatus(0x0000, 0x0000, Int32(0), "")
XRootDStatus(status::Integer) = XRootDStatus(UInt16(status), 0x0000, Int32(0), "")

function XRootDStatus(
    status::Integer, code::Integer, errNo::Integer, message::AbstractString
)
    return XRootDStatus(UInt16(status), UInt16(code), Int32(errNo), String(message))
end

"""
    isOK(st::XRootDStatus) -> Bool

`true` when the operation succeeded.
"""
isOK(st::XRootDStatus) = st.status == 0x0000

"""
    isError(st::XRootDStatus) -> Bool

`true` when the operation failed.
"""
isError(st::XRootDStatus) = !isOK(st)

"""
    error_name(st::XRootDStatus) -> String

The protocol name of the server error `st` carries (`"kXR_NotFound"`), for
logs and messages meant to be read. `ErrorCode` is the namespace to compare
against in code: `st.code == ErrorCode.NotFound`.
"""
error_name(st::XRootDStatus) = Wire.error_name(st.code)

function Base.show(io::IO, st::XRootDStatus)
    if isOK(st)
        print(io, "[SUCCESS]")
    else
        print(io, "[ERROR] ($(st.code), $(st.errNo)): $(st.message)")
    end
    return nothing
end

"Build an XRootDStatus from a terminal wire response."
function status_from(hdr::Wire.ResponseHeader, body::Vector{UInt8})
    hdr.status == Wire.kXR_ok && return XRootDStatus()
    if hdr.status == Wire.kXR_error && length(body) >= 4
        err = Wire.decode_error(body)
        return XRootDStatus(hdr.status, UInt16(err.errnum & 0xffff), 0, err.message)
    end
    return XRootDStatus(hdr.status, 0x0000, 0, "unexpected response status $(hdr.status)")
end
