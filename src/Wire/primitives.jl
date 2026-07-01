# Big-endian accessors over byte buffers. The XRootD wire is big-endian
# throughout; these are the only functions in the package that touch
# individual wire bytes (mirrors nginx-xrootd frame_hdr.h's accessor set).
# All offsets are 1-based.

"""
    get_u16(buf::AbstractVector{UInt8}, off::Integer) -> UInt16

Read a big-endian `UInt16` from `buf` starting at 1-based offset `off`.
"""
function get_u16(buf::AbstractVector{UInt8}, off::Integer)
    checkbounds(buf, off:(off + 1))
    return (UInt16(buf[off]) << 8) | UInt16(buf[off + 1])
end

"""
    get_u32(buf::AbstractVector{UInt8}, off::Integer) -> UInt32

Read a big-endian `UInt32` from `buf` starting at 1-based offset `off`.
"""
function get_u32(buf::AbstractVector{UInt8}, off::Integer)
    checkbounds(buf, off:(off + 3))
    v = UInt32(0)
    for i in 0:3
        v = (v << 8) | UInt32(buf[off + i])
    end
    return v
end

"""
    get_u64(buf::AbstractVector{UInt8}, off::Integer) -> UInt64

Read a big-endian `UInt64` from `buf` starting at 1-based offset `off`.
"""
function get_u64(buf::AbstractVector{UInt8}, off::Integer)
    checkbounds(buf, off:(off + 7))
    v = UInt64(0)
    for i in 0:7
        v = (v << 8) | UInt64(buf[off + i])
    end
    return v
end

"""
    set_u16!(buf::AbstractVector{UInt8}, off::Integer, v::UInt16) -> buf

Write `v` big-endian into `buf` at 1-based offset `off`.
"""
function set_u16!(buf::AbstractVector{UInt8}, off::Integer, v::UInt16)
    checkbounds(buf, off:(off + 1))
    buf[off] = (v >> 8) % UInt8
    buf[off + 1] = v % UInt8
    return buf
end

"""
    set_u32!(buf::AbstractVector{UInt8}, off::Integer, v::UInt32) -> buf

Write `v` big-endian into `buf` at 1-based offset `off`.
"""
function set_u32!(buf::AbstractVector{UInt8}, off::Integer, v::UInt32)
    checkbounds(buf, off:(off + 3))
    for i in 0:3
        buf[off + i] = (v >> (8 * (3 - i))) % UInt8
    end
    return buf
end

"""
    set_u64!(buf::AbstractVector{UInt8}, off::Integer, v::UInt64) -> buf

Write `v` big-endian into `buf` at 1-based offset `off`.
"""
function set_u64!(buf::AbstractVector{UInt8}, off::Integer, v::UInt64)
    checkbounds(buf, off:(off + 7))
    for i in 0:7
        buf[off + i] = (v >> (8 * (7 - i))) % UInt8
    end
    return buf
end

"""
    set_bytes!(buf::AbstractVector{UInt8}, off::Integer, src::AbstractVector{UInt8}) -> buf

Copy `src` into `buf` starting at 1-based offset `off`.
"""
function set_bytes!(buf::AbstractVector{UInt8}, off::Integer, src::AbstractVector{UInt8})
    checkbounds(buf, off:(off + length(src) - 1))
    copyto!(buf, off, src, 1, length(src))
    return buf
end

"""
    set_padded_string!(buf::AbstractVector{UInt8}, off::Integer, width::Integer, s::AbstractString) -> buf

Write `s` into the fixed `width`-byte field at `off`: NUL-padded when shorter,
truncated when longer (the wire contract of e.g. `ClientLoginRequest.username`
— NUL-padded, NOT NUL-terminated at exactly `width` bytes).
"""
function set_padded_string!(
    buf::AbstractVector{UInt8}, off::Integer, width::Integer, s::AbstractString
)
    checkbounds(buf, off:(off + width - 1))
    bytes = codeunits(s)
    n = min(length(bytes), width)
    copyto!(buf, off, bytes, 1, n)
    for i in n:(width - 1)
        buf[off + i] = 0x00
    end
    return buf
end

"""
    get_bounded_string(buf::AbstractVector{UInt8}, off::Integer, maxlen::Integer) -> String

Read at most `maxlen` bytes from `buf` at `off`, stopping early at a NUL.
Wire strings are NOT guaranteed NUL-terminated (see frame_hdr.h on the
kXR_error message) — never assume a terminator exists.
"""
function get_bounded_string(buf::AbstractVector{UInt8}, off::Integer, maxlen::Integer)
    maxlen <= 0 && return ""
    checkbounds(buf, off:(off + maxlen - 1))
    last = off + maxlen - 1
    stop = last
    for i in off:last
        if buf[i] == 0x00
            stop = i - 1
            break
        end
    end
    return String(buf[off:stop])
end
