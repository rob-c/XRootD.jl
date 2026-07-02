# Checksum algorithms for the checksum tools. CRC32c comes from the stdlib
# (hardware-accelerated); Adler-32 and CRC-64/XZ are implemented here.

"""
    adler32(data::AbstractVector{UInt8}; init=0x00000001) -> UInt32

Adler-32 checksum (RFC 1950). `init` allows streaming continuation.
"""
function adler32(data::AbstractVector{UInt8}; init::UInt32=0x00000001)
    a = init & 0xffff
    b = (init >> 16) & 0xffff
    for byte in data
        a = (a + byte) % 65521
        b = (b + a) % 65521
    end
    return (b << 16) | a
end

# CRC-64/XZ: reflected, poly 0x42F0E1EBA9EA3693, init/xorout all-ones.
const _CRC64_TABLE = let t = Vector{UInt64}(undef, 256)
    poly = 0xC96C5795D7870F42   # bit-reversed 0x42F0E1EBA9EA3693
    for n in 0:255
        c = UInt64(n)
        for _ in 1:8
            c = (c & 0x1) != 0 ? (poly ⊻ (c >> 1)) : (c >> 1)
        end
        t[n + 1] = c
    end
    t
end

"""
    crc64xz(data::AbstractVector{UInt8}; init=0xffffffffffffffff) -> UInt64

CRC-64/XZ checksum (the `.xz` / `xrdcrc64` variant). `init` allows streaming
continuation (pass the previous return XOR'd with all-ones is NOT needed;
pass the raw previous state's complement — see `checksum_stream`).
"""
function crc64xz(data::AbstractVector{UInt8}; init::UInt64=0xffffffffffffffff)
    c = init
    for byte in data
        c = _CRC64_TABLE[((c ⊻ byte) & 0xff) + 1] ⊻ (c >> 8)
    end
    return c ⊻ 0xffffffffffffffff
end

"""
    checksum_file(url::AbstractString, algo::Symbol) -> String

Compute a checksum of a local path or `root://` file by pulling the bytes
through the [`Storage`](@ref) layer. `algo` is `:adler32`, `:crc32c`, or
`:crc64`. Returns the lowercase hex digest.
"""
function checksum_file(url::AbstractString, algo::Symbol)
    backend = storage_for(url)
    buf = IOBuffer()
    code = storage_read(backend, buf)
    code == :ok || error("cannot read $url for checksum ($code)")
    data = take!(buf)
    if algo === :adler32
        return string(adler32(data); base=16, pad=8)
    elseif algo === :crc32c
        return string(CRC32c.crc32c(data); base=16, pad=8)
    elseif algo === :crc64
        return string(crc64xz(data); base=16, pad=16)
    else
        throw(ArgumentError("unknown checksum algorithm $algo"))
    end
end
