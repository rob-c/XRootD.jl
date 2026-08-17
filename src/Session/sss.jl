# SSS (Simple Shared Secret) credential construction. Byte-for-byte the
# format of the shared kernel `xrootd_sss_build_credential`
# (src/core/compat/sss_bf.c + src/protocols/root/protocol/sss.h): a 16-byte
# outer header, then Blowfish-CFB64 over the data header + NAME TLV +
# IEEE-CRC32. Keytab grammar: src/auth/sss/sss_keytab_kernel.c.

# ---- SSS wire constants (sss.h) ----
const SSS_HDR_LEN = 16
const SSS_DATA_HDR_LEN = 40
const SSS_BASE_TIME = 1222183880
const SSS_ENC_BF32 = UInt8('0')   # Blowfish-CFB64 marker (ASCII '0')
const SSS_OPT_USEDATA = 0x00      # self-contained credential
const SSS_TYPE_NAME = 0x01

"One usable keytab key."
struct SSSKey
    id::Int64
    key::Vector{UInt8}
end

# ---- IEEE CRC-32 (zlib polynomial; SSS uses this, NOT CRC32c) ----
const _CRC32_TABLE = let t = Vector{UInt32}(undef, 256)
    for n in 0:255
        c = UInt32(n)
        for _ in 1:8
            c = (c & 0x1) != 0 ? (0xedb88320 ⊻ (c >> 1)) : (c >> 1)
        end
        t[n + 1] = c
    end
    t
end

function crc32_ieee(data::AbstractVector{UInt8})
    c = 0xffffffff
    for b in data
        c = _CRC32_TABLE[((c ⊻ b) & 0xff) + 1] ⊻ (c >> 8)
    end
    return c ⊻ 0xffffffff
end

"""
    default_keytab_path() -> String

The keytab location libxrdc uses: `\$XrdSecSSSKT`, `\$XrdSecsssKT`, then
`~/.xrd/sss.keytab`.
"""
function default_keytab_path()
    for var in ("XrdSecSSSKT", "XrdSecsssKT")
        p = get(ENV, var, "")
        isempty(p) || return p
    end
    home = get(ENV, "HOME", "/tmp")
    return joinpath(home, ".xrd", "sss.keytab")
end

"""
    read_keytab(path) -> Vector{SSSKey}

Parse an SSS keytab. Each non-comment line starts with a version tag
(`0`/`1`) followed by `x:value` fields; only `k:` (hex key) and `N:`
(numeric id) matter for minting, and `e:` (expiry, seconds since epoch)
drops expired keys. Ground truth: `sss_keytab_kernel.c`.
"""
function read_keytab(path::AbstractString)
    keys = SSSKey[]
    now = time()
    for raw in eachline(path)
        line = strip(raw)
        (isempty(line) || startswith(line, "#")) && continue
        fields = split(line)
        (fields[1] == "0" || fields[1] == "1") || continue
        id = Int64(-1)
        keybytes = UInt8[]
        exp = Int64(0)
        for fld in fields[2:end]
            startswith(fld, "#") && break
            (length(fld) >= 2 && fld[2] == ':') || continue
            tag, val = fld[1], fld[3:end]
            if tag == 'k'
                keybytes = hex2bytes(val)
            elseif tag == 'N'
                id = parse(Int64, val)
            elseif tag == 'e'
                exp = parse(Int64, val)
            end
        end
        (exp != 0 && exp <= now) && continue
        isempty(keybytes) || push!(keys, SSSKey(id, keybytes))
    end
    return keys
end

"""
    bf32_encrypt(key_bytes, plain) -> Vector{UInt8}

XrdCryptoLite's `bf32` transform, the cipher SSS credentials and secver-0
signatures share: append the IEEE-CRC32 of `plain` big-endian, then
Blowfish-CFB64 the whole thing with a zero IV. The output is
`length(plain) + 4` bytes and — the zero IV — deterministic, which is what
lets a verifier check a signature by re-encrypting rather than decrypting.
"""
function bf32_encrypt(key_bytes::AbstractVector{UInt8}, plain::AbstractVector{UInt8})
    crc = crc32_ieee(plain)
    buf = vcat(
        Vector{UInt8}(plain),
        UInt8[(crc >> 24) % UInt8, (crc >> 16) % UInt8, (crc >> 8) % UInt8, crc % UInt8],
    )
    ctx = Blowfish.Context(key_bytes)
    return Blowfish.cfb64_encrypt(ctx, zeros(UInt8, 8), buf)
end

"""
    build_sss_credential(key::SSSKey, username; nonce=rand, gen_time=now) -> Vector{UInt8}

Mint an SSS `kXR_auth` credential blob from `key`, identical to the shared
`xrootd_sss_build_credential` encoder. `nonce` (32 bytes) and `gen_time`
(seconds since `SSS_BASE_TIME`) are injectable for testing.
"""
function build_sss_credential(
    key::SSSKey,
    username::AbstractString;
    nonce::AbstractVector{UInt8}=rand(UInt8, 32),
    gen_time::Integer=floor(Int, time()) - SSS_BASE_TIME,
)
    length(nonce) == 32 || throw(ArgumentError("SSS nonce must be 32 bytes"))
    user = isempty(username) ? "xrd" : username

    # 40-byte data header: 32 nonce + gen_time(BE) + zeros + USEDATA at [40].
    clear = zeros(UInt8, SSS_DATA_HDR_LEN)
    copyto!(clear, 1, nonce, 1, 32)
    clear[33] = (gen_time >> 24) % UInt8
    clear[34] = (gen_time >> 16) % UInt8
    clear[35] = (gen_time >> 8) % UInt8
    clear[36] = gen_time % UInt8
    clear[40] = SSS_OPT_USEDATA

    # NAME TLV: [type][0][len][username NUL-terminated]; len includes the NUL.
    ub = codeunits(user)
    ulen = min(length(ub) + 1, 64)
    tlv = UInt8[SSS_TYPE_NAME, 0x00, UInt8(ulen)]
    append!(tlv, ub[1:(ulen - 1)])
    push!(tlv, 0x00)

    cipher = bf32_encrypt(key.key, vcat(clear, tlv))

    header = zeros(UInt8, SSS_HDR_LEN)
    header[1] = UInt8('s')
    header[2] = UInt8('s')
    header[3] = UInt8('s')
    header[4] = 0x00
    header[5] = 0x01              # version
    header[6] = 0x00             # spare
    header[7] = 0x00             # kn_size: no named key
    header[8] = SSS_ENC_BF32
    kid = reinterpret(UInt64, key.id)
    for i in 0:7
        header[9 + i] = (kid >> (8 * (7 - i))) % UInt8
    end
    return vcat(header, cipher)
end

"""
    sss_material(; keytab=nothing, username=local_user())
        -> Union{NamedTuple,Nothing}

The credential AND the key it was minted from, as `(; cred, key::SSSKey)` —
`nothing` when no readable key exists. The key outlives the login exchange:
it is the session cipher secver-0 request signing encrypts with, so a caller
who only wanted the blob takes `.cred` and a caller arming signing keeps
`.key` too.
"""
function sss_material(;
    keytab::Union{AbstractString,Nothing}=nothing, username::AbstractString=local_user()
)
    path = keytab === nothing ? default_keytab_path() : keytab
    isfile(path) || return nothing
    keys = try
        read_keytab(path)
    catch
        return nothing
    end
    isempty(keys) && return nothing
    return (; cred=build_sss_credential(keys[1], username), key=keys[1])
end

"""
    sss_credential(; keytab=nothing, username=local_user()) -> Union{Vector{UInt8},Nothing}

Build an SSS credential from the first usable key in `keytab` (default
[`default_keytab_path`](@ref)); `nothing` when no readable key exists.
"""
function sss_credential(;
    keytab::Union{AbstractString,Nothing}=nothing, username::AbstractString=local_user()
)
    m = sss_material(; keytab, username)
    return m === nothing ? nothing : m.cred
end

function local_user()
    u = get(ENV, "USER", "")
    return isempty(u) ? "xrd" : u
end
