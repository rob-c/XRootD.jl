# Pure-Julia Blowfish in CFB64 mode — the cipher XRootD's SSS credential uses.
# The P-array and S-boxes are the fractional hex digits of π (Schneier's
# original spec); we derive them from `big(π)` at load time rather than
# embedding 1042 magic constants.

module Blowfish

# 18 P-array words + 4 × 256 S-box words = 1042 × 32-bit words of π's
# fractional hex expansion. 1042 words need 8336 hex digits ≈ 34_600 bits;
# take a comfortable margin.
const _NWORDS = 18 + 4 * 256

function _pi_words()
    setprecision(BigFloat, 8 * _NWORDS * 4 + 4096) do
        frac = big(π) - 3
        words = Vector{UInt32}(undef, _NWORDS)
        for i in 1:_NWORDS
            frac *= big(2)^32
            w = floor(BigInt, frac)
            words[i] = UInt32(w)
            frac -= w
        end
        return words
    end
end

const _PI_WORDS = _pi_words()

"Immutable initial P-array and S-boxes (copied per key schedule)."
const P0 = _PI_WORDS[1:18]
const S0 = (_PI_WORDS[19:274], _PI_WORDS[275:530], _PI_WORDS[531:786], _PI_WORDS[787:1042])

"A Blowfish key schedule (18-word P-array + four 256-word S-boxes)."
struct Context
    P::Vector{UInt32}
    S::NTuple{4,Vector{UInt32}}
end

function f(ctx::Context, x::UInt32)
    return (
        (
            (ctx.S[1][((x >> 24) & 0xff) + 1] + ctx.S[2][((x >> 16) & 0xff) + 1]) ⊻
            ctx.S[3][((x >> 8) & 0xff) + 1]
        ) + ctx.S[4][(x & 0xff) + 1]
    )
end

"Encrypt one 64-bit block given as `(left, right)`."
function encrypt_block(ctx::Context, L::UInt32, R::UInt32)
    for i in 1:16
        L ⊻= ctx.P[i]
        R ⊻= f(ctx, L)
        L, R = R, L
    end
    L, R = R, L
    R ⊻= ctx.P[17]
    L ⊻= ctx.P[18]
    return L, R
end

"""
    Context(key::AbstractVector{UInt8}) -> Context

Build a Blowfish key schedule from `key` (1–56 bytes), following Schneier's
subkey-generation algorithm.
"""
function Context(key::AbstractVector{UInt8})
    isempty(key) && throw(ArgumentError("Blowfish key must be non-empty"))
    length(key) > 56 && throw(ArgumentError("Blowfish key must be ≤ 56 bytes"))
    P = copy(P0)
    S = (copy(S0[1]), copy(S0[2]), copy(S0[3]), copy(S0[4]))
    ctx = Context(P, S)

    klen = length(key)
    j = 0
    for i in 1:18
        k = UInt32(0)
        for _ in 1:4
            k = (k << 8) | UInt32(key[j % klen + 1])
            j += 1
        end
        P[i] ⊻= k
    end

    L = UInt32(0)
    R = UInt32(0)
    for i in 1:2:18
        L, R = encrypt_block(ctx, L, R)
        P[i] = L
        P[i + 1] = R
    end
    for s in 1:4
        for i in 1:2:256
            L, R = encrypt_block(ctx, L, R)
            S[s][i] = L
            S[s][i + 1] = R
        end
    end
    return ctx
end

"""
    cfb64_encrypt(ctx, iv, data) -> Vector{UInt8}

Blowfish-CFB64 encryption with 8-byte `iv` (XRootD SSS uses an all-zero IV,
no padding — the stream length is preserved).
"""
function cfb64_encrypt(ctx::Context, iv::AbstractVector{UInt8}, data::AbstractVector{UInt8})
    length(iv) == 8 || throw(ArgumentError("Blowfish IV must be 8 bytes"))
    out = Vector{UInt8}(undef, length(data))
    fb = collect(iv)
    for base in 1:8:length(data)
        L = _load_be32(fb, 1)
        R = _load_be32(fb, 5)
        L, R = encrypt_block(ctx, L, R)
        _store_be32!(fb, 1, L)
        _store_be32!(fb, 5, R)
        n = min(8, length(data) - base + 1)
        for k in 0:(n - 1)
            c = data[base + k] ⊻ fb[k + 1]
            out[base + k] = c
            fb[k + 1] = c            # CFB feedback: ciphertext feeds the next block
        end
    end
    return out
end

function _load_be32(b, o)
    return (UInt32(b[o]) << 24) | (UInt32(b[o + 1]) << 16) | (UInt32(b[o + 2]) << 8) |
           UInt32(b[o + 3])
end

function _store_be32!(b, o, v)
    b[o] = (v >> 24) % UInt8
    b[o + 1] = (v >> 16) % UInt8
    b[o + 2] = (v >> 8) % UInt8
    b[o + 3] = v % UInt8
    return b
end

end # module Blowfish
