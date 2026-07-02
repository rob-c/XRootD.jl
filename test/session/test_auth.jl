using XRootD: Wire, Session
using XRootD.Session: Blowfish
using SHA: hmac_sha256

# CFB64 decryption helper for the round-trip test (feedback taken from the
# ciphertext, mirroring encrypt).
function _bf_cfb64_decrypt(ctx, cipher)
    out = Vector{UInt8}(undef, length(cipher))
    fb = zeros(UInt8, 8)
    for base in 1:8:length(cipher)
        L = Session.Blowfish._load_be32(fb, 1)
        R = Session.Blowfish._load_be32(fb, 5)
        L, R = Blowfish.encrypt_block(ctx, L, R)
        Session.Blowfish._store_be32!(fb, 1, L)
        Session.Blowfish._store_be32!(fb, 5, R)
        n = min(8, length(cipher) - base + 1)
        for k in 0:(n - 1)
            c = cipher[base + k]
            out[base + k] = c ⊻ fb[k + 1]
            fb[k + 1] = c
        end
    end
    return out
end

@testset "auth mechanisms" begin
    @testset "security trailer parsing" begin
        @test Session.parse_sec_protocols("&P=ztn&P=sss,foo&P=unix") ==
            ["ztn", "sss", "unix"]
        @test isempty(Session.parse_sec_protocols(""))
    end

    @testset "token discovery order" begin
        withenv("BEARER_TOKEN" => "envtoken", "BEARER_TOKEN_FILE" => nothing) do
            @test Session.discover_token() == "envtoken"
            @test Session.discover_token(; explicit=" xyz ") == "xyz"
        end
        mktemp() do path, io
            write(io, "  filetoken\n")
            close(io)
            withenv("BEARER_TOKEN" => nothing, "BEARER_TOKEN_FILE" => path) do
                @test Session.discover_token() == "filetoken"
            end
        end
        withenv(
            "BEARER_TOKEN" => nothing,
            "BEARER_TOKEN_FILE" => nothing,
            "XDG_RUNTIME_DIR" => mktempdir(),
        ) do
            @test Session.discover_token() === nothing
        end
    end
end

@testset "Blowfish" begin
    # Published Blowfish ECB test vectors (Eric Young's set): key, plaintext,
    # ciphertext, all 8 bytes.
    vectors = [
        (0x0000000000000000, 0x0000000000000000, 0x4ef99745_6198dd78),
        (0xffffffffffffffff, 0xffffffffffffffff, 0x51866fd5_b85ecb8a),
        (0x3000000000000000, 0x1000000000000001, 0x7d856f9a_613063f2),
    ]
    for (k, pt, ct) in vectors
        key = reinterpret(UInt8, [hton(UInt64(k))])
        ctx = Blowfish.Context(key)
        L = UInt32((pt >> 32) & 0xffffffff)
        R = UInt32(pt & 0xffffffff)
        eL, eR = Blowfish.encrypt_block(ctx, L, R)
        got = (UInt64(eL) << 32) | UInt64(eR)
        @test got == ct
    end

    @testset "CFB64 length preserved" begin
        ctx = Blowfish.Context(UInt8[1, 2, 3, 4, 5, 6, 7, 8])
        data = rand(UInt8, 45)   # not a multiple of 8
        enc = Blowfish.cfb64_encrypt(ctx, zeros(UInt8, 8), data)
        @test length(enc) == length(data)
        @test enc != data
    end
end

@testset "SSS credential" begin
    @testset "IEEE CRC32" begin
        # zlib crc32("123456789") == 0xCBF43926
        @test Session.crc32_ieee(Vector{UInt8}(codeunits("123456789"))) == 0xcbf43926
    end

    @testset "keytab parse" begin
        mktemp() do path, io
            write(
                io,
                """
                # a comment
                0 u:alice g:staff N:42 k:00112233445566778899aabbccddeeff
                1 N:7 k:deadbeef e:1
                """,
            )
            close(io)
            keys = Session.read_keytab(path)
            @test length(keys) == 1                      # expired (e:1) dropped
            @test keys[1].id == 42
            @test keys[1].key == UInt8[
                0x00,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0x66,
                0x77,
                0x88,
                0x99,
                0xaa,
                0xbb,
                0xcc,
                0xdd,
                0xee,
                0xff,
            ]
        end
    end

    @testset "credential blob shape and decrypt round trip" begin
        key = Session.SSSKey(Int64(9), collect(0x01:0x10))
        nonce = collect(0x20:0x3f)
        blob = Session.build_sss_credential(key, "bob"; nonce=nonce, gen_time=12345)
        @test blob[1:4] == UInt8['s', 's', 's', 0x00]
        @test blob[5] == 0x01
        @test blob[8] == Session.SSS_ENC_BF32
        @test Wire.get_u64(blob, 9) == 9             # key id big-endian
        # decrypt the body and check the nonce + CRC survive
        ctx = Blowfish.Context(key.key)
        cipher = blob[(Session.SSS_HDR_LEN + 1):end]
        # CFB64 decrypt: keystream from the same feedback, XOR back
        clear = _bf_cfb64_decrypt(ctx, cipher)
        @test clear[1:32] == nonce
        body = clear[1:(end - 4)]
        crc = Session.crc32_ieee(body)
        @test clear[(end - 3):end] == UInt8[
            (crc >> 24) % UInt8, (crc >> 16) % UInt8, (crc >> 8) % UInt8, crc % UInt8
        ]
    end
end

@testset "sigver" begin
    key = collect(0x01:0x20)
    hdr = collect(0x00:0x17)          # 24-byte request header
    payload = UInt8[0xaa, 0xbb]
    mac = Session.sigver_hmac(key, UInt64(1), hdr, payload)
    # reference HMAC over seqno_be || hdr || payload
    msg = vcat(UInt8[0, 0, 0, 0, 0, 0, 0, 1], hdr, payload)
    @test mac == hmac_sha256(key, msg)
    @test length(mac) == 32

    @test Session.sigver_required(Wire.kXR_write)
    @test Session.sigver_required(Wire.kXR_open)
    @test !Session.sigver_required(Wire.kXR_stat)
    @test !Session.sigver_required(Wire.kXR_read)

    # the codec: dlen = 32, payload = the HMAC
    frame = Wire.encode(Wire.SigverRequest(Wire.kXR_write, UInt64(5), mac), UInt16(7))
    @test frame[3:4] == UInt8[0x0b, 0xd5]        # kXR_sigver (3029 = 0x0bd5)
    @test Wire.get_u16(frame, 5) == Wire.kXR_write
    @test Wire.get_u64(frame, 9) == 5
    @test frame[17] == Wire.kXR_SHA256_sig
    @test Wire.get_u32(frame, 21) == 32
    @test frame[25:end] == mac
end
