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

    @testset "the π-derived tables are Schneier's constants" begin
        # The P-array and S-boxes are computed from big(π) rather than
        # embedded as 1042 magic numbers; the derivation has to reproduce the
        # published initialization values exactly.
        words = Blowfish._pi_words()
        @test length(words) == 18 + 4 * 256
        @test words[1:4] == UInt32[0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344]
        @test Blowfish.P0 == words[1:18]
        @test Blowfish.P0[18] == 0x8979fb1b
        @test Blowfish.S0[1][1] == 0xd1310ba6
        @test Blowfish.S0[4][256] == 0x3ac372e6
        @test all(length(s) == 256 for s in Blowfish.S0)
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

    @testset "keytab entries a client cannot use" begin
        mktempdir() do dir
            # A version tag that is neither 0 nor 1 is a format this client does
            # not know; a line without a key has nothing to sign with.
            path = joinpath(dir, "odd.keytab")
            write(
                path,
                """
                2 N:1 k:00112233445566778899aabbccddeeff
                0 N:2 u:nokey
                0 N:3 k:aabb # trailing comment ignored
                0 N:4 k:ccdd e:99999999999
                """,
            )
            keys = Session.read_keytab(path)
            @test [k.id for k in keys] == [3, 4]
            @test keys[1].key == UInt8[0xaa, 0xbb]

            # An entry with no id at all still has a key, and the id it gets is
            # the "unset" one the server treats as a wildcard.
            path = joinpath(dir, "noid.keytab")
            write(path, "1 k:0011\n")
            @test only(Session.read_keytab(path)).id == -1
        end
    end

    @testset "where the keytab is looked for" begin
        # libxrdc reads XrdSecSSSKT first, then the historical XrdSecsssKT
        # spelling, then falls back to the user's own copy.
        withenv(
            "XrdSecSSSKT" => "/one/kt", "XrdSecsssKT" => "/two/kt", "HOME" => "/home/u"
        ) do
            @test Session.default_keytab_path() == "/one/kt"
        end
        withenv("XrdSecSSSKT" => nothing, "XrdSecsssKT" => "/two/kt") do
            @test Session.default_keytab_path() == "/two/kt"
        end
        withenv("XrdSecSSSKT" => nothing, "XrdSecsssKT" => nothing, "HOME" => "/home/u") do
            @test Session.default_keytab_path() == "/home/u/.xrd/sss.keytab"
        end
    end

    @testset "a credential is only minted from a usable keytab" begin
        # No keytab, an unreadable one, and one with no usable entry all mean
        # the same thing to the caller: sss is not available, try something else.
        mktempdir() do dir
            @test Session.sss_credential(; keytab=joinpath(dir, "absent")) === nothing

            empty_kt = joinpath(dir, "empty.keytab")
            write(empty_kt, "# nothing but a comment\n")
            @test Session.sss_credential(; keytab=empty_kt) === nothing

            unreadable = joinpath(dir, "unreadable.keytab")
            write(unreadable, "0 N:1 k:00112233\n")
            chmod(unreadable, 0o000)
            # Root defeats the permission bits, so assert this only where the
            # file really cannot be opened.
            denied = try
                read(unreadable)
                false
            catch
                true
            end
            denied && @test Session.sss_credential(; keytab=unreadable) === nothing
            chmod(unreadable, 0o600)

            good = joinpath(dir, "good.keytab")
            write(good, "0 N:77 k:00112233445566778899aabbccddeeff\n")
            cred = Session.sss_credential(; keytab=good, username="alice")
            @test cred !== nothing
            @test cred[1:4] == UInt8['s', 's', 's', 0x00]
            @test Wire.get_u64(cred, 9) == 77
        end
    end

    @testset "the identity an sss credential carries" begin
        # An empty username is not a credential for nobody; sss_credential.c
        # substitutes "xrd", and so does the environment lookup.
        withenv("USER" => nothing) do
            @test Session.local_user() == "xrd"
        end
        withenv("USER" => "alice") do
            @test Session.local_user() == "alice"
        end
        key = Session.SSSKey(Int64(1), collect(0x01:0x10))
        @test length(Session.build_sss_credential(key, "")) ==
            length(Session.build_sss_credential(key, "xrd"))
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
