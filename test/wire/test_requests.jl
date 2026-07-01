using XRootD.Wire
using XRootD.Wire: ProtocolRequest, LoginRequest, AuthRequest, PingRequest, encode

@testset "Wire bootstrap requests" begin
    @testset "kXR_protocol golden frame" begin
        # streamid=1, pv=0x520, flags=secreqs|ableTLS, expect=ExpLogin
        frame = encode(ProtocolRequest(), UInt16(1))
        #! format: off
        @test frame == UInt8[
            0x00, 0x01, 0x0b, 0xbe,          # streamid, kXR_protocol (3006)
            0x00, 0x00, 0x05, 0x20,          # clientpv = 0x00000520
            0x03, 0x03,                      # flags, expect
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    # reserved[10]
            0x00, 0x00, 0x00, 0x00,          # dlen = 0
        ]
        #! format: on
    end

    @testset "kXR_login golden frame" begin
        frame = encode(LoginRequest("julia"; pid=1234), UInt16(2))
        #! format: off
        @test frame == UInt8[
            0x00, 0x02, 0x0b, 0xbf,                       # streamid, kXR_login (3007)
            0x00, 0x00, 0x04, 0xd2,                       # pid = 1234
            0x6a, 0x75, 0x6c, 0x69, 0x61, 0, 0, 0,        # "julia" NUL-padded to 8
            0x00, 0x00, 0x85, 0x00,                       # ability2, ability, capver, rsvd
            0x00, 0x00, 0x00, 0x00,                       # dlen = 0 (anonymous)
        ]
        #! format: on
        # username longer than the 8-byte wire field is truncated, not an error
        long = encode(LoginRequest("verylonguser"; pid=0), UInt16(2))
        @test long[9:16] == codeunits("verylong")
    end

    @testset "kXR_auth golden frame" begin
        frame = encode(AuthRequest("ztn", Vector{UInt8}(codeunits("TOKEN"))), UInt16(4))
        @test frame == vcat(
            UInt8[0x00, 0x04, 0x0b, 0xb8],               # streamid, kXR_auth (3000)
            zeros(UInt8, 12),                            # reserved[12]
            UInt8[0x7a, 0x74, 0x6e, 0x00],               # credtype "ztn\0"
            UInt8[0x00, 0x00, 0x00, 0x05],               # dlen = 5
            Vector{UInt8}(codeunits("TOKEN")),
        )
        @test_throws ArgumentError AuthRequest("toolong", UInt8[])  # credtype > 4 bytes
    end

    @testset "kXR_ping golden frame" begin
        frame = encode(PingRequest(), UInt16(3))
        @test frame == vcat(UInt8[0x00, 0x03, 0x0b, 0xc3], zeros(UInt8, 20))
    end
end

using XRootD.Wire: StatRequest, DirlistRequest, kXR_dstat, kXR_vfs

@testset "Wire fs requests" begin
    @testset "kXR_stat golden frame" begin
        frame = encode(StatRequest("/tmp"), UInt16(5))
        @test frame == vcat(
            UInt8[0x00, 0x05, 0x0b, 0xc9],       # streamid, kXR_stat (3017)
            zeros(UInt8, 16),                    # options=0, reserved, fhandle=0
            UInt8[0x00, 0x00, 0x00, 0x04],       # dlen = 4
            Vector{UInt8}(codeunits("/tmp")),    # path, no trailing NUL
        )
        vfs = encode(StatRequest("/data"; options=kXR_vfs), UInt16(5))
        @test vfs[5] == 0x01
        byhandle = encode(StatRequest(""; fhandle=(0x01, 0x02, 0x03, 0x04)), UInt16(5))
        @test byhandle[17:20] == UInt8[0x01, 0x02, 0x03, 0x04]
        @test byhandle[21:24] == zeros(UInt8, 4)   # dlen = 0 when path empty
    end

    @testset "kXR_dirlist golden frame" begin
        frame = encode(DirlistRequest("/data"), UInt16(6))
        @test frame == vcat(
            UInt8[0x00, 0x06, 0x0b, 0xbc],       # streamid, kXR_dirlist (3004)
            zeros(UInt8, 15),                    # reserved[15]
            UInt8[kXR_dstat],                    # options at body byte 16
            UInt8[0x00, 0x00, 0x00, 0x05],       # dlen = 5
            Vector{UInt8}(codeunits("/data")),
        )
        plain = encode(DirlistRequest("/data"; options=0x00), UInt16(6))
        @test plain[20] == 0x00
    end
end
