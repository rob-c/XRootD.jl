using XRootD.Wire
using XRootD.Wire:
    HANDSHAKE,
    Request,
    ResponseHeader,
    decode_header,
    encode,
    REQUEST_HDRLEN,
    RESPONSE_HDRLEN,
    requestid,
    body!,
    payload

# A minimal fake request to exercise the generic encoder without depending
# on the real request structs (Task 5).
struct FakeRequest <: Wire.Request end
Wire.requestid(::FakeRequest) = UInt16(3011)           # kXR_ping

struct FakePayloadRequest <: Wire.Request end
Wire.requestid(::FakePayloadRequest) = UInt16(3017)    # kXR_stat
Wire.payload(::FakePayloadRequest) = codeunits("/tmp")

@testset "Wire frames" begin
    @testset "client hello is byte-exact" begin
        # ClientInitHandShake (wire_core_requests.h): three zero words,
        # fourth = 4, fifth = ROOTD_PQ (2012 = 0x07dc).
        @test HANDSHAKE ==
            UInt8[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0, 0, 0x07, 0xdc]
        @test length(HANDSHAKE) == 20
    end

    @testset "request framing" begin
        frame = encode(FakeRequest(), UInt16(0x0003))
        @test length(frame) == REQUEST_HDRLEN
        @test frame == UInt8[
            0x00,
            0x03,
            0x0b,
            0xc3,                           # streamid, kXR_ping
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,  # body
            0x00,
            0x00,
            0x00,
            0x00,                           # dlen = 0
        ]

        frame = encode(FakePayloadRequest(), UInt16(0x0005))
        @test length(frame) == REQUEST_HDRLEN + 4
        @test frame[21:24] == UInt8[0x00, 0x00, 0x00, 0x04]   # dlen = 4
        @test frame[25:28] == codeunits("/tmp")               # no trailing NUL
    end

    @testset "response header decode" begin
        hdr = decode_header(UInt8[0x00, 0x07, 0x0f, 0xa4, 0x00, 0x00, 0x00, 0x10])
        @test hdr === ResponseHeader(0x0007, UInt16(4004), UInt32(16))  # kXR_redirect
        @test_throws ArgumentError decode_header(UInt8[0x00])
    end
end
