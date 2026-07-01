using XRootD.Wire:
    get_u16,
    get_u32,
    get_u64,
    set_u16!,
    set_u32!,
    set_u64!,
    set_bytes!,
    set_padded_string!,
    get_bounded_string

@testset "Wire primitives" begin
    @testset "big-endian round trips" begin
        buf = zeros(UInt8, 12)
        set_u16!(buf, 1, 0x0bbe)
        @test buf[1:2] == UInt8[0x0b, 0xbe]
        @test get_u16(buf, 1) === 0x0bbe

        set_u32!(buf, 3, 0x00000520)
        @test buf[3:6] == UInt8[0x00, 0x00, 0x05, 0x20]
        @test get_u32(buf, 3) === 0x00000520

        set_u64!(buf, 5, 0x0102030405060708)
        @test buf[5:12] == UInt8[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        @test get_u64(buf, 5) === 0x0102030405060708
    end

    @testset "bounds are checked" begin
        buf = zeros(UInt8, 4)
        @test_throws BoundsError get_u32(buf, 2)
        @test_throws BoundsError set_u16!(buf, 4, 0x0001)
    end

    @testset "byte and string fields" begin
        buf = zeros(UInt8, 8)
        set_bytes!(buf, 3, UInt8[0xaa, 0xbb])
        @test buf == UInt8[0, 0, 0xaa, 0xbb, 0, 0, 0, 0]

        fill!(buf, 0xff)
        set_padded_string!(buf, 1, 8, "julia")          # NUL-padded to width
        @test buf == UInt8[0x6a, 0x75, 0x6c, 0x69, 0x61, 0x00, 0x00, 0x00]
        set_padded_string!(buf, 1, 4, "toolongname")    # truncated at width
        @test buf[1:4] == UInt8[0x74, 0x6f, 0x6f, 0x6c]

        # bounded string: stops at NUL, never reads past maxlen
        raw = UInt8[0x68, 0x69, 0x00, 0x78]
        @test get_bounded_string(raw, 1, 4) == "hi"
        @test get_bounded_string(raw, 1, 2) == "hi"
        @test get_bounded_string(UInt8[0x61, 0x62], 1, 2) == "ab"  # no NUL on wire
    end
end
