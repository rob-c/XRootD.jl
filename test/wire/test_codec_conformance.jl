# Codec conformance: the wire layer on its own, no sockets involved.
#
# Every case re-derives the expected bytes from the protocol rules
# (big-endian primitives, CRC32c, 4 KiB page alignment) instead of comparing
# one Wire function against another, and sweeps the boundaries where framing
# bugs live: page edges, empty payloads, and the segment caps.

using CRC32c: crc32c
using XRootD: Wire
using XRootD.Wire:
    ReadRequest,
    WriteRequest,
    ReadVRequest,
    WriteVRequest,
    PgReadRequest,
    PgWriteRequest,
    encode,
    encode_pages,
    decode_pages,
    parse_readv,
    parse_pgwrite_cse,
    page_span

const CODEC_FH = (0x0a, 0x0b, 0x0c, 0x0d)

"Offsets and lengths that bracket every 4 KiB page boundary of interest."
const SWEEP_OFFSETS = [0, 1, 17, 4095, 4096, 4097, 8192, 12_287, 65_536]
const SWEEP_LENGTHS = [1, 2, 7, 4095, 4096, 4097, 8192, 9000]

@testset "Wire codec conformance" begin
    @testset "every request frame is 24 bytes plus its declared payload" begin
        data = collect(0x01:0x40)
        requests = [
            ReadRequest(CODEC_FH, Int64(0), Int32(64)),
            WriteRequest(CODEC_FH, Int64(4096), data),
            ReadVRequest([(; fhandle=CODEC_FH, offset=Int64(9), rlen=Int32(5))]),
            PgReadRequest(CODEC_FH, Int64(8192), Int32(100)),
            PgWriteRequest(CODEC_FH, Int64(0), data),
        ]
        for req in requests
            frame = encode(req, UInt16(0x1234))
            dlen = Int(Wire.get_u32(frame, 21))
            @test Wire.get_u16(frame, 1) == 0x1234           # streamid echoes back
            @test Wire.get_u16(frame, 3) == Wire.requestid(req)
            @test length(frame) == 24 + dlen                 # no hidden trailer
            @test dlen == length(Wire.payload(req))
        end
    end

    @testset "kXR_writev is the one request with bytes outside dlen" begin
        segs = [
            (; fhandle=CODEC_FH, offset=Int64(0), data=collect(0x01:0x08)),
            (; fhandle=CODEC_FH, offset=Int64(64), data=collect(0x09:0x10)),
        ]
        req = WriteVRequest(segs; do_sync=false)
        frame = encode(req, UInt16(1))
        dlen = Int(Wire.get_u32(frame, 21))
        @test dlen == 16 * length(segs)                      # descriptors only
        @test dlen % 16 == 0                                 # what stock servers enforce
        @test length(frame) == 24 + dlen + 16                # data trails the frame
        @test frame[(24 + dlen + 1):end] == vcat(segs[1].data, segs[2].data)
        for (i, seg) in enumerate(segs)                      # descriptors decode by hand
            base = 24 + 16 * (i - 1)
            @test tuple(frame[(base + 1):(base + 4)]...) == CODEC_FH
            @test Int(Wire.get_u32(frame, base + 5)) == length(seg.data)
            @test Int(Wire.get_u64(frame, base + 9)) == seg.offset
        end
    end

    @testset "page units align to the FILE offset, not the buffer" begin
        for offset in SWEEP_OFFSETS, len in SWEEP_LENGTHS
            data = UInt8[(3 * i + offset) % 256 for i in 1:len]
            pg = encode_pages(data, Int64(offset))
            # walk the units the way a server does: CRC, then up to the boundary
            pos, off, seen = 0, offset, UInt8[]
            nunits = 0
            while pos < length(pg)
                n = min(Wire.kXR_pgPageSZ - off % Wire.kXR_pgPageSZ, length(pg) - pos - 4)
                page = pg[(pos + 5):(pos + 4 + n)]
                @test Wire.get_u32(pg, pos + 1) == crc32c(page)
                append!(seen, page)
                pos += 4 + n
                off += n
                nunits += 1
            end
            @test seen == data                               # nothing lost or duplicated
            @test length(pg) == len + 4 * nunits             # exactly one CRC per unit
            @test decode_pages(pg, Int64(offset)) == data
        end
    end

    @testset "page_span never crosses a boundary and always advances" begin
        for offset in SWEEP_OFFSETS, remaining in [1, 4095, 4096, 100_000]
            n = page_span(Int64(offset), remaining)
            @test 1 <= n <= min(Wire.kXR_pgPageSZ, remaining)
            @test (offset + n) % Wire.kXR_pgPageSZ == 0 || n == remaining
        end
    end

    @testset "a corrupted page is rejected wherever the corruption lands" begin
        data = UInt8[(7 * i) % 256 for i in 1:9000]
        for offset in [0, 100, 4096]
            for spot in [1, 5, 4100, 8300]                   # a CRC byte and page bytes
                pg = encode_pages(data, Int64(offset))
                pg[spot] ⊻= 0x01
                @test_throws ArgumentError decode_pages(pg, Int64(offset))
            end
        end
    end

    @testset "readv response walk survives empty and clipped segments" begin
        function segment(off, data)
            return vcat(
                collect(CODEC_FH),
                Wire.set_u32!(zeros(UInt8, 4), 1, UInt32(length(data))),
                Wire.set_u64!(zeros(UInt8, 8), 1, UInt64(off)),
                data,
            )
        end
        body = vcat(
            segment(0, UInt8[0x01, 0x02]),
            segment(4096, UInt8[]),                          # server had nothing there
            segment(8192, collect(0x01:0x40)),
        )
        segs = parse_readv(body)
        @test length(segs) == 3
        @test segs[1].data == UInt8[0x01, 0x02]
        @test isempty(segs[2].data) && segs[2].offset == 4096
        @test segs[3].data == collect(0x01:0x40)
        # a header promising more than the body holds must not be trusted
        @test_throws ArgumentError parse_readv(body[1:(end - 1)])
    end

    @testset "reply caps cover the largest legal reply, per shape" begin
        for nseg in [1, 2, 64, Wire.VEC_MAXSEGS]
            segs = [
                (; fhandle=CODEC_FH, offset=Int64(4096 * i), rlen=Int32(64)) for i in 1:nseg
            ]
            req = ReadVRequest(segs)
            wire_size = nseg * (16 + 64)                     # echo header + data each
            @test Wire.readv_reply_cap(req) >= wire_size
        end
        for (offset, rlen) in [(0, 1), (0, 4096), (100, 9000), (4095, 65_536)]
            req = PgReadRequest(CODEC_FH, Int64(offset), Int32(rlen))
            npages, pos = 0, 0
            while pos < rlen                                 # count units independently
                pos += page_span(Int64(offset + pos), rlen - pos)
                npages += 1
            end
            # worst case: one status frame per page unit
            @test Wire.pgread_reply_cap(req) >= rlen + npages * (4 + Wire.STATUS_BODY_LEN)
        end
        for len in [1, 4096, 4097, 65_536]
            req = PgWriteRequest(CODEC_FH, Int64(0), zeros(UInt8, len))
            npages = cld(len, Wire.kXR_pgPageSZ)
            # worst case: every page reported corrupt
            @test Wire.pgwrite_reply_cap(req) >=
                Wire.STATUS_BODY_LEN + Wire.PGW_CSE_HDRLEN + 8 * npages
        end
    end

    @testset "pgwrite CSE trailers round trip for any page count" begin
        for k in 0:5
            offsets = Int64[4096 * i for i in 0:(k - 1)]
            trailer = vcat(zeros(UInt8, Wire.PGW_CSE_HDRLEN),
                reduce(vcat, (Wire.set_u64!(zeros(UInt8, 8), 1, UInt64(o)) for o in offsets);
                    init=UInt8[]))
            @test parse_pgwrite_cse(trailer) == offsets
        end
        # anything that is not header + whole 8-byte offsets is malformed
        for n in [0, 1, 7, 9, 15, 17]
            @test_throws ArgumentError parse_pgwrite_cse(zeros(UInt8, n))
        end
    end
end
