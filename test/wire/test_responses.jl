using XRootD.Wire:
    decode_error,
    wait_seconds,
    decode_redirect,
    decode_protocol,
    decode_login,
    parse_stat_line,
    parse_dirlist

@testset "Wire response bodies" begin
    @testset "kXR_error body" begin
        body = vcat(UInt8[0x00, 0x00, 0x0b, 0xc3], Vector{UInt8}(codeunits("No such file")))
        err = decode_error(body)
        @test err.errnum == Int32(3011)
        @test err.message == "No such file"
        # tolerate a trailing NUL some servers append
        @test decode_error(vcat(body, UInt8[0x00])).message == "No such file"
        @test_throws ArgumentError decode_error(UInt8[0x00, 0x00])
    end

    @testset "kXR_wait body" begin
        @test wait_seconds(UInt8[0x00, 0x00, 0x00, 0x05]) == 5
        @test wait_seconds(UInt8[]) == 5                       # fallback
        @test wait_seconds(UInt8[0x00, 0x00, 0x00, 0x00]) == 1 # clamp low
        @test wait_seconds(UInt8[0x00, 0x01, 0x00, 0x00]; cap=UInt32(600)) == 600
    end

    @testset "kXR_redirect body" begin
        body = vcat(UInt8[0x00, 0x00, 0x04, 0x46], Vector{UInt8}(codeunits("eos.cern.ch")))
        r = decode_redirect(body)
        @test r.port == Int32(1094)
        @test r.host == "eos.cern.ch"
        @test r.cgi == ""
        r = decode_redirect(
            vcat(
                UInt8[0x00, 0x00, 0x04, 0x46],
                Vector{UInt8}(codeunits("eos.cern.ch?xrd.spr=tls")),
            ),
        )
        @test r.host == "eos.cern.ch"
        @test r.cgi == "xrd.spr=tls"

        be32(x) = reverse(reinterpret(UInt8, [UInt32(x)]))
        redirect(text, port=1094) =
            decode_redirect(vcat(be32(port), Vector{UInt8}(codeunits(text))))
        # The host field is NUL-terminated, and a server that ends it with a
        # line break has still only named the host.
        @test redirect("eos.cern.ch\0trailing junk").host == "eos.cern.ch"
        @test redirect("eos.cern.ch\r\n").host == "eos.cern.ch"
        @test redirect("eos.cern.ch\n?a=1") ==
            (; port=Int32(1094), host="eos.cern.ch", cgi="")
        # EOS hands the open capability over as "?&cap.sym=…"; the separator is
        # not part of the token the data server has to be shown.
        @test redirect("ds1?&cap.sym=abc&cap.msg=def").cgi == "cap.sym=abc&cap.msg=def"
        @test redirect("ds1??a=1").cgi == "a=1"
        @test redirect("ds1?").cgi == ""
        @test redirect("ds1?").host == "ds1"
        # An IPv6 target arrives bracketed, and the brackets are the host's.
        @test redirect("[2001:db8::1]?a=1", 1095) ==
            (; port=Int32(1095), host="[2001:db8::1]", cgi="a=1")

        # The port is signed, and the sign carries meaning: a negative port is
        # how XRootD 5 says "continue at |port| over TLS". Decoding it as
        # unsigned would name port 4294966250 and lose the instruction.
        neg = redirect("ds1", reinterpret(UInt32, Int32(-1046)))
        @test neg.port == Int32(-1046)
        @test neg.host == "ds1"
        @test_throws ArgumentError decode_redirect(UInt8[0x00, 0x00, 0x04])
    end

    @testset "kXR_protocol + kXR_login bodies" begin
        p = decode_protocol(UInt8[0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x01])
        @test p.pval == 0x00000520
        @test p.flags == 0x00000001

        sessid = UInt8.(1:16)
        l = decode_login(sessid)
        @test l.sessid == sessid
        @test l.sec == ""
        l = decode_login(vcat(sessid, Vector{UInt8}(codeunits("&P=ztn"))))
        @test l.sec == "&P=ztn"
        @test_throws ArgumentError decode_login(UInt8[0x01])
    end

    @testset "stat line" begin
        s = parse_stat_line("1234567 16 65536 1700000000")
        @test s.id == "1234567"
        @test s.size == 16
        @test s.flags == UInt32(65536)
        @test s.mtime == 1700000000
        @test parse_stat_line("9 0 0 0\0").size == 0     # tolerate trailing NUL
        @test_throws ArgumentError parse_stat_line("only two")
    end

    @testset "dirlist bodies" begin
        plain = parse_dirlist(Vector{UInt8}(codeunits("a.root\nb.root\nsub\0")))
        @test plain.entries == ["a.root", "b.root", "sub"]
        @test plain.stats === nothing

        dstat_text = ".\n0 0 0 0\nf1\n10 100 0 1700000000\ndir1\n11 0 19 1700000001\0"
        ds = parse_dirlist(Vector{UInt8}(codeunits(dstat_text)))
        @test ds.entries == ["f1", "dir1"]
        @test ds.stats[1].id == "10"
        @test ds.stats[1].size == 100
        @test ds.stats[1].mtime == 1700000000
        @test ds.stats[2].flags == UInt32(19)

        empty = parse_dirlist(UInt8[])
        @test empty.entries == String[] && empty.stats === nothing
    end
end

using XRootD.Wire: decode_open, parse_locate

@testset "Wire fs/file response bodies" begin
    @testset "open body" begin
        body = UInt8[0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0]
        o = decode_open(body)
        @test o.fhandle == (0x01, 0x02, 0x03, 0x04)
        @test o.stat === nothing
        withstat = vcat(body, Vector{UInt8}(codeunits("7 13 51 1700000000\0")))
        o = decode_open(withstat)
        @test o.stat.size == 13
        @test decode_open(UInt8[1, 2, 3, 4]).fhandle == (0x01, 0x02, 0x03, 0x04)
        @test_throws ArgumentError decode_open(UInt8[1, 2])
    end

    @testset "locate tokens" begin
        locs = parse_locate(
            Vector{UInt8}(codeunits("Sr[::127.0.0.1]:1094 Mw[::10.0.0.1]:1094\0"))
        )
        @test length(locs) == 2
        @test locs[1].node == 'S' && locs[1].access == 'r'
        @test locs[1].address == "[::127.0.0.1]:1094"
        @test locs[2].node == 'M' && locs[2].access == 'w'
        @test isempty(parse_locate(UInt8[]))
    end

    @testset "extended stat line" begin
        s = parse_stat_line("123 13 51 1700000000 1700000001 1700000002 0644 rob users")
        @test s.has_ext
        @test s.mode == "0644" && s.owner == "rob" && s.group == "users"
        @test s.ctime == 1700000001 && s.atime == 1700000002
        b = parse_stat_line("123 13 51 1700000000")
        @test !b.has_ext && b.mode == "" && b.owner == ""
    end
end

using CRC32c: crc32c
using XRootD.Wire:
    parse_readv,
    decode_status_body,
    encode_pages,
    decode_pages,
    set_u16!,
    set_u32!,
    set_u64!

"Build a valid 24-byte kXR_status body (crc + sid/reqid/resptype/pgdlen/offset)."
function status_body(sid, resptype, pgdlen, offset)
    sb = zeros(UInt8, 24)
    set_u16!(sb, 5, UInt16(sid))
    sb[7] = 0x1e                             # requestid echo (pgread - 3000)
    sb[8] = UInt8(resptype)
    set_u32!(sb, 13, UInt32(pgdlen))
    set_u64!(sb, 17, UInt64(offset))
    set_u32!(sb, 1, crc32c(sb[5:24]))
    return sb
end

@testset "Wire vector and paged io responses" begin
    @testset "readv response walk" begin
        seg(off, data) = vcat(
            UInt8[1, 2, 3, 4],
            Wire.set_u32!(zeros(UInt8, 4), 1, UInt32(length(data))),
            Wire.set_u64!(zeros(UInt8, 8), 1, UInt64(off)),
            Vector{UInt8}(codeunits(data)),
        )
        segs = parse_readv(vcat(seg(0, "abc"), seg(4096, "de")))
        @test length(segs) == 2
        @test segs[1].data == codeunits("abc") && segs[1].offset == 0
        @test segs[2].data == codeunits("de") && segs[2].offset == 4096
        @test_throws ArgumentError parse_readv(UInt8[1, 2, 3])
    end

    @testset "status body decode + CRC" begin
        sb = status_body(7, 0x01, 4100, 8192)
        s = decode_status_body(sb)
        @test s.resptype == 0x01
        @test s.pgdlen == 4100
        @test s.offset == 8192
        sb[24] ⊻= 0xff                        # corrupt → CRC must fail
        @test_throws ArgumentError decode_status_body(sb)
        @test_throws ArgumentError decode_status_body(UInt8[0x00])
    end

    @testset "page encode/decode round trip" begin
        data = rand(UInt8, 10000)
        # aligned at 0: pages 4096+4096+1808, each prefixed by 4-byte CRC
        pg = encode_pages(data, Int64(0))
        @test length(pg) == 10000 + 3 * 4
        @test decode_pages(pg, Int64(0)) == data

        # unaligned start: short first page up to the 4 KiB boundary
        off = Int64(4000)
        pg = encode_pages(data, off)
        @test length(pg) == 10000 + 4 * 4     # 96 + 4096 + 4096 + 1712
        @test decode_pages(pg, off) == data

        # CRC corruption is detected
        pg[5] ⊻= 0xff
        @test_throws ArgumentError decode_pages(pg, off)
    end

    @testset "kXR_fattr Get response" begin
        be32(x) = reverse(reinterpret(UInt8, [UInt32(x)]))
        be16(x) = reverse(reinterpret(UInt8, [UInt16(x)]))
        nvec(names...) =
            vcat((vcat(be16(0), Vector{UInt8}(codeunits(n)), 0x00) for n in names)...)
        vvec(vals...) = vcat((vcat(be32(length(v)), v) for v in vals)...)

        body = vcat(
            UInt8[0x00, 0x02],                        # errcount, numattr
            nvec("user.a", "user.b"),
            vvec(UInt8[0x01, 0x02], UInt8[0x03]),
        )
        got = Wire.parse_fattr_get(body, 2)
        @test [g.rc for g in got] == UInt16[0, 0]
        @test [g.value for g in got] == [UInt8[0x01, 0x02], UInt8[0x03]]

        # A per-attribute error code travels with an empty value.
        err = vcat(UInt8[0x01, 0x01], vcat(be16(2), b"user.a", 0x00), vvec(UInt8[]))
        @test only(Wire.parse_fattr_get(err, 1)) == (; rc=UInt16(2), value=UInt8[])

        # A server that stops short mid-vvec leaves the remaining attributes
        # valueless rather than reading off the end of the body.
        @test [g.value for g in Wire.parse_fattr_get(body[1:(end - 5)], 2)] == [UInt8[0x01, 0x02], UInt8[]]
        # ... and a value whose length overruns the body is taken as far as it goes.
        long = vcat(UInt8[0x00, 0x01], nvec("user.a"), be32(64), UInt8[0xaa, 0xbb])
        @test only(Wire.parse_fattr_get(long, 1)).value == UInt8[0xaa, 0xbb]

        @test_throws ArgumentError Wire.parse_fattr_get(UInt8[0x00], 1)
    end

    @testset "pgwrite checksum-error trailer" begin
        # cseCRC[4] dlFirst[2] dlLast[2] then one big-endian offset per page
        hdr = vcat(zeros(UInt8, 4), UInt8[0x00, 0x10], UInt8[0x10, 0x00])
        off(v) = Wire.set_u64!(zeros(UInt8, 8), 1, UInt64(v))
        @test Wire.parse_pgwrite_cse(hdr) == Int64[]
        @test Wire.parse_pgwrite_cse(vcat(hdr, off(0), off(8192))) == Int64[0, 8192]
        @test_throws ArgumentError Wire.parse_pgwrite_cse(UInt8[0x00, 0x01])
        @test_throws ArgumentError Wire.parse_pgwrite_cse(vcat(hdr, zeros(UInt8, 7)))
    end
end
