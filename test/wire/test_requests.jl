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

using XRootD.Wire:
    MkdirRequest,
    RmRequest,
    RmdirRequest,
    MvRequest,
    ChmodRequest,
    TruncateRequest,
    LocateRequest,
    QueryRequest,
    OpenRequest,
    ReadRequest,
    WriteRequest,
    CloseRequest,
    SyncRequest,
    kXR_open_read,
    kXR_refresh,
    kXR_QStats

@testset "Wire fs/file operation requests" begin
    @testset "mkdir" begin
        f = encode(MkdirRequest("/d"; mode=UInt16(0o755), mkpath=true), UInt16(7))
        @test f[1:4] == UInt8[0x00, 0x07, 0x0b, 0xc0]
        @test f[5] == 0x01                       # kXR_mkdirpath
        @test f[19:20] == UInt8[0x01, 0xed]      # 0o755
        @test f[21:24] == UInt8[0, 0, 0, 2]
        @test f[25:26] == codeunits("/d")
    end

    @testset "rm / rmdir / close / sync" begin
        @test encode(RmRequest("/f"), UInt16(1))[3:4] == UInt8[0x0b, 0xc6]
        @test encode(RmdirRequest("/d"), UInt16(1))[3:4] == UInt8[0x0b, 0xc7]
        c = encode(CloseRequest((0x01, 0x02, 0x03, 0x04)), UInt16(1))
        @test c[3:4] == UInt8[0x0b, 0xbb]
        @test c[5:8] == UInt8[1, 2, 3, 4]
        s = encode(SyncRequest((0x01, 0x02, 0x03, 0x04)), UInt16(1))
        @test s[3:4] == UInt8[0x0b, 0xc8]
        @test s[5:8] == UInt8[1, 2, 3, 4]
    end

    @testset "mv carries arg1len and space-joined paths" begin
        f = encode(MvRequest("/a", "/bb"), UInt16(2))
        @test f[3:4] == UInt8[0x0b, 0xc1]
        @test f[19:20] == UInt8[0x00, 0x02]          # arg1len = ncodeunits("/a")
        @test String(f[25:end]) == "/a /bb"
    end

    @testset "chmod / truncate" begin
        f = encode(ChmodRequest("/f", UInt16(0o600)), UInt16(3))
        @test f[3:4] == UInt8[0x0b, 0xba]
        @test f[19:20] == UInt8[0x01, 0x80]
        t = encode(TruncateRequest("/f", Int64(5)), UInt16(3))
        @test t[3:4] == UInt8[0x0b, 0xd4]
        @test t[9:16] == UInt8[0, 0, 0, 0, 0, 0, 0, 5]
        @test String(t[25:end]) == "/f"
    end

    @testset "locate / query" begin
        f = encode(LocateRequest("/f"; options=kXR_refresh), UInt16(4))
        @test f[3:4] == UInt8[0x0b, 0xd3]
        @test f[5:6] == UInt8[0x00, 0x80]
        q = encode(QueryRequest(kXR_QStats, "a"), UInt16(4))
        @test q[3:4] == UInt8[0x0b, 0xb9]
        @test q[5:6] == UInt8[0x00, 0x01]
        @test String(q[25:end]) == "a"
    end

    @testset "open / read / write" begin
        o = encode(OpenRequest("/f"; mode=UInt16(0o644), options=kXR_open_read), UInt16(5))
        @test o[3:4] == UInt8[0x0b, 0xc2]
        @test o[5:6] == UInt8[0x01, 0xa4]
        @test o[7:8] == UInt8[0x00, 0x10]
        @test String(o[25:end]) == "/f"
        r = encode(
            ReadRequest((0x0a, 0x0b, 0x0c, 0x0d), Int64(1024), Int32(4096)), UInt16(6)
        )
        @test r[3:4] == UInt8[0x0b, 0xc5]
        @test r[5:8] == UInt8[0x0a, 0x0b, 0x0c, 0x0d]
        @test r[9:16] == UInt8[0, 0, 0, 0, 0, 0, 0x04, 0x00]
        @test r[17:20] == UInt8[0, 0, 0x10, 0x00]
        w = encode(
            WriteRequest((0x0a, 0x0b, 0x0c, 0x0d), Int64(0), UInt8[0xde, 0xad]), UInt16(6)
        )
        @test w[3:4] == UInt8[0x0b, 0xcb]
        @test w[5:8] == UInt8[0x0a, 0x0b, 0x0c, 0x0d]
        @test w[21:24] == UInt8[0, 0, 0, 2]
        @test w[25:26] == UInt8[0xde, 0xad]
    end
end

using XRootD.Wire: ReadVRequest, WriteVRequest, PgReadRequest, PgWriteRequest
using CRC32c: crc32c

@testset "Wire vector and paged io requests" begin
    fh = (0x01, 0x02, 0x03, 0x04)

    @testset "readv" begin
        r = encode(
            ReadVRequest([
                (; fhandle=fh, offset=Int64(0), rlen=Int32(16)),
                (; fhandle=fh, offset=Int64(4096), rlen=Int32(32)),
            ]),
            UInt16(9),
        )
        @test r[3:4] == UInt8[0x0b, 0xd1]        # kXR_readv (3025)
        @test r[21:24] == UInt8[0, 0, 0, 32]     # dlen = 2 entries x 16
        @test r[25:28] == UInt8[1, 2, 3, 4]      # entry 1: fhandle
        @test r[29:32] == UInt8[0, 0, 0, 16]     # entry 1: rlen
        @test r[33:40] == zeros(UInt8, 8)        # entry 1: offset 0
        @test r[41:44] == UInt8[1, 2, 3, 4]      # entry 2: fhandle
        @test r[45:48] == UInt8[0, 0, 0, 32]
        @test r[49:56] == UInt8[0, 0, 0, 0, 0, 0, 0x10, 0]   # 4096
    end

    @testset "writev: dlen covers descriptors only, data streams after" begin
        w = encode(
            WriteVRequest(
                [(; fhandle=fh, offset=Int64(8), data=UInt8[0xaa, 0xbb])]; do_sync=true
            ),
            UInt16(9),
        )
        @test w[3:4] == UInt8[0x0b, 0xd7]        # kXR_writev (3031)
        @test w[5] == 0x01                       # kXR_wv_doSync
        @test w[21:24] == UInt8[0, 0, 0, 16]     # dlen = descriptor list ONLY
        @test w[25:28] == UInt8[1, 2, 3, 4]
        @test w[29:32] == UInt8[0, 0, 0, 2]      # wlen
        @test w[33:40] == UInt8[0, 0, 0, 0, 0, 0, 0, 8]
        @test w[41:42] == UInt8[0xaa, 0xbb]      # data trailer (outside dlen)
        @test length(w) == 24 + 16 + 2

        w2 = encode(
            WriteVRequest([
                (; fhandle=fh, offset=Int64(0), data=UInt8[0x01]),
                (; fhandle=fh, offset=Int64(1), data=UInt8[0x02, 0x03]),
            ]),
            UInt16(9),
        )
        @test w2[21:24] == UInt8[0, 0, 0, 32]    # two descriptors
        @test w2[41:44] == UInt8[1, 2, 3, 4]     # segment 2 descriptor
        @test w2[57:59] == UInt8[0x01, 0x02, 0x03]  # concatenated data trailer
    end

    @testset "vector limits are enforced at construction" begin
        seg(off, len) = (; fhandle=fh, offset=Int64(off), rlen=Int32(len))
        @test_throws ArgumentError ReadVRequest(typeof(seg(0, 1))[])
        @test_throws ArgumentError ReadVRequest([seg(i, 1) for i in 0:(Wire.VEC_MAXSEGS)])
        @test_throws ArgumentError ReadVRequest([seg(0, -1)])
        @test_throws ArgumentError ReadVRequest([
            seg(0, Wire.VEC_MAXBYTES ÷ 2 + 1), seg(1 << 30, Wire.VEC_MAXBYTES ÷ 2 + 1)
        ])

        wseg(off, n) = (; fhandle=fh, offset=Int64(off), data=zeros(UInt8, n))
        @test_throws ArgumentError WriteVRequest(typeof(wseg(0, 1))[]; do_sync=false)
        @test_throws ArgumentError WriteVRequest(
            [wseg(i, 1) for i in 0:(Wire.VEC_MAXSEGS)]; do_sync=false
        )
    end

    @testset "reply caps bound what a server may answer" begin
        r = ReadVRequest([
            (; fhandle=fh, offset=Int64(0), rlen=Int32(16)),
            (; fhandle=fh, offset=Int64(4096), rlen=Int32(32)),
        ])
        @test Wire.readv_reply_cap(r) == 2 * 16 + 48

        p = PgReadRequest(fh, Int64(0), Int32(2 * Wire.kXR_pgPageSZ))
        # 2 full pages + 2 pages of slack, each with a CRC and a status body
        @test Wire.pgread_reply_cap(p) == 2 * Wire.kXR_pgPageSZ + 4 * (4 + 24)

        pw = PgWriteRequest(fh, Int64(0), zeros(UInt8, Wire.kXR_pgPageSZ + 1))
        @test Wire.pgwrite_reply_cap(pw) == 24 + Wire.PGW_CSE_HDRLEN + 8 * 3
    end

    @testset "pgread / pgwrite" begin
        p = encode(PgReadRequest(fh, Int64(4096), Int32(8192)), UInt16(9))
        @test p[3:4] == UInt8[0x0b, 0xd6]        # kXR_pgread (3030)
        @test p[5:8] == UInt8[1, 2, 3, 4]
        @test p[9:16] == UInt8[0, 0, 0, 0, 0, 0, 0x10, 0]
        @test p[17:20] == UInt8[0, 0, 0x20, 0]

        pw = encode(PgWriteRequest(fh, Int64(0), UInt8[0xde, 0xad]), UInt16(9))
        @test pw[3:4] == UInt8[0x0b, 0xd2]       # kXR_pgwrite (3026)
        @test pw[5:8] == UInt8[1, 2, 3, 4]
        @test pw[9:16] == zeros(UInt8, 8)
        @test pw[17] == 0x00                     # pathid
        @test pw[18] == 0x00                     # reqflags
        # payload is [crc32c][page] units: 4-byte CRC + 2 data bytes
        @test pw[21:24] == UInt8[0, 0, 0, 6]
        crc = Wire.get_u32(pw, 25)
        @test pw[29:30] == UInt8[0xde, 0xad]
        @test crc == crc32c(UInt8[0xde, 0xad])
    end

    @testset "clone" begin
        src = (0x0a, 0x0b, 0x0c, 0x0d)
        c = encode(
            Wire.CloneRequest(
                fh,
                Wire.CloneItem[
                    (;
                        fhandle=src,
                        src_offset=Int64(0),
                        src_len=Int64(16),
                        dst_offset=Int64(4096),
                    ),
                    (;
                        fhandle=src,
                        src_offset=Int64(8192),
                        src_len=Int64(1),
                        dst_offset=Int64(0),
                    ),
                ],
            ),
            UInt16(9),
        )
        @test c[3:4] == UInt8[0x0b, 0xd8]        # kXR_clone (3032)
        @test c[5:8] == UInt8[1, 2, 3, 4]        # destination handle
        @test all(==(0x00), c[9:20])             # reserved
        @test c[21:24] == UInt8[0, 0, 0, 64]     # dlen = 2 items x 32
        @test c[25:28] == UInt8[0x0a, 0x0b, 0x0c, 0x0d]
        @test all(==(0x00), c[29:32])            # per-item reserved
        @test Wire.get_u64(c, 33) == 0           # src_offset
        @test Wire.get_u64(c, 41) == 16          # src_len
        @test Wire.get_u64(c, 49) == 4096        # dst_offset
        @test c[57:60] == UInt8[0x0a, 0x0b, 0x0c, 0x0d]
        @test Wire.get_u64(c, 65) == 8192
        @test length(c) == 24 + 64

        item(off) =
            (; fhandle=src, src_offset=Int64(off), src_len=Int64(1), dst_offset=Int64(off))
        @test_throws ArgumentError Wire.CloneRequest(fh, Wire.CloneItem[])
        @test_throws ArgumentError Wire.CloneRequest(
            fh, Wire.CloneItem[item(i) for i in 0:(Wire.CLONE_MAXITEMS)]
        )
        @test_throws ArgumentError Wire.CloneRequest(fh, Wire.CloneItem[item(-1)])
        @test_throws ArgumentError Wire.CloneRequest(
            fh,
            Wire.CloneItem[(;
                fhandle=src, src_offset=Int64(0), src_len=Int64(-1), dst_offset=Int64(0)
            )],
        )

        # Like kXR_readv, a clone names handles a reopen cannot re-aim: the
        # source handle lives in the payload, not in the header field
        # `with_fhandle` rewrites.
        one = Wire.CloneRequest(fh, Wire.CloneItem[item(0)])
        @test Wire.with_fhandle(one, src).dst_fhandle == fh
    end
end

using XRootD.Wire:
    FattrRequest,
    SetattrRequest,
    SymlinkRequest,
    LinkRequest,
    ReadlinkRequest,
    PrepareRequest,
    kXR_fattrGet,
    kXR_fattrSet,
    kXR_fattrList,
    kXR_stage

@testset "Wire extended operation requests" begin
    @testset "fattr get/set/list" begin
        g = encode(FattrRequest(kXR_fattrGet, "/f"; names=["user.x"]), UInt16(1))
        @test g[3:4] == UInt8[0x0b, 0xcc]        # kXR_fattr (3020)
        @test g[9] == kXR_fattrGet
        @test g[10] == 0x01                      # numattr
        @test String(g[25:27]) == "/f\0"         # path + NUL
        @test g[28:29] == UInt8[0x00, 0x00]      # nvec rc
        @test String(g[30:36]) == "user.x\0"

        s = encode(
            FattrRequest(kXR_fattrSet, "/f"; names=["a"], values=[UInt8[0x01, 0x02]]),
            UInt16(1),
        )
        @test s[9] == kXR_fattrSet
        # after "/f\0" + rc(2) + "a\0" comes vvec [int32 len][value]
        tail = s[25:end]
        i = findfirst(==(0x00), tail) + 1        # after path NUL
        @test tail[(i + 2):(i + 3)] == codeunits("a\0")[1:2]

        l = encode(FattrRequest(kXR_fattrList, "/f"), UInt16(1))
        @test l[9] == kXR_fattrList
        @test l[10] == 0x00
    end

    @testset "setattr prefix" begin
        f = encode(SetattrRequest("/f"; flags=1, mtime=(1700000000, 0)), UInt16(2))
        @test f[3:4] == UInt8[0x0d, 0xac]        # kXR_setattr (3500)
        @test Wire.get_u32(f, 25) == 1           # flags at payload start
        @test Wire.get_u64(f, 25 + 20) == 1700000000  # mtime_s at prefix off 20
        @test String(f[(25 + 44):end]) == "/f\0"
    end

    @testset "symlink / link / readlink" begin
        sl = encode(SymlinkRequest("/target", "/link"), UInt16(3))
        @test sl[3:4] == UInt8[0x0d, 0xad]       # kXR_symlink (3501)
        @test Wire.get_u16(sl, 19) == ncodeunits("/target")
        @test String(sl[25:end]) == "/target /link"

        ln = encode(LinkRequest("/old", "/new"), UInt16(3))
        @test ln[3:4] == UInt8[0x0d, 0xaf]       # kXR_link (3503)
        @test Wire.get_u16(ln, 19) == ncodeunits("/old")

        rl = encode(ReadlinkRequest("/link"), UInt16(3))
        @test rl[3:4] == UInt8[0x0d, 0xae]       # kXR_readlink (3502)
        @test String(rl[25:end]) == "/link"
    end

    @testset "prepare" begin
        p = encode(PrepareRequest(["/a", "/b"]; options=kXR_stage), UInt16(4))
        @test p[3:4] == UInt8[0x0b, 0xcd]        # kXR_prepare (3021)
        @test p[5] == kXR_stage
        @test String(p[25:end]) == "/a\n/b"
    end

    @testset "gpfile" begin
        g = encode(Wire.GPFileRequest("/f"; options=2, buffsz=65536), UInt16(5))
        @test g[3:4] == UInt8[0x0b, 0xbd]        # kXR_gpfile (3005)
        @test Wire.get_u32(g, 5) == 2            # options
        @test all(==(0x00), g[9:16])             # reserved[8]
        @test Wire.get_u32(g, 17) == 65536       # buffsz
        @test Wire.get_u32(g, 21) == 2
        @test String(g[25:end]) == "/f"
        # The options field is signed on the wire, and the sign has to survive.
        neg = encode(Wire.GPFileRequest("/f"; options=-1), UInt16(5))
        @test neg[5:8] == UInt8[0xff, 0xff, 0xff, 0xff]
        @test Wire.with_cgi(Wire.GPFileRequest("/f"), "a=1").path == "/f?a=1"
    end
end

@testset "opaque data can be merged onto a request's path" begin
    # A redirector's CGI has to reach the destination on the retried
    # request, and the caller's own CGI has to survive the merge.
    @test Wire.merge_cgi("/f", "a=1") == "/f?a=1"
    @test Wire.merge_cgi("/f?mine=1", "a=1") == "/f?mine=1&a=1"
    @test Wire.merge_cgi("/f", "") == "/f"

    @test Wire.with_cgi(StatRequest("/f"), "a=1").path == "/f?a=1"
    @test Wire.with_cgi(OpenRequest("/f?m=1"; options=kXR_open_read), "a=1").path ==
        "/f?m=1&a=1"
    @test Wire.with_cgi(MkdirRequest("/f"; mkpath=true), "a=1").mkpath
    @test Wire.with_cgi(TruncateRequest("/f", Int64(9)), "a=1").size == 9
    @test Wire.with_cgi(RmRequest("/f"), "").path == "/f"

    # A request that names no path is handed back untouched — there is
    # nowhere to put the opaque data and inventing one would be wrong.
    @test Wire.with_cgi(PingRequest(), "a=1") isa PingRequest
    @test Wire.with_cgi(MvRequest("/a", "/b"), "a=1").src == "/a"
end

@testset "a path need not already be a String" begin
    # Paths arrive as views far more often than as String: splitting a
    # directory listing, slicing a URL, iterating `eachsplit`. Every request
    # that names one accepts any AbstractString and stores a String, so the
    # frame is byte-identical to the one built from a String.
    parts = split("/store/data /store/temp", ' ')     # SubString{String}
    src, dst = parts[1], parts[2]
    @test src isa SubString

    @test encode(RmRequest(src), UInt16(1)) == encode(RmRequest("/store/data"), UInt16(1))
    @test encode(RmdirRequest(src), UInt16(1)) ==
        encode(RmdirRequest("/store/data"), UInt16(1))
    @test encode(MvRequest(src, dst), UInt16(1)) ==
        encode(MvRequest("/store/data", "/store/temp"), UInt16(1))
    @test encode(ChmodRequest(src, 0o755), UInt16(1)) ==
        encode(ChmodRequest("/store/data", 0o755), UInt16(1))
    @test encode(SymlinkRequest(src, dst), UInt16(1)) ==
        encode(SymlinkRequest("/store/data", "/store/temp"), UInt16(1))
    @test encode(LinkRequest(src, dst), UInt16(1)) ==
        encode(LinkRequest("/store/data", "/store/temp"), UInt16(1))
    @test encode(ReadlinkRequest(src), UInt16(1)) ==
        encode(ReadlinkRequest("/store/data"), UInt16(1))

    args = split("stats /store", ' ')[2]
    @test encode(QueryRequest(kXR_QStats, args), UInt16(1)) ==
        encode(QueryRequest(kXR_QStats, "/store"), UInt16(1))

    @test RmRequest(src).path isa String
    @test MvRequest(src, dst).dst isa String
end

using XRootD.Wire:
    ChkPointRequest,
    CloseRequest,
    EndsessRequest,
    QueryRequest,
    ReadRequest,
    SetRequest,
    StatxRequest,
    SyncRequest,
    TruncateRequest,
    WriteRequest,
    kXR_ckpBegin,
    kXR_ckpRollback,
    kXR_ckpXeq,
    kXR_fattrList,
    kXR_Qcksum,
    kXR_Qvisa,
    kXR_write

@testset "requests that name an open file handle" begin
    fh = (0xde, 0xad, 0xbe, 0xef)

    @testset "kXR_close carries a verified size" begin
        # Bytes 9:16 are the size the close must agree with; 17:20 stay zero.
        p = encode(CloseRequest(fh; fsize=1024), UInt16(1))
        @test p[3:4] == UInt8[0x0b, 0xbb]                 # kXR_close (3003)
        @test Tuple(p[5:8]) == fh
        @test p[9:16] == UInt8[0, 0, 0, 0, 0, 0, 0x04, 0x00]
        @test all(==(0x00), p[17:24])
        # The default suppresses the check rather than asking for a zero-byte file.
        @test all(==(0x00), encode(CloseRequest(fh), UInt16(1))[9:24])
    end

    @testset "kXR_query can name a handle instead of a path" begin
        # The handle sits at parameter bytes 9:12, past a two-byte hole.
        p = encode(QueryRequest(kXR_Qvisa; fhandle=fh), UInt16(1))
        @test p[3:4] == UInt8[0x0b, 0xb9]                 # kXR_query (3001)
        @test Wire.get_u16(p, 5) == kXR_Qvisa
        @test all(==(0x00), p[7:8])
        @test Tuple(p[9:12]) == fh
        @test Wire.get_u32(p, 21) == 0                    # no arguments
        # The path form leaves the handle zero.
        @test all(==(0x00), encode(QueryRequest(kXR_Qcksum, "/f"), UInt16(1))[9:12])
    end

    @testset "kXR_chkpoint puts its subcode in the last parameter byte" begin
        p = encode(ChkPointRequest(fh, kXR_ckpBegin), UInt16(7))
        @test p[3:4] == UInt8[0x0b, 0xc4]                 # kXR_chkpoint (3012)
        @test Tuple(p[5:8]) == fh
        @test all(==(0x00), p[9:19])                      # reserved
        @test p[20] == kXR_ckpBegin
        @test Wire.get_u32(p, 21) == 0
        @test encode(ChkPointRequest(fh, kXR_ckpRollback), UInt16(7))[20] == kXR_ckpRollback
    end

    @testset "kXR_ckpXeq frames the embedded header alone" begin
        inner = WriteRequest(fh, Int64(16), UInt8[0xaa, 0xbb])
        p = encode(Wire.checkpoint_exec(fh, inner), UInt16(7))
        @test p[20] == kXR_ckpXeq
        # dlen counts the 24-byte embedded header and nothing else; the
        # embedded request's own data trails outside the frame, on the same
        # rule kXR_writev follows.
        @test Wire.get_u32(p, 21) == Wire.REQUEST_HDRLEN
        @test length(p) == 24 + Wire.REQUEST_HDRLEN + 2
        embedded = p[25:(24 + Wire.REQUEST_HDRLEN)]
        @test Wire.get_u16(embedded, 3) == kXR_write
        @test Tuple(embedded[5:8]) == fh
        @test Wire.get_u32(embedded, 21) == 2             # the inner dlen
        @test p[(end - 1):end] == UInt8[0xaa, 0xbb]
        # The embedded header carries no stream id: the answer comes back on
        # the outer frame's.
        @test Wire.get_u16(embedded, 1) == 0

        @test Wire.checkpoint_exec(fh, TruncateRequest("", Int64(4), fh)) isa
            ChkPointRequest
        @test_throws ArgumentError Wire.checkpoint_exec(fh, StatRequest("/f"))
    end

    @testset "kXR_statx, kXR_set and kXR_endsess" begin
        p = encode(StatxRequest(["/a", "/b"]), UInt16(1))
        @test p[3:4] == UInt8[0x0b, 0xce]                 # kXR_statx (3022)
        @test all(==(0x00), p[5:20])
        @test String(p[25:end]) == "/a\n/b"

        p = encode(SetRequest("appid test"), UInt16(1))
        @test p[3:4] == UInt8[0x0b, 0xca]                 # kXR_set (3018)
        @test String(p[25:end]) == "appid test"

        id = UInt8[i for i in 1:16]
        p = encode(EndsessRequest(id), UInt16(1))
        @test p[3:4] == UInt8[0x0b, 0xcf]                 # kXR_endsess (3023)
        @test p[5:20] == id
        @test Wire.get_u32(p, 21) == 0
        # A short id is right-padded, an over-long one is refused.
        @test EndsessRequest(UInt8[0x01]).sessid[2] == 0x00
        @test_throws ArgumentError EndsessRequest(zeros(UInt8, 17))
        @test all(==(0x00), encode(EndsessRequest(), UInt16(1))[5:20])
    end
end

@testset "a request can be re-aimed at a reopened handle" begin
    # A file handle is valid only on the connection it was opened on, so a
    # request replayed after a reopen has to name the new one.
    fh = (0x11, 0x22, 0x33, 0x44)
    for req in (
        ReadRequest(Wire.NULL_FHANDLE, Int64(8), Int32(16)),
        WriteRequest(Wire.NULL_FHANDLE, Int64(8), UInt8[0x01]),
        PgReadRequest(Wire.NULL_FHANDLE, Int64(0), Int32(4096)),
        PgWriteRequest(Wire.NULL_FHANDLE, Int64(0), UInt8[0x01]),
        SyncRequest(Wire.NULL_FHANDLE),
        CloseRequest(Wire.NULL_FHANDLE; fsize=3),
        StatRequest(""; fhandle=Wire.NULL_FHANDLE),
        TruncateRequest("", Int64(2), Wire.NULL_FHANDLE),
        QueryRequest(kXR_Qvisa; fhandle=Wire.NULL_FHANDLE),
        FattrRequest(kXR_fattrList, ""; fhandle=Wire.NULL_FHANDLE),
        ChkPointRequest(Wire.NULL_FHANDLE, kXR_ckpBegin),
    )
        aimed = Wire.with_fhandle(req, fh)
        @test aimed.fhandle == fh
        @test Wire.requestid(aimed) == Wire.requestid(req)
    end

    # The rest of the request survives the re-aiming.
    r = Wire.with_fhandle(ReadRequest(Wire.NULL_FHANDLE, Int64(8), Int32(16)), fh)
    @test r.offset == 8 && r.rlen == 16
    @test Wire.with_fhandle(CloseRequest(Wire.NULL_FHANDLE; fsize=3), fh).fsize == 3

    # A request that names no handle is handed back untouched — kXR_readv
    # among them, because its segments may name several files at once.
    @test Wire.with_fhandle(PingRequest(), fh) isa PingRequest
    @test Wire.with_fhandle(RmRequest("/f"), fh).path == "/f"
    rv = ReadVRequest([(fhandle=Wire.NULL_FHANDLE, offset=Int64(0), rlen=Int32(8))])
    @test Wire.with_fhandle(rv, fh).segments[1].fhandle == Wire.NULL_FHANDLE
end

@testset "requests routed over a bound data path" begin
    fh = (0x0a, 0x0b, 0x0c, 0x0d)

    @testset "kXR_bind names the session to join" begin
        id = UInt8[i for i in 1:16]
        p = encode(Wire.BindRequest(id), UInt16(3))
        @test p[3:4] == UInt8[0x0b, 0xd0]                 # kXR_bind (3024)
        @test p[5:20] == id
        @test Wire.get_u32(p, 21) == 0
        @test Wire.decode_bind(UInt8[0x02]) == 0x02
        # A reply naming path 0 names the control link, which would send the
        # data straight back down the link the bind was meant to relieve.
        @test_throws ArgumentError Wire.decode_bind(UInt8[0x00])
        @test_throws ArgumentError Wire.decode_bind(UInt8[])
    end

    @testset "kXR_read asks for its answer on the path" begin
        r = encode(ReadRequest(fh, Int64(1024), Int32(4096); pathid=0x03), UInt16(6))
        # The header is unchanged; the id rides in the optional arguments,
        # whose length is what dlen counts (alen = 8, no pre-read hints).
        @test Tuple(r[5:8]) == fh
        @test r[9:16] == UInt8[0, 0, 0, 0, 0, 0, 0x04, 0x00]
        @test r[17:20] == UInt8[0, 0, 0x10, 0x00]
        @test Wire.get_u32(r, 21) == 8
        @test r[25] == 0x03
        @test all(==(0x00), r[26:32])
        @test length(r) == 32
        @test Wire.pathid(ReadRequest(fh, Int64(0), Int32(1); pathid=0x03)) == 0x03
        # On the control link the request is byte-identical to one that never
        # heard of data paths.
        plain = encode(ReadRequest(fh, Int64(1024), Int32(4096)), UInt16(6))
        @test length(plain) == 24 && Wire.get_u32(plain, 21) == 0
        @test Wire.pathid(ReadRequest(fh, Int64(0), Int32(1))) == 0x00
    end

    @testset "kXR_write declares its data but sends it elsewhere" begin
        data = UInt8[0xde, 0xad, 0xbe, 0xef]
        w = encode(WriteRequest(fh, Int64(0), data; pathid=0x02), UInt16(6))
        @test Tuple(w[5:8]) == fh
        @test w[17] == 0x02                               # path id
        @test all(==(0x00), w[18:20])                     # reserved
        # dlen counts the data wherever it travels, but the frame does not
        # carry it: it goes out on the bound socket instead.
        @test Wire.get_u32(w, 21) == length(data)
        @test length(w) == 24
        @test Wire.path_data(WriteRequest(fh, Int64(0), data; pathid=0x02)) == data
        @test isempty(Wire.payload(WriteRequest(fh, Int64(0), data; pathid=0x02)))

        # Path 0 keeps the data in the frame, exactly as before.
        plain = encode(WriteRequest(fh, Int64(0), data), UInt16(6))
        @test plain[17] == 0x00
        @test Wire.get_u32(plain, 21) == length(data)
        @test plain[25:end] == data
        @test isempty(Wire.path_data(WriteRequest(fh, Int64(0), data)))
    end

    @testset "a replayed request comes home to the control link" begin
        # The path id belonged to the session that went away; the reopened one
        # has bound nothing.
        r = Wire.without_pathid(ReadRequest(fh, Int64(8), Int32(16); pathid=0x03))
        @test r.pathid == 0x00 && r.offset == 8 && r.rlen == 16
        w = Wire.without_pathid(WriteRequest(fh, Int64(8), UInt8[0x01]; pathid=0x03))
        @test w.pathid == 0x00 && w.data == UInt8[0x01]
        @test Wire.without_pathid(PingRequest()) isa PingRequest
    end
end
