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
        @test s == (; id="1234567", size=16, flags=UInt32(65536), mtime=1700000000)
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
        @test ds.stats[1] == (; id="10", size=100, flags=UInt32(0), mtime=1700000000)
        @test ds.stats[2].flags == UInt32(19)

        empty = parse_dirlist(UInt8[])
        @test empty.entries == String[] && empty.stats === nothing
    end
end
