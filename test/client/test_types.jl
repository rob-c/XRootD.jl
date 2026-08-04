using XRootD.XrdCl
using XRootD.XrdCl: StatInfo, Location, ProtocolInfo
using XRootD.XrdCl: StatFlags, cksum_path, ismanager, split_address
using XRootD: Wire

@testset "XrdCl types" begin
    @testset "XRootDStatus" begin
        ok = XRootDStatus()
        @test isOK(ok)
        @test !isError(ok)
        @test occursin("SUCCESS", sprint(show, ok))

        bad = XRootDStatus(0x0003, 0x0065, 2, "No such file")
        @test isError(bad)
        @test !isOK(bad)
        s = sprint(show, bad)
        @test occursin("ERROR", s) && occursin("No such file", s)

        # The one-argument form is the bare status word: no code, no message.
        only_status = XRootDStatus(0x0003)
        @test isError(only_status)
        @test only_status.code == 0x0000
        @test only_status.errNo == 0
        @test only_status.message == ""
        @test isOK(XRootDStatus(0x0000))
    end

    @testset "StatInfo basic + extended" begin
        b = StatInfo("123 13 51 1700000000")
        @test b.size == 13
        @test b.flags == UInt32(51)                 # xset|isDir? no: 51 = 0x33
        @test b.modtime == 1700000000
        @test b.owner == "" && b.mode == ""

        e = StatInfo("123 13 51 1700000000 1700000001 1700000002 0644 rob users")
        @test e.owner == "rob" && e.group == "users"
        @test e.mode == "0644"
        @test e.octmode == "rw-r--r--"
        @test e.ctime == 1700000001

        m = StatInfo("1 0 0 0 0 0 0775 u g")
        @test m.octmode == "rwxrwxr-x"

        show(devnull, e)
    end

    @testset "StatInfo predicates" begin
        dir = StatInfo("1 4096 $(Int(0x02 | 0x01 | 0x10 | 0x20)) 0")   # isDir|xset|r|w
        @test isdir(dir)
        @test !isfile(dir)
        @test isreadable(dir)
        @test iswritable(dir)
        @test isExecutable(dir)
        @test !isOffline(dir)

        f = StatInfo("1 10 $(Int(0x10)) 0")                            # readable file
        @test isfile(f)
        @test !isdir(f)
        @test !iswritable(f)
    end

    @testset "flag namespaces" begin
        @test OpenFlags.Read == 0x0010
        @test OpenFlags.Update == 0x0020
        @test OpenFlags.New == 0x0008
        @test OpenFlags.Delete == 0x0002
        @test OpenFlags.Refresh == 0x0080
        @test OpenFlags.MakePath == 0x0100
        @test OpenFlags.Write == 0x8000
        @test OpenFlags.New | OpenFlags.Write == 0x8008
        @test Access.UR | Access.UW == 0o600
        @test Access.None == 0
        @test DirListFlags.Stat == 1
        @test QueryCode.Stats == 1
        @test QueryCode.Space == 5
        @test QueryCode.Config == 7
        @test MkDirFlags.MakePath == 1
    end

    @testset "Location / ProtocolInfo show" begin
        loc = Location("[::127.0.0.1]:1094", 'S', 'r')
        @test occursin("1094", sprint(show, loc))
        p = ProtocolInfo(0x00000520, 0x00000001)
        @test occursin("1312", sprint(show, p)) ||
            occursin("0x", sprint(show, p)) ||
            occursin("5.2", sprint(show, p))
        show(devnull, p)
    end

    @testset "StatFlags" begin
        # kXR_statx answers one flags byte per path: the same bitfield StatInfo
        # carries, so the predicates read the same on either.
        dir = StatFlags(Wire.kXR_isDir | Wire.kXR_readable | Wire.kXR_writable)
        @test isdir(dir) && !isfile(dir)
        @test isreadable(dir) && iswritable(dir)
        @test !isExecutable(dir) && !isOffline(dir)
        @test occursin("dir", sprint(show, dir)) && occursin("rw", sprint(show, dir))

        # A plain file is the absence of every type bit, not a bit of its own.
        f = StatFlags(Wire.kXR_readable | Wire.kXR_xset)
        @test isfile(f) && !isdir(f)
        @test isExecutable(f) && !iswritable(f)
        @test occursin("file", sprint(show, f)) && occursin("r-", sprint(show, f))

        off = StatFlags(Wire.kXR_offline)
        @test isOffline(off)
        @test occursin("offline", sprint(show, off))

        # kXR_other is neither, so it is not a file either.
        other = StatFlags(Wire.kXR_other)
        @test !isfile(other) && !isdir(other)
        @test occursin("other", sprint(show, other))

        @test StatFlags(2) === StatFlags(UInt32(2))
    end

    @testset "the flag namespaces beyond 0.2.x" begin
        @test PrepareFlags.Stage == 0x08
        @test PrepareFlags.Cancel == 0x01
        @test PrepareFlags.Notify | PrepareFlags.NoErrors == 0x06
        @test PrepareFlags.Fresh == 0x40
        @test PrepareFlags.None == 0x00

        @test LocateFlags.AddPeers == 0x0001
        @test LocateFlags.Refresh == 0x0080
        @test LocateFlags.PreferName == 0x0100
        @test LocateFlags.NoWait == 0x2000

        @test ChkPointCode.Begin == 0x00
        @test ChkPointCode.Commit == 0x01
        @test ChkPointCode.Query == 0x02
        @test ChkPointCode.Rollback == 0x03
        @test ChkPointCode.Xeq == 0x04

        # The error namespace is numerically distinct from the opcodes it
        # shares a range with, and it has holes where codes went unassigned.
        @test ErrorCode.NotFound == 3011
        @test ErrorCode.ItExists == 3018
        @test ErrorCode.AttrNotFound == 3027
        @test ErrorCode.TooManyErrs == 3033
        @test error_name(XRootDStatus(0x0002, ErrorCode.ItExists, 0, "")) == "kXR_ItExists"
        @test error_name(XRootDStatus(0x0002, UInt16(3026), 0, "")) == "kXR_error(3026)"
    end

    @testset "locate answers name managers and addresses" begin
        @test ismanager(Location("h:1094", 'M', 'r'))
        @test ismanager(Location("h:1094", 'm', 'r'))    # pending is still a manager
        @test !ismanager(Location("h:1094", 'S', 'r'))

        # An address that names a port keeps it; one that does not inherits
        # the handle's, and an IPv6 literal loses only its brackets.
        @test split_address("host:1095", 1094) == ("host", 1095)
        @test split_address("host", 1094) == ("host", 1094)
        @test split_address("[::1]:1095", 1094) == ("::1", 1095)
        @test split_address("[::1]", 1094) == ("::1", 1094)
        # A trailing colon that is not a port is not one.
        @test split_address("host:abc", 1094) == ("host:abc", 1094)
    end

    @testset "a checksum algorithm travels as CGI" begin
        @test cksum_path("/f", "") == "/f"
        @test cksum_path("/f", "md5") == "/f?cks.type=md5"
        # A path that already carries opaque data keeps it.
        @test cksum_path("/f?authz=tok", "crc32c") == "/f?authz=tok&cks.type=crc32c"
    end

    @testset "a protocol reply names the endpoint's role" begin
        srv = ProtocolInfo(0x00000520, Wire.kXR_isServer)
        @test isserver(srv) && !ismanager(srv)
        @test !ismeta(srv) && !isproxy(srv) && !issupervisor(srv)
        @test occursin("server", sprint(show, srv))

        mgr = ProtocolInfo(0x00000520, Wire.kXR_isManager | Wire.kXR_haveTLS)
        @test ismanager(mgr) && !isserver(mgr)
        @test occursin("manager", sprint(show, mgr))

        # The attribute bits qualify the role rather than replacing it: a
        # supervisor is still a manager, and a proxy still fronts one.
        sup = ProtocolInfo(0x00000520, Wire.kXR_isManager | Wire.kXR_attrSuper)
        @test ismanager(sup) && issupervisor(sup)
        @test occursin("supervisor", sprint(show, sup))

        meta = ProtocolInfo(0x00000520, Wire.kXR_isManager | Wire.kXR_attrMeta)
        @test ismeta(meta) && occursin("meta-manager", sprint(show, meta))

        proxy = ProtocolInfo(0x00000520, Wire.kXR_isServer | Wire.kXR_attrProxy)
        @test isproxy(proxy) && occursin("proxy server", sprint(show, proxy))

        # A server that claims neither role gets no role invented for it.
        @test occursin("unknown", sprint(show, ProtocolInfo(0x00000520, 0x00000000)))

        # ismanager reads the same on the locate answer and on the protocol reply.
        @test ismanager(Location("h:1094", 'M', 'r')) == ismanager(mgr)
        @test isserver(Location("h:1094", 'S', 'r')) == isserver(srv)
    end
end
