using XRootD.XrdCl
using XRootD.XrdCl: StatInfo, Location, ProtocolInfo

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
end
