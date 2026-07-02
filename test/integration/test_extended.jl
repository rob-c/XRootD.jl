# Extended FileSystem ops against the real XRootD_jll server: xattr round
# trips, statvfs, and remote checksum. (Vendor symlink/hardlink/readlink need
# a server advertising xrdfs.ext — covered by the wire golden tests, not
# exercised here against stock xrootd.)

using XRootD.XrdCl
using XRootD.XrdCl: getxattr, setxattr, listxattr, removexattr, statvfs, checksum

@testset "extended operations" begin
    fs = FileSystem("root://localhost:1094")
    write("/tmp/xattr_testfile", "attr me")

    @testset "xattr round trip" begin
        st, _ = setxattr(
            fs, "/tmp/xattr_testfile", "user.color", Vector{UInt8}(codeunits("blue"))
        )
        if isOK(st)                      # server may disable xattrs on the export
            st, names = listxattr(fs, "/tmp/xattr_testfile")
            @test isOK(st)
            @test "user.color" in names
            st, val = getxattr(fs, "/tmp/xattr_testfile", "user.color")
            @test isOK(st)
            @test String(val) == "blue"
            st, _ = removexattr(fs, "/tmp/xattr_testfile", "user.color")
            @test isOK(st)
        else
            @info "server rejected setxattr; skipping xattr round trip" status = st
        end
    end

    @testset "statvfs" begin
        st, vfs = statvfs(fs, "/tmp")
        @test isOK(st)
        @test !isempty(vfs.raw)
    end

    @testset "checksum" begin
        st, cks = checksum(fs, "/tmp/xattr_testfile")
        # checksum config is optional; accept success or a clean error status
        if isOK(st)
            @test occursin(" ", cks) || !isempty(cks)
        else
            @test isError(st)
        end
    end

    rm("/tmp/xattr_testfile")
end
