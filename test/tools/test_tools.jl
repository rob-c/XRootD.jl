using XRootD.Tools
using XRootD.Tools: adler32, crc64xz, copyfile, checksum_file
using CRC32c: crc32c

const Xrdcp = XRootD.Tools.Xrdcp
const Cksum = XRootD.Tools.Cksum

@testset "Tools" begin
    @testset "checksum algorithms" begin
        # Adler-32 of "Wikipedia" is 0x11E60398 (RFC 1950 worked example).
        @test adler32(Vector{UInt8}(codeunits("Wikipedia"))) == 0x11e60398
        # CRC-64/XZ of "123456789" is 0x995DC9BBDF1939FA (rocksoft/xz vector).
        @test crc64xz(Vector{UInt8}(codeunits("123456789"))) == 0x995dc9bbdf1939fa
    end

    @testset "checksum_file (local)" begin
        dir = mktempdir()
        path = joinpath(dir, "data.bin")
        data = Vector{UInt8}(codeunits("123456789"))
        write(path, data)
        @test checksum_file(path, :crc64) == "995dc9bbdf1939fa"
        @test checksum_file(path, :crc32c) == string(crc32c(data); base=16, pad=8)
        @test checksum_file(path, :adler32) == string(adler32(data); base=16, pad=8)
    end

    @testset "copyfile local→local" begin
        dir = mktempdir()
        src = joinpath(dir, "a.bin")
        dst = joinpath(dir, "b.bin")
        data = rand(UInt8, 4096)
        write(src, data)
        ok, _ = copyfile(src, dst; verify=true)
        @test ok
        @test read(dst) == data
        # without force, refuse to overwrite
        ok2, _ = copyfile(src, dst; force=false)
        @test !ok2
        ok3, _ = copyfile(src, dst; force=true)
        @test ok3
    end

    @testset "xrdcp main (local)" begin
        dir = mktempdir()
        src = joinpath(dir, "s.bin")
        dst = joinpath(dir, "d.bin")
        write(src, "payload")
        @test Xrdcp.main(["-f", "--verify", src, dst]) == 0
        @test read(dst, String) == "payload"
        @test Xrdcp.main([src]) == 2                       # usage error
        @test Xrdcp.main(["--version"]) == 0
    end

    @testset "checksum tool mains (local)" begin
        dir = mktempdir()
        path = joinpath(dir, "c.bin")
        write(path, "123456789")
        @test Cksum.crc64_main([path]) == 0
        @test Cksum.adler32_main([path]) == 0
        @test Cksum.ckverify_main([path, "crc64", "995dc9bbdf1939fa"]) == 0
        @test Cksum.ckverify_main([path, "crc64", "deadbeef"]) == 1
        @test Cksum.ckverify_main([path]) == 2             # usage
    end
end
