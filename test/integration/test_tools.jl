# Copy engine + xrdcp/xrdfs against the real XRootD_jll server.

using XRootD.Tools: copyfile, checksum_file

const Xrdcp = XRootD.Tools.Xrdcp
const Xrdfs = XRootD.Tools.Xrdfs

@testset "tools integration" begin
    data = rand(UInt8, 12000)
    write("/tmp/tool_src", data)

    @testset "copy local→root→local" begin
        remote = "root://localhost:1094//tmp/tool_remote"
        ok, _ = copyfile("/tmp/tool_src", remote; force=true, verify=true)
        @test ok
        @test read("/tmp/tool_remote") == data

        ok, _ = copyfile(remote, "/tmp/tool_back"; force=true, verify=true)
        @test ok
        @test read("/tmp/tool_back") == data
    end

    @testset "checksum of a root:// file matches local" begin
        remote = "root://localhost:1094//tmp/tool_src"
        @test checksum_file(remote, :crc64) == checksum_file("/tmp/tool_src", :crc64)
    end

    @testset "xrdcp main to/from root" begin
        rc = Xrdcp.main(["-f", "/tmp/tool_src", "root://localhost:1094//tmp/tool_cp"])
        @test rc == 0
        @test read("/tmp/tool_cp") == data
    end

    @testset "xrdfs ls / stat / rm" begin
        @test Xrdfs.main(["localhost", "stat", "/tmp/tool_src"]) == 0
        @test Xrdfs.main(["localhost", "ls", "/tmp"]) == 0
        @test Xrdfs.main(["localhost", "rm", "/tmp/tool_cp"]) == 0
        @test !isfile("/tmp/tool_cp")
    end

    foreach(
        p -> isfile(p) && rm(p), ("/tmp/tool_src", "/tmp/tool_remote", "/tmp/tool_back")
    )
end
