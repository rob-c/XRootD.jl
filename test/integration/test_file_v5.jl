# v5 parity additions (sync / readv / writev / pgread / pgwrite) against a
# real xrootd server. The legacy files cover the 0.2.x surface; this covers
# what 0.2.x never had.

using XRootD.XrdCl
using XRootD.XrdCl: sync, readv, writev, pgread, pgwrite

@testset "v5 file io" begin
    data = rand(UInt8, 20000)
    write("/tmp/v5_testfile", data)

    f = File("root://localhost:1094//tmp/v5_testfile")
    @test f isa File

    @testset "readv" begin
        st, chunks = readv(f, [(0, 100), (5000, 256), (19000, 1000)])
        @test isOK(st)
        @test length(chunks) == 3
        @test chunks[1] == data[1:100]
        @test chunks[2] == data[5001:5256]
        @test chunks[3] == data[19001:20000]
    end

    @testset "pgread equals plain read" begin
        st, viapg = pgread(f, length(data), 0)
        @test isOK(st)
        @test viapg == data
        st, plain = read(f, length(data), 0)
        @test isOK(st)
        @test viapg == plain
    end

    close(f)

    @testset "pgwrite round trip" begin
        f = File()
        st, _ = open(
            f, "root://localhost:1094//tmp/v5_out", OpenFlags.Write | OpenFlags.Delete
        )
        @test isOK(st)
        st, _ = pgwrite(f, data, 0)
        @test isOK(st)
        st, _ = sync(f)
        @test isOK(st)
        close(f)
        @test read("/tmp/v5_out") == data     # the server exports local /tmp
    end

    @testset "writev round trip" begin
        f = File()
        st, _ = open(
            f, "root://localhost:1094//tmp/v5_out2", OpenFlags.Write | OpenFlags.Delete
        )
        @test isOK(st)
        st, _ = writev(f, [(0, data[1:1000]), (1000, data[1001:2000])]; do_sync=true)
        @test isOK(st)
        close(f)
        @test read("/tmp/v5_out2") == data[1:2000]
    end

    foreach(rm, ("/tmp/v5_testfile", "/tmp/v5_out", "/tmp/v5_out2"))
end
