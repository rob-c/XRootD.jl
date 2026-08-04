# Storage streams over root:// against the real XRootD_jll server. The generic
# handles are covered against HTTP in test/storage/test_stream.jl; what is
# specific here is that the xroot lane holds one `kXR_open` handle open for the
# whole stream and addresses it by offset in both directions.

using XRootD.Storage
using XRootD.Storage:
    storage_open, storage_for, storage_stat, StorageReader, StorageWriter, XRootDStream

@testset "storage streams over root://" begin
    base = "root://localhost:1094"
    data = rand(UInt8, 5 << 20)
    url = "$base//tmp/stream_obj.bin"

    @testset "write, then read it back" begin
        storage_open(url, "w") do io
            @test io isa StorageWriter{XRootDStream}
            @test write(io, data) == length(data)
            @test position(io) == length(data)
        end
        @test read("/tmp/stream_obj.bin") == data

        code, info = storage_stat(storage_for(url))
        @test code == :ok && info.size == length(data)

        storage_open(url) do io
            @test io isa StorageReader{XRootDStream}
            @test !eof(io)
            @test read(io, 16) == data[1:16]
            seek(io, 4 << 20)
            @test read(io, 32) == data[((4 << 20) + 1):((4 << 20) + 32)]
            seekend(io)
            @test eof(io)
            seekstart(io)
            @test read(io) == data
        end
    end

    @testset "one handle serves the whole stream" begin
        storage_open(url) do io
            total = 0
            buf = Vector{UInt8}(undef, 64 * 1024)
            while !eof(io)
                total += readbytes!(io, buf, length(buf))
            end
            @test total == length(data)
        end
    end

    @testset "a writer can go back over what it wrote" begin
        seekable = "$base//tmp/stream_seek.bin"
        storage_open(seekable, "w") do io
            write(io, fill(UInt8('a'), 1000))
            flush(io)
            seek(io, 100)
            write(io, fill(UInt8('b'), 10))
        end
        got = storage_open(read, seekable)
        @test length(got) == 1000
        @test all(==(UInt8('b')), got[101:110])
        @test got[100] == UInt8('a') && got[111] == UInt8('a')
    end

    @testset "an object that is not there fails at open" begin
        @test_throws StorageError storage_open("$base//tmp/stream_absent_xyz.bin")
    end

    foreach(
        p -> isfile(p) && rm(p),
        ("/tmp/stream_obj.bin", "/tmp/stream_seek.bin"),
    )
end
