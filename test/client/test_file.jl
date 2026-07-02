# File API over the mock server from test/session/test_connection.jl
# (start_mock_server + MOCK_CONTENT are defined there and shared via Main).

using XRootD.XrdCl
using XRootD.XrdCl: sync, pgread

@testset "File over mock server" begin
    port = start_mock_server()
    base = "root://127.0.0.1:$port"

    @testset "open failure returns nothing" begin
        @test File("$base//nonexisting") === nothing
    end

    @testset "open + stat" begin
        f = File("$base//data")
        @test f isa File
        @test isopen(f)
        st, si = stat(f)
        @test isOK(st)
        @test si.size == length(MOCK_CONTENT)
        close(f)
        @test !isopen(f)
    end

    @testset "read semantics (0.2.x cursor rules)" begin
        f = File("$base//data")
        st, buf = read(f, length(MOCK_CONTENT))
        @test isOK(st)
        @test buf == MOCK_CONTENT
        # reading again without an offset re-reads from the unmoved cursor
        st, buf = read(f, length(MOCK_CONTENT) + 100)
        @test isOK(st)
        @test length(buf) == length(MOCK_CONTENT)
        # explicit offset positions the cursor
        st, buf = read(f, 5, 6)
        @test isOK(st)
        @test String(buf) == "World"
        # reading past EOF yields empty
        st, buf = read(f, 10, 100)
        @test isOK(st)
        @test isempty(buf)
        close(f)
    end

    @testset "readline / readlines / eof" begin
        f = File("$base//data")
        st, l1 = readline(f)
        @test isOK(st) && l1 == "Hello\n"
        st, l2 = readline(f)
        @test isOK(st) && l2 == "World\n"
        st, l3 = readline(f)
        @test isOK(st) && l3 == "Folks!"
        st, l4 = readline(f)
        @test isOK(st) && isempty(l4)
        @test eof(f)
        close(f)

        f = File()
        st, _ = open(f, "$base//data", OpenFlags.Read)
        @test isOK(st)
        st, lines = readlines(f)
        @test isOK(st)
        @test lines == ["Hello\n", "World\n", "Folks!"]
        close(f)
    end

    @testset "write / truncate / sync" begin
        f = File("$base//data", OpenFlags.Update)
        st, _ = write(f, "payload")
        @test isOK(st)
        st, _ = truncate(f, 4)
        @test isOK(st)
        st, _ = sync(f)
        @test isOK(st)
        close(f)
    end

    @testset "pgread" begin
        f = File("$base//data")
        st, data = pgread(f, 10, 0)
        @test isOK(st)
        @test String(data) == "HelloWorld"
        close(f)
    end

    @testset "operations on a closed file fail cleanly" begin
        f = File()
        st, _ = read(f, 10)
        @test isError(st)
        st, _ = sync(f)
        @test isError(st)
    end
end
