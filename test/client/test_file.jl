# File API over the mock server from test/session/test_connection.jl
# (start_mock_server + MOCK_CONTENT are defined there and shared via Main).

using CRC32c: crc32c
using XRootD: Wire
using XRootD.XrdCl
using XRootD.XrdCl: sync, pgread, pgwrite, readv, writev

"""
A `kXR_pgwrite` reply that is malformed in exactly one way:

* `:short_status` — a `kXR_status` frame whose body is too short to decode;
* `:bad_cse_len` — a checksum-error trailer whose length is not a whole
  number of page offsets;
* `:outside_offset` — a trailer naming a page the request never wrote;
* `:promised_trailer` — a deferred (`kXR_attn`) reply announcing `pgdlen`
  bytes of trailer and sending none. Only the deferred form can do this: the
  reader appends exactly `pgdlen` bytes to an in-line `kXR_status` frame.
"""
function broken_pgwrite_reply(sid::UInt16, mode::Symbol)
    mode === :short_status &&
        return vcat(resp_hdr(sid, Wire.kXR_status, 4), zeros(UInt8, 4))
    mode === :bad_cse_len &&
        return status_frame(sid, Wire.kXR_FinalResult, 0, ones(UInt8, 9))
    mode === :outside_offset &&
        return status_frame(sid, Wire.kXR_FinalResult, 0, cse_trailer(1 << 20))

    sb = zeros(UInt8, 24)
    Wire.set_u16!(sb, 5, sid)
    sb[7] = 0x1f                          # requestid echo (pgwrite - 3000)
    sb[8] = Wire.kXR_FinalResult
    Wire.set_u32!(sb, 13, UInt32(16))     # promises a 16-byte trailer...
    Wire.set_u32!(sb, 1, crc32c(sb[5:24]))
    body = vcat(
        be32(Wire.kXR_asynresp), zeros(UInt8, 4), resp_hdr(sid, Wire.kXR_status, 24), sb
    )
    return vcat(resp_hdr(0x0000, Wire.kXR_attn, length(body)), body)   # ... and sends none
end

"A server whose paged-io and vector replies are malformed in `mode`."
function serve_broken_paged(sock, mode::Symbol)
    serve_bringup(sock)
    while isopen(sock)
        frame, _ = read_request(sock)
        sid, rid = req_sid(frame), req_id(frame)
        if rid == Wire.kXR_open
            write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, 4), UInt8[1, 1, 1, 1]))
        elseif rid == Wire.kXR_pgwrite
            write(sock, broken_pgwrite_reply(sid, mode))
        elseif rid == Wire.kXR_readv
            # not a whole 16-byte segment header, let alone its data
            write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, 5), UInt8[1, 2, 3, 4, 5]))
        else
            write(sock, resp_hdr(sid, Wire.kXR_ok, 0))
        end
    end
    return nothing
end

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
        # an overwrite inside the recorded size leaves it alone
        @test f.filesize == length(MOCK_CONTENT)
        st, _ = truncate(f, 4)
        @test isOK(st)
        # truncate re-declares the size outright
        @test f.filesize == 4
        st, _ = sync(f)
        @test isOK(st)
        close(f)
    end

    @testset "a write past the end moves eof with it" begin
        f = File("$base//data", OpenFlags.Update)
        st, _ = readlines(f)
        @test isOK(st)
        @test eof(f)
        # the handle itself appended, so its own eof answer must move — a
        # cursor at the old end is now mid-file, not at it
        st, _ = write(f, "tail", length(MOCK_CONTENT))
        @test isOK(st)
        @test !eof(f)
        @test f.filesize == length(MOCK_CONTENT) + 4
        close(f)
    end

    @testset "pgread" begin
        f = File("$base//data")
        st, data = pgread(f, 10, 0)
        @test isOK(st)
        @test String(data) == "HelloWorld"
        close(f)
    end

    @testset "pgwrite retries the pages the server reports corrupt" begin
        f = File("$base//data", OpenFlags.Update)
        data = Vector{UInt8}(codeunits("paged payload"))
        st, _ = pgwrite(f, data, 0)
        @test isOK(st)
        # the resend carried exactly the corrupt page, CRC32c and all
        @test PGWRITE_LAST[] == Wire.encode_pages(data, Int64(0))
        close(f)
    end

    @testset "pgwrite gives up on a page that stays corrupt" begin
        f = File("$base//data", OpenFlags.Update)
        st, _ = pgwrite(f, Vector{UInt8}(codeunits("doomed")), 8192)
        @test isError(st)
        @test occursin("still corrupt after $(Wire.PGW_MAX_RETRY) retries", st.message)
        close(f)
    end

    @testset "readv" begin
        f = File("$base//data")
        st, chunks = readv(f, [(0, 5), (6, 5)])
        @test isOK(st)
        @test String.(chunks) == ["Hello", "World"]
        # a reply missing a segment is a stopped transfer, not a short read
        st, chunks = readv(f, [(0, 5), (MOCK_DROP_OFFSET, 5)])
        @test isError(st)
        @test chunks === nothing
        @test occursin("1 of 2 segments", st.message)
        # local validation rejects an over-large vector before it hits the wire
        st, _ = readv(f, [(i, 1) for i in 0:(Wire.VEC_MAXSEGS)])
        @test isError(st)
        close(f)
    end

    @testset "writev validates the vector locally" begin
        # An empty vector is refused before it reaches the wire, like readv's
        # over-large one. (The wire form is checked in conformance/test_rw.jl,
        # against a server that parses it strictly.)
        f = File("$base//data", OpenFlags.Update)
        st, _ = writev(f, Tuple{Int,Vector{UInt8}}[])
        @test isError(st)
        @test occursin("bad segment count 0", st.message)
        close(f)
    end

    @testset "readline from an explicit offset" begin
        f = File("$base//data")
        st, line = readline(f, 0, 6)
        @test isOK(st) && line == "World\n"
        @test f.currentOffset == 12          # the cursor moved to the offset first
        close(f)
    end

    @testset "an open the client cannot even attempt" begin
        # Nothing is listening on port 1: the failure is local, and reported
        # as a status rather than thrown.
        f = File()
        st, _ = open(f, "root://127.0.0.1:1//data", OpenFlags.Read)
        @test isError(st)
        @test !isopen(f)

        # A mode that does not fit the wire field fails while the request is
        # being built, after the connection is up — which must still be closed.
        g = File()
        st, _ = open(g, "$base//data", OpenFlags.Read, 0x10000)
        @test isError(st)
        @test occursin("InexactError", st.message)
        @test !isopen(g)
    end

    @testset "replies to paged and vector io that do not parse" begin
        for (mode, expect) in (
            (:short_status, "kXR_status body"),
            (:bad_cse_len, "malformed pgwrite CSE trailer"),
            (:outside_offset, "outside the request"),
            (:promised_trailer, "truncated checksum-error trailer"),
        )
            server, bport = start_server(sock -> serve_broken_paged(sock, mode))
            try
                f = File("root://127.0.0.1:$bport//data", OpenFlags.Update)
                @test f isa File
                st, _ = pgwrite(f, Vector{UInt8}(codeunits("payload")), 0)
                @test isError(st)
                @test occursin(expect, st.message)
                close(f)
            finally
                close(server)
            end
        end

        # A readv reply that is not a whole segment header is a protocol
        # error, not a short read.
        server, bport = start_server(sock -> serve_broken_paged(sock, :short_status))
        try
            f = File("root://127.0.0.1:$bport//data")
            st, chunks = readv(f, [(0, 5)])
            @test isError(st)
            @test chunks === nothing
            @test occursin("truncated readv segment header", st.message)
            close(f)
        finally
            close(server)
        end
    end

    @testset "operations on a closed file fail cleanly" begin
        f = File()
        st, _ = read(f, 10)
        @test isError(st)
        st, _ = sync(f)
        @test isError(st)
    end
end
