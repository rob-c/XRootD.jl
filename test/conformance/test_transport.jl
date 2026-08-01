# TCP delivers bytes, not frames. A reply may arrive in one read, in a hundred,
# or split anywhere at all — inside the 8-byte header, between the header and
# the body, or part-way through a paged trailer that lives outside `dlen`.
#
# Every whole-frame test in this suite passes on a client that assumes one read
# per frame; a slow or busy link is where that client stops working. These tests
# hand the same replies over one byte at a time, and in pieces that land on the
# awkward boundaries on purpose.

using CRC32c: crc32c
using XRootD.XrdCl
using XRootD: Wire

"A `kXR_status` pgread reply for `data` at `offset`, framed the way a server sends it."
function tr_pgread_frame(sid::UInt16, offset::Integer, data::Vector{UInt8})
    return cs_status(
        sid, Wire.kXR_pgread, Wire.kXR_FinalResult, offset, cs_page_units(data, offset)
    )
end

@testset "conformance: replies that arrive in pieces" begin
    srv, port = start_info_server()
    fs = info_fs(port)

    @testset "a reply delivered one byte at a time still parses" begin
        for n in (1, 2, 3, 5, 7, 8, 9)      # 8 lands exactly on the header boundary
            info_reset!(srv)
            srv.fragment = n
            info_reply!(srv, "v5.2.0")
            st, text = query(fs, QueryCode.Config, "version")
            @test isOK(st) && text == "v5.2.0"
            @test isempty(srv.violations)
        end
    end

    @testset "the split may land inside the header as easily as the body" begin
        # dlen is bytes 5..8 of the header: a 5-byte fragment cuts it in half,
        # so a client that reads the length before it has arrived reads junk.
        info_reset!(srv)
        srv.fragment = 5
        info_error!(srv, 3011, "no such file or directory")
        st, si = stat(fs, "/p")
        @test isError(st) && st.code == 3011
        @test st.message == "no such file or directory"
        @test si === nothing
    end

    @testset "a long body arrives in as many pieces as the link gives it" begin
        info_reset!(srv)
        srv.fragment = 13
        text = join(("line $i" for i in 1:400), "\n")
        info_reply!(srv, text)
        st, got = query(fs, QueryCode.Config, "bigreply")
        @test isOK(st) && got == text
        @test isempty(srv.violations)
    end

    @testset "a deferred reply is reassembled too, envelope and all" begin
        # The attn envelope is a frame around a frame: fragmenting it splits
        # the inner header as well as the outer one.
        info_reset!(srv)
        srv.async = true
        srv.fragment = 3
        info_reply!(srv, "deferred and dribbled")
        st, text = query(fs, QueryCode.Config, "version")
        @test isOK(st) && text == "deferred and dribbled"
        @test srv.ops == [Wire.kXR_query]
        @test isempty(srv.violations)
    end

    @testset "a paged reply's trailer is outside dlen and still gets read" begin
        # kXR_status announces `pgdlen` bytes of page units AFTER the framed
        # body; the reader has to go back to the socket for them, which is
        # exactly where a fragmented delivery hurts.
        data = UInt8[(7 * i + 3) % 256 for i in 1:9000]
        for n in (0, 1, 11, 4096)
            info_reset!(srv)
            srv.fragment = n
            srv.body = collect(CONF_FHANDLE)
            f = File()
            st, _ = open(f, "root://127.0.0.1:$port//p")
            @test isOK(st)

            # From here on every reply is the scripted pgread frame, addressed
            # to whichever stream the request came in on.
            srv.scripted = sid -> tr_pgread_frame(sid, 0, data)
            st, got = pgread(f, length(data), 0)
            @test isOK(st)
            @test got == data

            srv.scripted = nothing
            srv.fragment = 0
            srv.body = UInt8[]
            close(f)
            @test isempty(srv.violations)
        end
    end

    @testset "a page whose checksum does not match is refused, however it arrives" begin
        data = UInt8[(11 * i + 5) % 256 for i in 1:5000]
        for n in (0, 1, 17)
            info_reset!(srv)
            srv.body = collect(CONF_FHANDLE)
            f = File()
            st, _ = open(f, "root://127.0.0.1:$port//p")
            @test isOK(st)

            srv.scripted = function (sid)
                frame = tr_pgread_frame(sid, 0, data)
                frame[end] ⊻= 0xff                     # flip a bit in the last page
                return frame
            end
            srv.fragment = n
            st, got = pgread(f, length(data), 0)
            @test isError(st)
            @test occursin("pgread integrity failure", st.message)
            @test got === nothing                      # never the bytes that arrived

            srv.scripted = nothing
            srv.fragment = 0
            srv.body = UInt8[]
            close(f)
        end
    end
end
