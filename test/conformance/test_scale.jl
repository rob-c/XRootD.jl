# Scale conformance: the same strict server from conformance/server.jl, driven
# over the ranges where an off-by-one hides — every 4 KiB page boundary, the
# segment caps, a megabyte in one frame — and with many requests in flight at
# once, which is the property the Session multiplexer exists to provide.

using XRootD: Session, Wire
using XRootD.XrdCl
using XRootD.XrdCl: readv, writev, pgread, pgwrite

"Read `len` bytes at `offset`, bypassing the cursor entirely."
function conf_pread(f, offset::Integer, len::Integer)
    buf = zeros(UInt8, max(len, 1))
    st, n = GC.@preserve buf unsafe_read(f, pointer(buf), len, offset)
    return st, buf[1:n]
end

"What the file holds for `[offset, offset+len)`, clipped at EOF."
function conf_slice(offset::Integer, len::Integer)
    lo, hi = offset + 1, min(offset + len, length(CONF_CONTENT))
    return lo <= hi ? CONF_CONTENT[lo:hi] : UInt8[]
end

# offsets: page-aligned, either side of a boundary, at EOF and past it
const SCALE_OFFSETS = [0, 1, 4095, 4096, 4097, 8191, 9999, 10_000, 10_001]
const SCALE_LENGTHS = [0, 1, 7, 4096, 5000, 10_000]

@testset "conformance: sweeps and scale" begin
    srv, port = start_conf_server(CONF_CONTENT)

    @testset "kXR_read: an offset x length sweep over the page grid" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        for offset in SCALE_OFFSETS, len in SCALE_LENGTHS
            st, got = conf_pread(f, offset, len)
            @test isOK(st)
            @test got == conf_slice(offset, len)
        end
        close(f)
        @test isempty(srv.violations)
    end

    @testset "kXR_pgread: the same sweep, CRC-verified page units" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        for offset in SCALE_OFFSETS, len in SCALE_LENGTHS
            st, got = pgread(f, len, offset)
            @test isOK(st)
            @test got == conf_slice(offset, len)
        end
        close(f)
        @test isempty(srv.violations)
    end

    @testset "kXR_pgwrite: every alignment lands byte-exact" begin
        wsrv, wport = start_conf_server()
        f = conf_file(wport)
        # Bases are multiples of 4 KiB so each case keeps its offset's phase
        # within the page grid, and far enough apart that they cannot overlap.
        for (i, (offset, len)) in
            enumerate(Iterators.product([0, 1, 4095, 4096, 4097, 8191], [1, 7, 4095, 4096, 4097, 9000]))
            base = (i - 1) * 131_072 + offset
            payload = CONF_CONTENT[1:len]
            st, _ = pgwrite(f, payload, base)
            @test isOK(st)
            @test wsrv.data[(base + 1):(base + len)] == payload
        end
        close(f)
        @test isempty(wsrv.violations)          # every CRC32c checked server-side
    end

    @testset "kXR_readv: 1 to VEC_MAXSEGS segments" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        for nseg in [1, 2, 16, 256, Wire.VEC_MAXSEGS]
            chunks = [((i - 1) * 8, 8) for i in 1:nseg]
            st, got = readv(f, chunks)
            @test isOK(st)
            @test length(got) == nseg
            @test all(got[i] == conf_slice(chunks[i]...) for i in 1:nseg)
        end
        close(f)
        @test isempty(srv.violations)
    end

    @testset "kXR_writev: 1 to VEC_MAXSEGS segments" begin
        wsrv, wport = start_conf_server()
        f = conf_file(wport)
        for nseg in [1, 2, 16, 256, Wire.VEC_MAXSEGS]
            segs = [(Int64((i - 1) * 32), UInt8[(nseg + i) % 256 for _ in 1:16]) for i in 1:nseg]
            st, _ = writev(f, segs)
            @test isOK(st)
            @test all(wsrv.data[(s[1] + 1):(s[1] + 16)] == s[2] for s in segs)
        end
        close(f)
        @test isempty(wsrv.violations)
    end

    @testset "a megabyte survives the round trip in one frame" begin
        wsrv, wport = start_conf_server()
        f = conf_file(wport)
        payload = UInt8[(11 * i + 3) % 256 for i in 1:(1024 * 1024)]

        st, _ = write(f, payload, length(payload), 0)
        @test isOK(st)
        @test wsrv.data == payload

        st, got = conf_pread(f, 0, length(payload))
        @test isOK(st) && got == payload

        st, _ = pgwrite(f, payload[1:262_144], 0)   # 64 pages of paged write
        @test isOK(st)
        @test wsrv.data[1:262_144] == payload[1:262_144]

        st, got = pgread(f, 262_144, 0)             # 64 status frames back
        @test isOK(st) && got == payload[1:262_144]

        close(f)
        @test isempty(wsrv.violations)
    end

    @testset "many requests are in flight over one connection at once" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        conn = f.conn
        n = 24
        got = Vector{Any}(undef, n)
        @sync for i in 1:n
            @async begin
                off = (i - 1) * 337
                req = Wire.ReadRequest(f.fhandle, Int64(off), Int32(128))
                hdr, body = Session.roundtrip(conn, req; maxbytes=128)
                got[i] = (hdr.status, body)
            end
        end
        for i in 1:n
            @test got[i][1] == Wire.kXR_ok
            @test got[i][2] == conf_slice((i - 1) * 337, 128)
        end
        close(f)
        @test isempty(srv.violations)
    end

    @testset "concurrent replies of different shapes demultiplex" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        plain, paged, vector = Ref{Any}(), Ref{Any}(), Ref{Any}()
        @sync begin
            # kXR_ok, multi-frame kXR_status and a segmented body, interleaved
            @async plain[] = conf_pread(f, 512, 1024)
            @async paged[] = pgread(f, 9000, 100)
            @async vector[] = readv(f, [(0, 64), (4096, 64), (8192, 64)])
        end
        @test isOK(plain[][1]) && plain[][2] == conf_slice(512, 1024)
        @test isOK(paged[][1]) && paged[][2] == conf_slice(100, 9000)
        @test isOK(vector[][1])
        @test vector[][2] == [conf_slice(0, 64), conf_slice(4096, 64), conf_slice(8192, 64)]
        close(f)
        @test isempty(srv.violations)
    end

    @testset "a long run of operations leaks no streamid" begin
        conf_reset!(srv)
        f = conf_file(port, OpenFlags.Read)
        conn = f.conn
        mismatched = 0
        for i in 1:300
            offset = (7 * i) % 9000
            st, got = conf_pread(f, offset, 64)
            (isOK(st) && got == conf_slice(offset, 64)) || (mismatched += 1)
        end
        @test mismatched == 0
        @test isempty(conn.pending)             # every streamid was handed back
        close(f)
        @test isempty(srv.violations)
    end
end
