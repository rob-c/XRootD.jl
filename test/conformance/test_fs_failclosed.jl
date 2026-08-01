# Fail-closed conformance for the namespace surface: a server that answers a
# path operation with a body the protocol does not allow, refuses it, stalls
# it, or drops the link mid-reply must never be reported as a success. Each
# case drives the strict server from conformance/fs_server.jl into one
# specific misbehaviour and asserts the client fails with a diagnosable
# status — and, for the resilience cases, that it retries exactly as often as
# the at-most-once contract allows.

using XRootD.XrdCl
using XRootD.XrdCl: dirlist_stat, checksum, prepare
using XRootD.XrdCl: symlink, hardlink, readlink

"A namespace body the client must reject rather than half-believe."
fsc_bytes(s::AbstractString) = Vector{UInt8}(codeunits(s))

@testset "conformance: fail-closed on the namespace surface" begin
    srv, port = start_conf_fs(["/data/a.txt" => "hello", "/data/b.bin" => "bb", "/empty/"])
    fs = conf_fs(port)

    @testset "a malformed listing is an error, not a partial listing" begin
        fsc_reset!(srv)
        # A dstat listing whose last entry has no stat line: the pairing is the
        # only thing that says which line is a name.
        srv.body_for = Wire.kXR_dirlist
        srv.body_next = fsc_bytes(".\n0 0 0 0\na.txt\n5 5 48 1700000000\nb.bin\n")
        st, names, stats = dirlist_stat(fs, "/data")
        @test isError(st) && names === nothing && stats === nothing
        @test occursin("malformed", st.message)

        srv.body_for = Wire.kXR_dirlist
        srv.body_next = fsc_bytes(".\n0 0 0 0\na.txt\nnot a stat line\n")
        st, names = readdir(fs, "/data", DirListFlags.Stat)
        @test isError(st) && names === nothing
        @test occursin("malformed", st.message)

        st, names = readdir(fs, "/data")                 # the link is still usable
        @test isOK(st) && names == ["a.txt", "b.bin"]
        @test isempty(srv.violations)
    end

    @testset "a truncated stat line is an error, not a zero-sized file" begin
        fsc_reset!(srv)
        srv.body_for = Wire.kXR_stat
        srv.body_next = fsc_bytes("1 2")                 # four fields are the minimum
        st, si = stat(fs, "/data/a.txt")
        @test isError(st) && si === nothing
        @test occursin("malformed", st.message)

        srv.body_for = Wire.kXR_stat
        srv.body_next = fsc_bytes("5 not-a-number 48 1700000000")
        st, si = stat(fs, "/data/a.txt")
        @test isError(st) && si === nothing

        st, si = stat(fs, "/data/a.txt")
        @test isOK(st) && si.size == 5
        @test isempty(srv.violations)
    end

    @testset "malformed bodies on the other decoded replies" begin
        fsc_reset!(srv)
        srv.body_for = Wire.kXR_open
        srv.body_next = UInt8[0x01]                      # no room for a file handle
        st, _ = open(File(), "root://127.0.0.1:$port//data/a.txt", OpenFlags.Read)
        @test isError(st) && occursin("malformed", st.message)

        srv.body_for = Wire.kXR_locate
        srv.body_next = fsc_bytes("XY")                  # a token with no address
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isError(st) && locs === nothing && occursin("malformed", st.message)

        srv.body_for = Wire.kXR_protocol
        srv.body_next = UInt8[0x00, 0x00, 0x05, 0x20]    # only half the reply
        st, p = protocol(fs)
        @test isError(st) && p === nothing && occursin("malformed", st.message)

        srv.body_for = Wire.kXR_fattr
        srv.body_next = UInt8[0x00, 0x00, 0x00, 0x00]    # claims no attribute at all
        st, value = getxattr(fs, "/data/a.txt", "user.one")
        @test isError(st) && value === nothing && occursin("malformed", st.message)
        @test isempty(srv.violations)
    end

    @testset "every namespace operation surfaces the server's error" begin
        cases = [
            (Wire.kXR_ping, () -> ping(fs)),
            (Wire.kXR_stat, () -> stat(fs, "/data/a.txt")),
            (Wire.kXR_dirlist, () -> readdir(fs, "/data")),
            (Wire.kXR_mkdir, () -> mkdir(fs, "/fail")),
            (Wire.kXR_mv, () -> mv(fs, "/data/a.txt", "/data/z.txt")),
            (Wire.kXR_chmod, () -> chmod(fs, "/data/a.txt", 0o600)),
            (Wire.kXR_rm, () -> rm(fs, "/data/a.txt")),
            (Wire.kXR_rmdir, () -> rmdir(fs, "/empty")),
            (Wire.kXR_truncate, () -> truncate(fs, "/data/a.txt", Int64(0))),
            (Wire.kXR_query, () -> checksum(fs, "/data/a.txt")),
            (Wire.kXR_locate, () -> locate(fs, "/data/a.txt", 0)),
            (Wire.kXR_fattr, () -> listxattr(fs, "/data/a.txt")),
            (Wire.kXR_prepare, () -> prepare(fs, ["/data/a.txt"])),
            (Wire.kXR_symlink, () -> symlink(fs, "/data/a.txt", "/fail.link")),
            (Wire.kXR_readlink, () -> readlink(fs, "/data/a.txt")),
            (Wire.kXR_link, () -> hardlink(fs, "/data/a.txt", "/fail.hard")),
        ]
        for (rid, call) in cases
            fsc_reset!(srv)
            srv.fail_next = rid
            st, result = call()
            @test isError(st)
            @test st.code == FSC_IOError
            @test result === nothing
            @test fsc_op_count(srv, rid) == 1            # a server error is not retried
        end
        # None of the refused mutations touched the namespace.
        @test sort!(collect(keys(srv.nodes))) ==
            ["/", "/data", "/data/a.txt", "/data/b.bin", "/empty"]
        @test isempty(srv.violations)
    end

    @testset "kXR_wait is honoured by re-sending the same request" begin
        fsc_reset!(srv)
        srv.wait_next = Wire.kXR_stat
        st, si = stat(fs, "/data/a.txt")
        @test isOK(st) && si.size == 5
        @test fsc_op_count(srv, Wire.kXR_stat) == 2      # the wait, then the answer
        @test isempty(srv.violations)
    end

    @testset "a frame addressed to no one is dropped, not mistaken for a reply" begin
        fsc_reset!(srv)
        srv.junk = true
        st, si = stat(fs, "/data/a.txt")
        @test isOK(st) && si.size == 5
        st, names = readdir(fs, "/data")
        @test isOK(st) && names == ["a.txt", "b.bin"]
        @test isempty(srv.violations)
    end

    @testset "a reply shorter than its own dlen is refused" begin
        fsc_reset!(srv)
        withenv("XRDC_MAX_STALL_MS" => "0") do        # no reconnect-and-replay window
            srv.cut_next = Wire.kXR_stat
            st, si = stat(fs, "/data/a.txt")
            @test isError(st) && si === nothing
            @test fsc_op_count(srv, Wire.kXR_stat) == 1
        end
        st, si = stat(fs, "/data/a.txt")                 # the next call reconnects
        @test isOK(st) && si.size == 5
        @test isempty(srv.violations)
    end

    @testset "an idempotent request is replayed across a lost link" begin
        fsc_reset!(srv)
        srv.cut_next = Wire.kXR_dirlist                  # link dies behind a short body
        st, names = readdir(fs, "/data")
        @test isOK(st) && names == ["a.txt", "b.bin"]
        @test fsc_op_count(srv, Wire.kXR_dirlist) == 2   # once lost, once replayed
        @test isempty(srv.violations)
    end

    @testset "a mutation is never replayed: at most once, not at least once" begin
        fsc_reset!(srv)
        # The server applies the removal and then drops the link before the
        # reply lands, the one case where a retry would delete a second file.
        srv.cut_next = Wire.kXR_rm
        st, _ = rm(fs, "/data/b.bin")
        @test isError(st)
        @test fsc_op_count(srv, Wire.kXR_rm) == 1        # not replayed
        @test !haskey(srv.nodes, "/data/b.bin")          # ... though it did happen
        @test isempty(srv.violations)
    end
end
