# The open-handle operations the reference clients carry and 0.2.x did not:
# what the server will say about a handle (`kXR_Qvisa`, the per-file
# checksum, the compression descriptor), extended attributes addressed by
# handle rather than by path, the size-verified close, checkpointed writes,
# and getting a handle back after the connection under it died.

using XRootD.XrdCl
using XRootD: Wire

@testset "conformance: the open handle beyond 0.2.x" begin
    srv, port = start_conf_fs(["/h/data.bin" => "0123456789", "/h/ckp.bin" => "AAAA"])
    furl(path) = "root://127.0.0.1:$port/$path"

    @testset "visa asks about the handle, not the path" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/data.bin")
        @test f isa File

        st, answer = visa(f)
        @test isOK(st) && occursin("/h/data.bin", answer)
        # The handle form names no path, so the request carried none.
        @test !any(==("/h/data.bin"), srv.paths[2:end])
        close(f)
        @test isempty(srv.violations)
    end

    @testset "checksum by handle names its algorithm" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/data.bin")
        st, cks = checksum(f)
        @test isOK(st) && startswith(cks, "adler32 ")

        st, cks = checksum(f; algorithm="md5")
        @test isOK(st) && startswith(cks, "md5 ")
        @test srv.opaque[end] == "cks.type=md5"
        close(f)
        @test isempty(srv.violations)
    end

    @testset "the compression descriptor comes back from the open" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/data.bin")
        @test compression(f) == 0
        close(f)

        f = fs_file(port, "/h/data.bin", OpenFlags.Read | OpenFlags.Compress)
        @test f isa File
        @test compression(f) == FSC_CPSIZE
        close(f)
        @test isempty(srv.violations)
    end

    @testset "kXR_retstat spares the open its second round trip" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/data.bin", OpenFlags.Read | OpenFlags.RetStat)
        @test f isa File
        @test f.filesize == 10 && !eof(f)
        # The stat line rode in on the open reply, so no kXR_stat followed it.
        @test fsc_op_count(srv, Wire.kXR_stat) == 0
        close(f)
        @test isempty(srv.violations)
    end

    @testset "extended attributes addressed by handle" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/data.bin", OpenFlags.Update)
        @test f isa File

        st, _ = setxattr(f, "user.tag", Vector{UInt8}("alpha"))
        @test isOK(st) &&
            srv.nodes["/h/data.bin"].xattr["user.tag"] == Vector{UInt8}("alpha")

        st, value = getxattr(f, "user.tag")
        @test isOK(st) && value == Vector{UInt8}("alpha")

        st, names = listxattr(f)
        @test isOK(st) && names == ["user.tag"]

        st, _ = getxattr(f, "user.missing")
        @test isError(st) && st.code == ErrorCode.AttrNotFound

        st, _ = removexattr(f, "user.tag")
        @test isOK(st) && isempty(srv.nodes["/h/data.bin"].xattr)
        close(f)
        @test isempty(srv.violations)
    end

    @testset "a size-verified close is all-or-nothing" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/verify.bin", OpenFlags.Update | OpenFlags.New)
        @test f isa File
        @test isOK(write(f, "12345")[1])
        st, _ = close(f; fsize=5)
        @test isOK(st)
        @test srv.nodes["/h/verify.bin"].data == Vector{UInt8}("12345")

        # A file that came out the wrong length is rejected AND removed: the
        # writer said "this size or nothing".
        f = fs_file(port, "/h/partial.bin", OpenFlags.Update | OpenFlags.New)
        @test isOK(write(f, "123")[1])
        st, _ = close(f; fsize=99)
        @test isError(st)
        @test !haskey(srv.nodes, "/h/partial.bin")
        @test !isopen(f)                      # released either way
        @test isempty(srv.violations)
    end

    @testset "checkpoints commit and roll back" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/ckp.bin", OpenFlags.Update)
        @test f isa File

        st, cap = checkpoint_query(f)
        @test isOK(st) && cap.capacity == FSC_CKP_CAPACITY && cap.used == 0

        st, _ = checkpoint_begin(f)
        @test isOK(st)
        st, cap = checkpoint_query(f)
        @test isOK(st) && cap.used == 4                    # the snapshot it holds

        st, _ = checkpoint_write(f, Vector{UInt8}("ZZ"), 0)
        @test isOK(st) && srv.nodes["/h/ckp.bin"].data == Vector{UInt8}("ZZAA")

        st, _ = checkpoint_rollback(f)
        @test isOK(st) && srv.nodes["/h/ckp.bin"].data == Vector{UInt8}("AAAA")

        # A second checkpoint: committed this time, and it also survives a
        # truncate, which is the other operation the server knows how to undo.
        @test isOK(checkpoint_begin(f)[1])
        @test isOK(checkpoint_write(f, Vector{UInt8}("BB"), 0)[1])
        @test isOK(checkpoint_truncate(f, 3)[1])
        @test isOK(checkpoint_commit(f)[1])
        @test srv.nodes["/h/ckp.bin"].data == Vector{UInt8}("BBA")

        # Committing with no checkpoint open is the server's refusal, not a
        # local no-op.
        st, _ = checkpoint_commit(f)
        @test isError(st)
        close(f)
        @test isempty(srv.violations)
    end

    @testset "the checkpoint block form commits, and rolls back on a throw" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/block.bin", OpenFlags.Update | OpenFlags.New)
        @test isOK(write(f, "keep")[1])

        st, result = checkpoint(f) do
            checkpoint_write(f, Vector{UInt8}("GONE"), 0)
            :done
        end
        @test isOK(st) && result == :done
        @test srv.nodes["/h/block.bin"].data == Vector{UInt8}("GONE")

        @test_throws ErrorException checkpoint(f) do
            checkpoint_write(f, Vector{UInt8}("XXXX"), 0)
            error("the caller changed its mind")
        end
        @test srv.nodes["/h/block.bin"].data == Vector{UInt8}("GONE")
        close(f)
        @test isempty(srv.violations)
    end

    @testset "checkpoint_exec refuses what the server cannot undo" begin
        @test_throws ArgumentError Wire.checkpoint_exec(
            (0x01, 0x02, 0x03, 0x04), Wire.SyncRequest((0x01, 0x02, 0x03, 0x04))
        )
    end

    @testset "clone copies ranges without them crossing the client" begin
        fsc_reset!(srv)
        dst = fs_file(port, "/h/cloned.bin", OpenFlags.Update | OpenFlags.New)
        @test dst isa File
        # A file handle is only good on the connection that issued it, so the
        # source is opened on the destination's session rather than its own.
        src = File()
        st, _ = open(src, furl("/h/data.bin"), OpenFlags.Read; conn=dst.conn)
        @test isOK(st) && src.conn === dst.conn

        st, _ = clone(dst, src, [(0, 4, 0), (6, 4, 4)])
        @test isOK(st)
        @test srv.nodes["/h/cloned.bin"].data == Vector{UInt8}("01236789")
        # The bytes never reached this client: no read, no write, one request.
        @test fsc_op_count(srv, Wire.kXR_read) == 0
        @test fsc_op_count(srv, Wire.kXR_write) == 0
        @test fsc_op_count(srv, Wire.kXR_clone) == 1

        # A range past the destination's end extends it, and a zero-length
        # range is skipped rather than refused.
        st, _ = clone(dst, src, [(0, 0, 99), (0, 2, 10)])
        @test isOK(st)
        @test srv.nodes["/h/cloned.bin"].data ==
            vcat(Vector{UInt8}("01236789"), zeros(UInt8, 2), Vector{UInt8}("01"))

        # Reading past the end of the source is the server's error, and it
        # says so about the source rather than failing the whole handle.
        st, _ = clone(dst, src, [(0, 1 << 20, 0)])
        @test isError(st) && st.code == FSC_IOError
        @test isopen(dst) && isopen(src)

        # Closing the borrowed handle leaves the session to the file that
        # dialed it, and the destination still works on it afterwards.
        @test isOK(close(src)[1])
        @test isopen(dst.conn.sock)
        @test isOK(sync(dst)[1])
        @test isOK(close(dst)[1])
        @test isempty(srv.violations)
    end

    @testset "clone refuses what the protocol cannot express" begin
        fsc_reset!(srv)
        dst = fs_file(port, "/h/clone2.bin", OpenFlags.Update | OpenFlags.New)
        @test dst isa File
        # Two files that each dialed their own session hold handles that mean
        # nothing to each other, and the refusal is local: nothing is sent.
        elsewhere = fs_file(port, "/h/data.bin")
        st, _ = clone(dst, elsewhere, [(0, 1, 0)])
        @test isError(st) && occursin("different connections", st.message)
        @test fsc_op_count(srv, Wire.kXR_clone) == 0
        close(elsewhere)

        src = File()
        @test isOK(open(src, furl("/h/data.bin"), OpenFlags.Read; conn=dst.conn)[1])
        # An empty range list is a request the server would answer
        # kXR_ArgMissing; the wire codec refuses to build it at all.
        st, _ = clone(dst, src, Tuple{Int,Int,Int}[])
        @test isError(st) && occursin("bad item count", st.message)
        st, _ = clone(dst, src, [(-1, 1, 0)])
        @test isError(st) && occursin("negative offset", st.message)
        @test fsc_op_count(srv, Wire.kXR_clone) == 0

        # A closed handle on either side is not a request either.
        close(src)
        st, _ = clone(dst, src, [(0, 1, 0)])
        @test isError(st) && occursin("not open", st.message)
        close(dst)
        @test isempty(srv.violations)
    end

    @testset "a read-only handle survives losing its connection" begin
        fsc_reset!(srv)
        f = fs_file(port, "/h/data.bin", OpenFlags.Read)
        @test f isa File
        @test recoverable(f)
        first_handle = f.fhandle

        # The server announces a body it then declines to send in full and
        # hangs up: the read has to come back from a reopened handle, not
        # from the one the dead connection held.
        srv.cut_next = Wire.kXR_read
        st, data = read(f, 4, 0)
        @test isOK(st) && String(copy(data)) == "0123"
        @test f.fhandle != first_handle
        @test fsc_op_count(srv, Wire.kXR_open) == 2
        close(f)

        # A handle opened for writing is not recoverable — reopening it would
        # discard whatever the writer had already put there.
        f = fs_file(port, "/h/data.bin", OpenFlags.Update)
        @test !recoverable(f)
        st = reopen!(f)
        @test isError(st) && occursin("not recoverable", st.message)
        close(f)
    end

    close(fs_file(port, "/h/data.bin"))
end
