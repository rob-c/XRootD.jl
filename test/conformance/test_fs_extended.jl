# The namespace operations the reference clients carry and 0.2.x did not:
# the path predicates every one of them builds out of stat, whole-tree
# creation and removal, the many-paths stat, per-file checksums by algorithm,
# the session and property requests, and the recursive locate a manager needs.
#
# Driven against the strict namespace server, so an operation is judged by
# what the server ends up holding and by the requests it saw — a `mkpath`
# that walks the path one component at a time is a different client from one
# that sets `kXR_mkdirpath`, even when both end with the directory there.

using XRootD.XrdCl
using XRootD: Wire

@testset "conformance: the namespace operations beyond 0.2.x" begin
    srv, port = start_conf_fs([
        "/x/a.txt" => "hello", "/x/sub/b.bin" => UInt8[0x00, 0x01], "/x/empty/"
    ])
    fs = conf_fs(port)

    @testset "path predicates answer from one stat" begin
        fsc_reset!(srv)
        @test ispath(fs, "/x/a.txt")
        @test !ispath(fs, "/x/nowhere")
        @test isfile(fs, "/x/a.txt") && !isdir(fs, "/x/a.txt")
        @test isdir(fs, "/x/sub") && !isfile(fs, "/x/sub")
        @test filesize(fs, "/x/a.txt") == 5
        @test filesize(fs, "/x/nowhere") == -1
        # A predicate is one request: the answer is in the stat, not in a
        # listing of the parent.
        @test all(==(Wire.kXR_stat), srv.ops)
        @test isempty(srv.violations)
    end

    @testset "ispath distinguishes absence from failure" begin
        fsc_reset!(srv)
        # kXR_NotFound is an answer; anything else is not one, and a client
        # that reported "no" for an unauthorized path would be lying.
        srv.fail_next = Wire.kXR_stat
        srv.fail_code = 3010                       # kXR_NotAuthorized
        @test_throws ErrorException ispath(fs, "/x/a.txt")
        @test isempty(srv.violations)
    end

    @testset "mkpath makes the whole path in one request" begin
        fsc_reset!(srv)
        st, _ = mkpath(fs, "/x/deep/deeper/deepest")
        @test isOK(st)
        @test srv.nodes["/x/deep"].dir && srv.nodes["/x/deep/deeper/deepest"].dir
        @test fsc_op_count(srv, Wire.kXR_mkdir) == 1

        # Already there is what mkpath asked for, so it is not a failure —
        # even though the server answers kXR_ItExists.
        st, _ = mkpath(fs, "/x/deep/deeper")
        @test isOK(st)
        @test fsc_op_count(srv, Wire.kXR_mkdir) == 2

        st, _ = mkpath(fs, "/x/moded", 0o700)
        @test isOK(st) && srv.nodes["/x/moded"].mode == 0o700
        @test isempty(srv.violations)
    end

    @testset "touch creates without disturbing what is there" begin
        fsc_reset!(srv)
        st, _ = touch(fs, "/x/fresh")
        @test isOK(st) && haskey(srv.nodes, "/x/fresh")
        @test isempty(srv.nodes["/x/fresh"].data)

        # An existing file keeps its bytes: touch has no truncating open in it.
        st, _ = touch(fs, "/x/a.txt")
        @test isOK(st)
        @test srv.nodes["/x/a.txt"].data == Vector{UInt8}("hello")

        # It must not have left a handle behind on either path.
        @test isempty(srv.handles)
        @test isempty(srv.violations)
    end

    @testset "rm recursive empties a tree from the bottom up" begin
        fsc_reset!(srv)
        @test isOK(mkpath(fs, "/tree/a/b")[1])
        @test isOK(touch(fs, "/tree/a/b/leaf")[1])
        @test isOK(touch(fs, "/tree/a/other")[1])

        fsc_reset!(srv)
        st, _ = rm(fs, "/tree"; recursive=true)
        @test isOK(st)
        @test !any(startswith(p, "/tree") for p in keys(srv.nodes))
        # A directory is removed only once it is empty, so every kXR_rmdir
        # comes after the kXR_rm of everything it held.
        rmdirs = findall(==(Wire.kXR_rmdir), srv.ops)
        rms = findall(==(Wire.kXR_rm), srv.ops)
        @test !isempty(rmdirs) && !isempty(rms)
        @test maximum(rms) < maximum(rmdirs)
        @test isempty(srv.violations)

        # The plain form still removes a plain file, and recursion over one
        # is the same single request rather than a failed listing.
        @test isOK(touch(fs, "/x/one.txt")[1])
        st, _ = rm(fs, "/x/one.txt"; recursive=true)
        @test isOK(st) && !haskey(srv.nodes, "/x/one.txt")

        st, _ = rm(fs, "/x/nowhere"; recursive=true)
        @test isError(st) && st.code == FSC_NotFound
    end

    @testset "statx answers about many paths at once" begin
        fsc_reset!(srv)
        st, flags = statx(fs, ["/x/a.txt", "/x/sub", "/x/nowhere"])
        @test isOK(st) && length(flags) == 3
        @test isfile(flags[1]) && isreadable(flags[1]) && iswritable(flags[1])
        @test isdir(flags[2])
        @test isOffline(flags[3])
        @test fsc_op_count(srv, Wire.kXR_statx) == 1

        # No paths is no request.
        st, flags = statx(fs, String[])
        @test isOK(st) && isempty(flags)
        @test fsc_op_count(srv, Wire.kXR_statx) == 1
        @test isempty(srv.violations)
    end

    @testset "checksum picks its algorithm through the CGI" begin
        fsc_reset!(srv)
        st, cks = checksum(fs, "/x/a.txt")
        @test isOK(st) && cks == "adler32 062c0215"
        @test srv.opaque[end] == ""

        st, cks = checksum(fs, "/x/a.txt"; algorithm="md5")
        @test isOK(st) && startswith(cks, "md5 ")
        @test srv.opaque[end] == "cks.type=md5"

        # A path that already carries CGI keeps it.
        st, _ = checksum(fs, "/x/a.txt?authz=tok"; algorithm="crc32c")
        @test isOK(st) && srv.opaque[end] == "authz=tok&cks.type=crc32c"

        st, _ = checksum_cancel(fs, "/x/a.txt")
        @test isOK(st)
        @test isempty(srv.violations)
    end

    @testset "dirlist_checksum digests a directory in one listing" begin
        # Its own namespace: the digests are asserted by value, so nothing the
        # earlier testsets left behind may show up in the listing.
        dsrv, dport = start_conf_fs(["/d/hello.txt" => "hello", "/d/sub/"])
        dfs = conf_fs(dport)
        st, names, stats, cksums = dirlist_checksum(dfs, "/d")
        @test isOK(st)
        @test names == ["hello.txt", "sub"]
        # kXR_dcksm implies kXR_dstat, so the stat lines come back whether or
        # not the client also asked for them — and they are the extended form.
        @test stats !== nothing && stats[1].size == 5
        @test stats[1].octmode == "rw-r--r--"
        @test isdir(stats[2])
        @test [c.algorithm for c in cksums] == ["adler32", "adler32"]
        @test cksums[1].value == "062c0215"          # adler32("hello")
        # A directory has no digest of its own and says so rather than
        # leaving the token off and shifting every other entry's answer.
        @test cksums[2].value == "none"
        @test fsc_op_count(dsrv, Wire.kXR_dirlist) == 1
        @test dsrv.opaque[end] == ""
        @test isempty(dsrv.violations)

        # The algorithm rides on the path as CGI, the way `checksum` picks one.
        st, _, _, cksums = dirlist_checksum(dfs, "/d"; algorithm="crc32c")
        @test isOK(st) && dsrv.opaque[end] == "cks.type=crc32c"
        @test cksums[1] == (; algorithm="crc32c", value="9a71bb4c")

        st, _, _, _ = dirlist_checksum(dfs, "/d?authz=tok"; algorithm="crc32c")
        @test isOK(st) && dsrv.opaque[end] == "authz=tok&cks.type=crc32c"

        # An algorithm the server does not have is its refusal, not an
        # empty answer.
        st, names, stats, cksums = dirlist_checksum(dfs, "/d"; algorithm="sha3")
        @test isError(st) && st.code == FSC_ServerError
        @test names === nothing && stats === nothing && cksums === nothing
        @test isempty(dsrv.violations)

        # A server that answers a dcksm listing without the tokens is not
        # lying about them: there is nothing to report rather than "none".
        dsrv.no_stat = true
        st, names, stats, cksums = dirlist_checksum(dfs, "/d")
        @test isOK(st) && names == ["hello.txt", "sub"]
        @test stats === nothing && cksums === nothing
        @test isempty(dsrv.violations)
        close(dfs)
    end

    @testset "gpfile is declared, refused and reported" begin
        fsc_reset!(srv)
        st, body = gpfile(fs, "/x/a.txt"; options=1, buffsz=1 << 16)
        # No server implements the opcode; the client's job is to send a
        # well-formed request and hand the refusal back unembellished.
        @test isError(st) && st.code == FSC_Unsupported
        @test body === nothing
        @test srv.gpfiles == [(; options=1, buffsz=1 << 16)]
        @test srv.paths[end] == "/x/a.txt"
        @test isempty(srv.violations)

        st, _ = gpfile(fs, "/x/a.txt")
        @test isError(st) && srv.gpfiles[end] == (; options=0, buffsz=0)
        @test isempty(srv.violations)

        # A server that said gpfile only travels over TLS is refused here, on
        # the cleartext link: sending it anyway would put whatever the request
        # carries on the wire in the clear.
        conn = XRootD.XrdCl.connection!(fs)
        conn.flags |= Wire.kXR_tlsGPF
        st, body = gpfile(fs, "/x/a.txt")
        @test isError(st) && st.code == ErrorCode.TLSRequired
        @test body === nothing && occursin("TLS", st.message)
        @test fsc_op_count(srv, Wire.kXR_gpfile) == 2      # nothing was sent
        conn.flags &= ~Wire.kXR_tlsGPF
        @test isempty(srv.violations)
    end

    @testset "xattrs reads every attribute in one get" begin
        fsc_reset!(srv)
        @test isOK(setxattr(fs, "/x/a.txt", "one", Vector{UInt8}("1"))[1])
        @test isOK(setxattr(fs, "/x/a.txt", "two", Vector{UInt8}("22"))[1])

        fsc_reset!(srv)
        st, attrs = xattrs(fs, "/x/a.txt")
        @test isOK(st)
        @test attrs == Dict("one" => Vector{UInt8}("1"), "two" => Vector{UInt8}("22"))
        # One list and one get, however many attributes there are.
        @test fsc_op_count(srv, Wire.kXR_fattr) == 2

        st, attrs = xattrs(fs, "/x/sub/b.bin")
        @test isOK(st) && isempty(attrs)

        st, _ = xattrs(fs, "/x/nowhere")
        @test isError(st) && st.code == FSC_NotFound
        @test isempty(srv.violations)
    end

    @testset "evict prepares without staging" begin
        fsc_reset!(srv)
        st, handle = evict(fs, ["/x/a.txt"])
        @test isOK(st) && handle == "prep-0001"
        @test isempty(srv.violations)
    end

    @testset "query_config names its answers" begin
        fsc_reset!(srv)
        st, cfg = query_config(fs, "role", "sitename")
        @test isOK(st) && cfg == Dict("role" => "server", "sitename" => "conformance")

        st, cfg = query_config(fs)
        @test isOK(st) && cfg == Dict("version" => "5.2.0")
        @test isempty(srv.violations)
    end

    @testset "appid labels the connection, endsess releases it" begin
        fsc_reset!(srv)
        st, _ = appid(fs, "conformance")
        @test isOK(st) && srv.directives == ["appid conformance"]

        st, _ = set_property(fs, "monitor info test")
        @test isOK(st) && srv.directives[end] == "monitor info test"

        sessid = XRootD.XrdCl.connection!(fs).sessid
        st, _ = endsess(fs)
        @test isOK(st)
        @test srv.sessions_ended == [Tuple(sessid)]
        @test fs.conn === nothing
        @test isempty(srv.violations)

        # The handle still works: the next operation connects again.
        @test isOK(ping(fs)[1])
        close(fs)
        @test fs.conn === nothing
    end

    @testset "deep_locate resolves managers down to data servers" begin
        fsc_reset!(srv)
        # The namespace server answers every locate with one server and one
        # manager pointing at itself, so the recursion terminates on the
        # second visit to an address it has already resolved.
        # The manager it names is not listening, and an unreachable
        # subordinate is a branch to skip rather than a failed locate.
        st, locs = withenv("XRDC_MAX_STALL_MS" => "0") do
            deep_locate(fs, "/x/a.txt")
        end
        @test isOK(st)
        @test all(!ismanager, locs)
        @test !isempty(locs) && locs[1].address == "127.0.0.1:1094"
        @test isempty(srv.violations)
    end

    @testset "the protocol reply names what answered it" begin
        fsc_reset!(srv)
        st, info = protocol(fs)
        @test isOK(st)
        # The namespace server holds the files it answers about, so it is a
        # data server and not a redirector.
        @test isserver(info) && !ismanager(info)
        @test !isproxy(info) && !ismeta(info) && !issupervisor(info)
        # It volunteers none of the capability bits either, and a client that
        # assumed otherwise would send requests nothing answers.
        @test !supports_gpfile(info) && !allows_anon_gpfile(info)
        @test !supports_pgio(info) && !supports_posc(info)
        @test supports_gpfile(ProtocolInfo(UInt32(0x520), Wire.kXR_supgpf))
        @test allows_anon_gpfile(ProtocolInfo(UInt32(0x520), Wire.kXR_anongpf))
        @test supports_pgio(ProtocolInfo(UInt32(0x520), Wire.kXR_suppgrw))
        @test supports_posc(ProtocolInfo(UInt32(0x520), Wire.kXR_supposc))
        @test isempty(srv.violations)
    end

    @testset "error_name reads a status back as a protocol name" begin
        fsc_reset!(srv)
        st, _ = stat(fs, "/x/nowhere")
        @test isError(st) && error_name(st) == "kXR_NotFound"
        @test isempty(srv.violations)
    end

    close(fs)
end
