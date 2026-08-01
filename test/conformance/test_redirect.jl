# Redirects: the half of the protocol that makes a federation work. A manager
# holds no data, so every useful operation against one ends in `kXR_redirect`
# and the client is expected to reconnect, log in again, and re-issue the
# request at the destination with the manager's opaque data attached.
#
# These tests put a redirector in front of the namespace conformance server
# and judge the client by what the *destination* ends up seeing: the path, the
# CGI and the identity that arrived there. The hostile cases — a loop, a dead
# destination, a redirect body that decodes to nothing, a server that only
# ever says "wait" — must all end in a status, never in a hang or a throw.

using XRootD.XrdCl
using XRootD: Wire

@testset "conformance: redirects" begin
    target, tport = start_conf_fs(["/data/a.txt" => "hello", "/out/"])

    # A redirect remakes the connection, so the stall deadline cannot ride on
    # the handle the test opened: it has to come from the environment to cover
    # every connection the client makes on its way to the destination.
    withenv("XRDC_STALL_DEADLINE_MS" => string(CONF_STALL_MS)) do
        @testset "a redirect is followed to the server that holds the file" begin
            fsc_reset!(target)
            rdr, rport = start_redirector(; target_port=tport)
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")

            st, si = stat(fs, "/data/a.txt")
            @test isOK(st) && si.size == 5
            @test rdr.ops == [Wire.kXR_stat]        # the manager answered once
            @test target.paths == ["/data/a.txt"]   # ... and the destination served it
            @test fs.port == tport

            # The destination sticks: the next operation goes straight there
            # rather than back through the manager.
            st, _ = stat(fs, "/data/a.txt")
            @test isOK(st)
            @test length(rdr.ops) == 1
            @test length(target.paths) == 2
            @test isempty(rdr.violations) && isempty(target.violations)
        end

        @testset "a mutation is redirected too, and takes effect at the target" begin
            fsc_reset!(target)
            rdr, rport = start_redirector(; target_port=tport)
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")

            st, _ = mkdir(fs, "/out/viaredir")
            @test isOK(st)
            @test rdr.ops == [Wire.kXR_mkdir]
            @test target.nodes["/out/viaredir"].dir
            @test isempty(rdr.violations) && isempty(target.violations)
        end

        @testset "the manager's opaque data travels with the request" begin
            fsc_reset!(target)
            rdr, rport = start_redirector(; target_port=tport, cgi="authz=redir")
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")

            st, _ = stat(fs, "/data/a.txt")
            @test isOK(st)
            # The path the destination acts on is the path alone; the token the
            # manager issued arrives beside it.
            @test target.paths == ["/data/a.txt"]
            @test target.opaque == ["authz=redir"]

            # The caller's own CGI is not thrown away to make room for it.
            fsc_reset!(target)
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
            st, _ = stat(fs, "/data/a.txt?mine=1")
            @test isOK(st)
            @test target.paths == ["/data/a.txt"]
            @test target.opaque == ["mine=1&authz=redir"]
            @test isempty(rdr.violations) && isempty(target.violations)
        end

        @testset "the target is taken apart the way the manager spelled it" begin
            # A manager names its target already bracketed when it is an IPv6
            # literal; the brackets belong to the notation, not to the address
            # the resolver is handed. (127.0.0.1 stands in for ::1 here so the
            # test does not depend on the loopback stack having IPv6.)
            fsc_reset!(target)
            rdr, rport = start_redirector(; target_host="[127.0.0.1]", target_port=tport)
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
            st, si = stat(fs, "/data/a.txt")
            @test isOK(st) && si.size == 5
            @test fs.host == "127.0.0.1"

            # EOS hands the open capability over as "?&cap.sym=…". The `&` is
            # the separator the manager put there, not part of the token.
            fsc_reset!(target)
            rdr, rport = start_redirector(; target_port=tport, cgi="&cap.sym=abc")
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
            st, _ = stat(fs, "/data/a.txt")
            @test isOK(st)
            @test target.opaque == ["cap.sym=abc"]

            fsc_reset!(target)
            f = XrdCl.File("root://127.0.0.1:$rport//data/a.txt")
            @test f !== nothing
            close(f)
            @test target.opaque == ["cap.sym=abc"]
            @test isempty(rdr.violations) && isempty(target.violations)
        end

        @testset "a negative port sends the client to a TLS endpoint" begin
            # The port field is signed: a manager that wants the client to
            # continue over TLS negates it (XRootD 5). The magnitude is still
            # the port, so a client that ignored the sign would talk plaintext
            # to a port that only speaks TLS — or, worse, to no port at all.
            dead = dead_port()
            rdr, rport = start_redirector(; target_port=(-dead))
            withenv("XRDC_MAX_STALL_MS" => "500") do
                fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
                st, _ = stat(fs, "/data/a.txt")
                @test isError(st)
                @test fs.port == dead        # the magnitude, not the raw value
                @test fs.want_tls            # ... and TLS from here on
            end
            @test rdr.ops == [Wire.kXR_stat]
            @test isempty(rdr.violations)

            # A plain redirect leaves a plaintext session plaintext.
            fsc_reset!(target)
            rdr, rport = start_redirector(; target_port=tport)
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
            st, _ = stat(fs, "/data/a.txt")
            @test isOK(st)
            @test fs.port == tport && !fs.want_tls
            @test isempty(rdr.violations) && isempty(target.violations)
        end

        @testset "the destination is logged in as the same user" begin
            fsc_reset!(target)
            rdr, rport = start_redirector(; target_port=tport)
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport"; username="alice")

            st, _ = stat(fs, "/data/a.txt")
            @test isOK(st)
            # Credentials are a property of the handle, not of the connection
            # that happened to be open: the new session presents them again.
            @test rdr.logins == ["alice"]
            @test target.logins == ["alice"]
            @test isempty(rdr.violations) && isempty(target.violations)
        end

        @testset "a redirect loop is bounded" begin
            # Port 0 means "keep the port you used", so this redirector sends
            # the client straight back to itself.
            rdr, rport = start_redirector(; target_port=0)
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")

            st, _ = stat(fs, "/data/a.txt")
            @test isError(st)
            @test occursin("too many redirects", st.message)
            # Eight hops plus the request that earned the ninth redirect, each
            # on its own connection — the client gave up on its own.
            @test length(rdr.ops) == 9
            @test rdr.conns == 9
            @test isempty(rdr.violations)
        end

        @testset "a redirect to a dead server is reported, not waited out" begin
            rdr, rport = start_redirector(; target_port=dead_port())
            withenv("XRDC_MAX_STALL_MS" => "500") do
                fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
                elapsed = @elapsed ((st, _) = stat(fs, "/data/a.txt"))
                @test isError(st)
                @test elapsed < 10          # the retry window, not the TCP one
            end
            @test rdr.ops == [Wire.kXR_stat]
            @test isempty(rdr.violations)
        end

        @testset "a malformed redirect is refused rather than acted on" begin
            # Four bytes are the port; a body shorter than that names nothing.
            rdr, rport = start_redirector(; body=UInt8[0x00, 0x01])
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
            st, _ = stat(fs, "/data/a.txt")
            @test isError(st) && occursin("malformed kXR_redirect", st.message)

            # A well-formed body with no host is just as unusable.
            rdr, rport = start_redirector(; body=cs_be32(1094))
            fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
            st, _ = stat(fs, "/data/a.txt")
            @test isError(st) && occursin("names no host", st.message)
            @test isempty(rdr.violations)
        end

        @testset "opening a file follows the redirect and reads at the target" begin
            fsc_reset!(target)
            rdr, rport = start_redirector(; target_port=tport, cgi="authz=open")
            f = XrdCl.File("root://127.0.0.1:$rport//data/a.txt")
            @test f !== nothing

            st, data = read(f, 5, 0)
            @test isOK(st) && String(copy(data)) == "hello"
            close(f)

            @test rdr.ops == [Wire.kXR_open]
            @test target.paths == ["/data/a.txt"]
            @test target.opaque == ["authz=open"]
            @test isempty(target.handles)
            @test isempty(rdr.violations) && isempty(target.violations)
        end

        @testset "an open that only ever gets redirected gives up" begin
            rdr, rport = start_redirector(; target_port=0)
            st, _ = open(XrdCl.File(), "root://127.0.0.1:$rport//data/a.txt")
            @test isError(st) && occursin("too many redirects", st.message)
            @test length(rdr.ops) == 9

            rdr, rport = start_redirector(; body=UInt8[0x00])
            st, _ = open(XrdCl.File(), "root://127.0.0.1:$rport//data/a.txt")
            @test isError(st) && occursin("malformed kXR_redirect", st.message)

            # Nothing is left half-open when the open ends in a redirect.
            f = XrdCl.File("root://127.0.0.1:$rport//data/a.txt")
            @test f === nothing
            @test isempty(rdr.violations)
        end

        @testset "an endless stream of kXR_wait is bounded" begin
            rdr, rport = start_redirector(; wait_secs=1)
            withenv("XRDC_MAX_WAIT_MS" => "1500") do
                fs = XrdCl.FileSystem("root://127.0.0.1:$rport")
                st, _ = stat(fs, "/data/a.txt")
                @test isError(st) && occursin("kXR_wait budget", st.message)
            end
            # A wait is not a redirect: the client re-sent on the same
            # connection instead of reconnecting.
            @test length(rdr.ops) >= 2
            @test rdr.conns == 1
            @test isempty(rdr.violations)
        end
    end
end
