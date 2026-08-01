# URL handling on the wire. A `root://` URL is not just an address: everything
# past the first `?` is CGI that the server splits off and acts on — it is how
# authorization tokens reach an endpoint. These tests pin down what the client
# puts in the path field of a request, and that the namespace the server ends
# up addressing is the path alone.

using XRootD.XrdCl
using XRootD.XrdCl: parse_file_url
using XRootD.Storage: storage_for, storage_read, storage_write
using XRootD.Tools: copyfile

@testset "conformance: URLs and opaque data" begin
    srv, port = start_conf_fs(["/data/a.txt" => "hello", "/out/"])
    host = "root://127.0.0.1:$port"

    @testset "root:// URLs parse the way the protocol spells them" begin
        @test parse_file_url("root://host//data/f") == ("host", 1094, "/data/f")
        @test parse_file_url("root://host:1234//data/f") == ("host", 1234, "/data/f")
        @test parse_file_url("roots://host//data/f") == ("host", 1094, "/data/f")
        # A single slash is a path too — only the doubled one is collapsed.
        @test parse_file_url("root://host/data/f") == ("host", 1094, "/data/f")
        # The CGI belongs to the path field and is handed on unparsed.
        @test parse_file_url("root://host//f?authz=t")[3] == "/f?authz=t"

        @test_throws ArgumentError parse_file_url("http://host/data/f")
        @test_throws ArgumentError parse_file_url("/data/f")
        @test_throws ArgumentError parse_file_url("root://host")

        # The `xroot://` alias and an IPv6 literal are the same URL to the
        # client; the brackets exist to tell the address colons from the port.
        @test parse_file_url("xroot://host//data/f") == ("host", 1094, "/data/f")
        @test parse_file_url("root://[::1]:1095//data/f") == ("::1", 1095, "/data/f")
        @test parse_file_url("root://alice@host//data/f") == ("host", 1094, "/data/f")
        @test_throws ArgumentError parse_file_url("root://host:notaport//f")

        fs = FileSystem("root://host:9//ignored")
        @test fs.host == "host" && fs.port == 9 && !fs.want_tls
        @test FileSystem("roots://host").want_tls
        @test FileSystem("xroots://host").want_tls
        @test FileSystem("root://host").port == 1094
        @test FileSystem("root://[2001:db8::1]:1095").host == "2001:db8::1"
        @test_throws ArgumentError FileSystem("https://host/x")
        @test_throws ArgumentError FileSystem("root://host:0")
    end

    @testset "a user named in the URL is the account that logs in" begin
        fsc_reset!(srv)
        fs = FileSystem("root://alice@127.0.0.1:$port")
        st, _ = ping(fs)
        @test isOK(st)
        @test srv.logins == ["alice"]

        # A file URL carries it the same way, and an explicit keyword still wins
        # over the URL — the caller is more specific than the address.
        fsc_reset!(srv)
        f = File("root://bob@127.0.0.1:$port//data/a.txt")
        @test f !== nothing
        close(f)
        @test srv.logins == ["bob"]

        fsc_reset!(srv)
        fs = FileSystem("root://alice@127.0.0.1:$port"; username="carol")
        @test isOK(first(ping(fs)))
        @test srv.logins == ["carol"]

        # With no user in the URL the client logs in as whoever is running it.
        fsc_reset!(srv)
        @test isOK(first(ping(conf_fs(port))))
        # The login field is 8 bytes wide, so a longer account name arrives cut.
        @test srv.logins == [first(get(ENV, "USER", "nobody"), 8)]
        @test isempty(srv.violations)
    end

    @testset "the xroot:// alias reaches the same server" begin
        fsc_reset!(srv)
        f = File("xroot://127.0.0.1:$port//data/a.txt")
        @test f !== nothing
        st, data = read(f, 5, 0)
        @test isOK(st) && String(copy(data)) == "hello"
        close(f)

        st, si = stat(FileSystem("xroot://127.0.0.1:$port"), "/data/a.txt")
        @test isOK(st) && si.size == 5
        @test isempty(srv.violations)
    end

    @testset "an opened file carries its CGI and is found without it" begin
        fsc_reset!(srv)
        f = File("$host//data/a.txt?authz=tok&xrd.wantprot=unix")
        @test f !== nothing
        st, data = read(f, 5, 0)
        @test isOK(st) && String(copy(data)) == "hello"
        close(f)
        @test srv.paths == ["/data/a.txt"]
        @test srv.opaque == ["authz=tok&xrd.wantprot=unix"]
        @test isempty(srv.violations)
    end

    @testset "filesystem requests carry it on every path they name" begin
        fs = conf_fs(port)

        fsc_reset!(srv)
        st, si = stat(fs, "/data/a.txt?authz=t1")
        @test isOK(st) && si.size == 5
        @test srv.paths == ["/data/a.txt"] && srv.opaque == ["authz=t1"]

        fsc_reset!(srv)
        st, names = readdir(fs, "/data?authz=t2")
        @test isOK(st) && names == ["a.txt"]
        @test srv.opaque == ["authz=t2"]

        fsc_reset!(srv)
        st, _ = mkdir(fs, "/cgi?authz=t3")
        @test isOK(st) && haskey(srv.nodes, "/cgi") && !haskey(srv.nodes, "/cgi?authz=t3")

        # Both halves of a two-path request keep their own CGI.
        fsc_reset!(srv)
        st, _ = mv(fs, "/cgi?a=1", "/cgi2?b=2")
        @test isOK(st)
        @test srv.paths == ["/cgi", "/cgi2"] && srv.opaque == ["a=1", "b=2"]
        @test haskey(srv.nodes, "/cgi2")

        # A path with no CGI gets none: the client invents nothing.
        fsc_reset!(srv)
        st, _ = stat(fs, "/data/a.txt")
        @test isOK(st) && srv.opaque == [""]
        @test isempty(srv.violations)
    end

    @testset "the storage layer and the copy engine hand the token through" begin
        fsc_reset!(srv)
        dir = mktempdir()
        down = joinpath(dir, "a.txt")
        @test first(copyfile("$host//data/a.txt?authz=tok", down))
        @test read(down, String) == "hello"
        @test srv.opaque == ["authz=tok"]        # the open, and nothing else

        fsc_reset!(srv)
        @test storage_write(storage_for("$host//out/up.bin?authz=tok"), IOBuffer("up")) ==
            :ok
        @test srv.nodes["/out/up.bin"].data == Vector{UInt8}("up")
        @test srv.opaque == ["authz=tok"]

        fsc_reset!(srv)
        sink = IOBuffer()
        @test storage_read(storage_for("$host//out/up.bin?authz=tok"), sink) == :ok
        @test take!(sink) == Vector{UInt8}("up")
        @test srv.opaque == ["authz=tok"]
        @test isempty(srv.violations)
    end
end
