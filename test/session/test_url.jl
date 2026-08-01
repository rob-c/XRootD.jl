# The `root://` URL grammar. Everything the client does starts by taking a URL
# apart, so the parts that are easy to get wrong are worth spelling out: the
# userinfo that names the login account, the colons of an IPv6 literal that are
# not a port separator, and the doubled slash that separates the authority from
# an absolute path.
#
# The grammar is libxrdc's (`net/url.c` + `compat/host_split.c`): a bad port is
# refused rather than defaulted, `xroot(s)://` is an accepted alias, and the CGI
# stays attached to the path because it is the server that splits the two.

using XRootD: Session
using XRootD.Session: parse_root_url, split_host_port, DEFAULT_PORT, RootURL

@testset "root:// URL grammar" begin
    @testset "the parts a URL is made of" begin
        # (url, scheme, username, host, port, path)
        cases = [
            (
                "root://eos.example.org//store/d.root",
                "root",
                "",
                "eos.example.org",
                1094,
                "/store/d.root",
            ),
            ("root://eos.example.org:1095//a", "root", "", "eos.example.org", 1095, "/a"),
            ("roots://h//a/b", "roots", "", "h", 1094, "/a/b"),
            ("root://alice@h//a", "root", "alice", "h", 1094, "/a"),
            ("roots://alice@h:1095//a", "roots", "alice", "h", 1095, "/a"),
            ("root://[2001:db8::1]:1234//p", "root", "", "2001:db8::1", 1234, "/p"),
            ("root://[::1]//p", "root", "", "::1", 1094, "/p"),
            ("root://bob@[::1]:1095//p", "root", "bob", "::1", 1095, "/p"),
            # A single slash addresses the same path: only the doubled one collapses.
            ("root://h/relative", "root", "", "h", DEFAULT_PORT, "/relative"),
            # An endpoint names no path at all.
            ("root://h", "root", "", "h", 1094, ""),
            ("root://h:1095", "root", "", "h", 1095, ""),
            ("root://alice@h", "root", "alice", "h", 1094, ""),
        ]
        for (url, scheme, username, host, port, path) in cases
            u = parse_root_url(url)
            @test (u.scheme, u.username, u.host, u.port, u.path) ==
                (scheme, username, host, port, path)
            @test u.raw == url
        end
    end

    @testset "xroot(s):// is the same URL spelled the other way" begin
        for (alias, canonical) in
            ["xroot://h//p" => "root://h//p", "xroots://h//p" => "roots://h//p"]
            a, c = parse_root_url(alias), parse_root_url(canonical)
            @test (a.scheme, a.host, a.port, a.path) == (c.scheme, c.host, c.port, c.path)
        end
        @test parse_root_url("xroots://alice@h:1095//p").username == "alice"
        # The scheme is a keyword, not a hostname: its case carries no meaning.
        @test parse_root_url("ROOT://HOST//P").scheme == "root"
        @test parse_root_url("XRootS://h//p").scheme == "roots"
        # ... and the host is passed to the resolver as it was written.
        @test parse_root_url("ROOT://HOST//P").host == "HOST"
        @test parse_root_url("root://h//Store/D.root").path == "/Store/D.root"
    end

    @testset "TLS is a property of the scheme" begin
        for url in ("roots://h//p", "xroots://h//p", "ROOTS://h//p")
            @test parse_root_url(url).scheme == "roots"
        end
        for url in ("root://h//p", "xroot://h//p")
            @test parse_root_url(url).scheme == "root"
        end
    end

    @testset "the path keeps its CGI, and everything after the authority" begin
        @test parse_root_url("root://h//p?authz=tok").path == "/p?authz=tok"
        @test parse_root_url("root://h//p?a=1&b=2").path == "/p?a=1&b=2"
        # A `@` or `:` past the authority belongs to the path, not the authority.
        @test parse_root_url("root://h//p?u=a@b").path == "/p?u=a@b"
        @test parse_root_url("root://h//p:1").path == "/p:1"
        # Interior double slashes are the server's business; only the leading
        # pair is the authority/path separator.
        @test parse_root_url("root://h//a//b").path == "/a//b"
        @test parse_root_url("root://h///a").path == "//a"
        @test parse_root_url("root://h//").path == "/"
        @test parse_root_url("root://h/").path == "/"
        # Spaces and dots are legal in a name and are not normalised away.
        @test parse_root_url("root://h//a dir/f.root").path == "/a dir/f.root"
        @test parse_root_url("root://h//a/../b").path == "/a/../b"
    end

    @testset "userinfo names the login account" begin
        @test parse_root_url("root://alice@h//p").username == "alice"
        # The first `@` separates: the rest is the authority, which cannot
        # contain another one.
        @test parse_root_url("root://a@b@h//p").username == "a"
        @test parse_root_url("root://h//p").username == ""
        # A `user:password` form keeps the pair together — the protocol has no
        # password field, so the client never invents one.
        @test parse_root_url("root://a:b@h//p").username == "a:b"
        @test parse_root_url("root://a:b@h:1095//p").port == 1095
    end

    @testset "a port that is not one is refused, not defaulted" begin
        for url in (
            "root://h:abc//p",
            "root://h:99999//p",
            "root://h:0//p",
            "root://h:-1//p",
            "root://h:1094x//p",
            "root://h:  //p",
            "root://h://p",
            "root://[::1]:abc//p",
            "root://[::1]:0//p",
        )
            @test_throws ArgumentError parse_root_url(url)
        end
        # The edges of the range are ports like any other.
        @test parse_root_url("root://h:1//p").port == 1
        @test parse_root_url("root://h:65535//p").port == 65535
        @test_throws ArgumentError parse_root_url("root://h:65536//p")
    end

    @testset "an authority that is not addressable is refused" begin
        for url in (
            "root://",
            "root:///p",
            "root://:1094//p",
            "root://[::1//p",               # unterminated literal
            "root://[]//p",                 # empty literal
            "root://[::1]junk//p",          # junk between the literal and the port
            "root://[::1]x:1094//p",
        )
            @test_throws ArgumentError parse_root_url(url)
        end
        # An empty userinfo is not a missing host: `@h` still names `h`.
        empty_user = parse_root_url("root://@h//p")
        @test (empty_user.username, empty_user.host) == ("", "h")
    end

    @testset "a scheme this client does not speak is refused" begin
        for url in (
            "http://h/p",
            "https://h/p",
            "file:///p",
            "s3://bucket/key",
            "rootx://h//p",
            "/store/d.root",
            "h:1094",
            "",
            "root:/h//p",                   # one slash short of a URL
            "://h//p",
        )
            @test_throws ArgumentError parse_root_url(url)
        end
        # The message says which URL was refused — a client that parses many
        # of them has to be able to say which one was wrong.
        err = try
            parse_root_url("http://h/p")
        catch e
            e
        end
        @test err isa ArgumentError && occursin("http://h/p", err.msg)
    end

    @testset "host:port splitting on its own" begin
        @test split_host_port("h", "url") == ("h", DEFAULT_PORT)
        @test split_host_port("h:1095", "url") == ("h", 1095)
        @test split_host_port("[::1]", "url") == ("::1", DEFAULT_PORT)
        @test split_host_port("[::1]:1095", "url") == ("::1", 1095)
        # An unbracketed literal is ambiguous; the last colon is the port
        # separator, which is why brackets exist.
        @test split_host_port("2001:db8::1:1095", "url") == ("2001:db8::1", 1095)
        @test_throws ArgumentError split_host_port("", "url")
        @test_throws ArgumentError split_host_port(":1095", "url")
    end

    @testset "parsing is repeatable, and the parts spell the URL again" begin
        parts(u) = (u.scheme, u.username, u.host, u.port, u.path)
        u = parse_root_url("root://alice@h:1095//p?authz=t")
        @test u isa RootURL
        @test parts(u) == parts(parse_root_url("root://alice@h:1095//p?authz=t"))
        @test parts(u) != parts(parse_root_url("root://alice@h:1096//p?authz=t"))
        # Round trip: the parts spell a URL that parses back to the same parts.
        again = parse_root_url("$(u.scheme)://$(u.username)@$(u.host):$(u.port)/$(u.path)")
        @test parts(again) == parts(u)
    end
end
