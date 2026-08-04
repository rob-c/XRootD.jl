# XrdHttp/WebDAV credentials and write verbs: bearer tokens, X.509 client
# certificates over HTTPS, MKCOL/MOVE/COPY, and WLCG HTTP third-party copy.
#
# make_test_pki, start_mtls_server, recording and RequestLog are defined in
# test/session/test_x509.jl, `with_prompter` in test/session/test_prompt.jl,
# and `header` in test/storage/test_storage.jl; all are shared via Main.

using XRootD.Storage
using XRootD.Storage:
    storage_for,
    storage_read,
    storage_write,
    storage_stat,
    storage_list,
    storage_remove,
    storage_mkdir,
    storage_move,
    storage_copy,
    storage_tpc,
    tpc_outcome,
    parse_propfind,
    dav_destination,
    web_client,
    web_authorize!,
    WebBackend
using XRootD.Session: CredentialRequest
using XRootD.Tools: ensure_dir
using HTTP: HTTP

"A WebDAV `multistatus` body: the collection itself, a file in it, and a child."
const DAV_MULTISTATUS = """
<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/coll/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop>
    <D:status>HTTP/1.1 200 OK</D:status></D:propstat>
  </D:response>
  <D:response>
    <D:href>/coll/one%20two.bin</D:href>
    <D:propstat><D:prop><D:getcontentlength>17</D:getcontentlength>
    <D:resourcetype/></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
  </D:response>
  <D:response>
    <D:href>/coll/sub/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop>
    <D:status>HTTP/1.1 200 OK</D:status></D:propstat>
  </D:response>
</D:multistatus>
"""

"""
A WebDAV/TPC mock answering each verb with the status a real server would.
`/locked` is the collection that already exists (405) and `/denied` the one
that may not be created (403); a transfer naming `/broken` reports its failure
in the body, not in the status, and one naming `/refused` is turned away with a
status instead. `/missing` is not there, and `/gone` has no listing.
"""
function dav_handler()
    return function (req)
        if req.method == "MKCOL"
            startswith(req.target, "/locked") && return HTTP.Response(405)
            startswith(req.target, "/denied") && return HTTP.Response(403)
            return HTTP.Response(201)
        elseif req.method == "COPY" || req.method == "MOVE"
            dest = something(header(req.headers, "Destination"), "")
            src = something(header(req.headers, "Source"), "")
            if any(u -> occursin("/refused", u), (req.target, dest, src))
                return HTTP.Response(403)
            end
            if any(u -> occursin("/broken", u), (req.target, dest, src))
                return HTTP.Response(
                    200, "Perf Marker\nfailure: source refused the connection\n"
                )
            end
            isempty(src) || return HTTP.Response(200, "Perf Marker\nsuccess: Created\n")
            return HTTP.Response(201)
        elseif req.method == "PUT"
            return HTTP.Response(201)
        elseif req.method == "DELETE"
            startswith(req.target, "/denied") && return HTTP.Response(403)
            return HTTP.Response(204)
        elseif req.method == "PROPFIND"
            startswith(req.target, "/gone") && return HTTP.Response(404)
            return HTTP.Response(207, DAV_MULTISTATUS)
        elseif req.method == "HEAD"
            startswith(req.target, "/missing") && return HTTP.Response(404)
            startswith(req.target, "/denied") && return HTTP.Response(403)
            # The body is what gives the response its Content-Length; a real
            # server drops it from a HEAD and keeps the length, as this one does.
            return HTTP.Response(
                200, ["Last-Modified" => "Tue, 15 Nov 1994 12:45:26 GMT"], "payload"
            )
        elseif req.method == "GET" && header(req.headers, "Range") !== nothing
            return HTTP.Response(206, "loa")
        end
        return HTTP.Response(200, "payload")
    end
end

@testset "web credentials and WebDAV writes" begin
    @testset "bearer token policy" begin
        withenv("BEARER_TOKEN" => "discovered", "BEARER_TOKEN_FILE" => nothing) do
            b = storage_for("https://example.org/obj")
            @test ("Authorization" => "Bearer discovered") in b.headers
            @test b.token == "discovered"   # kept for third-party delegation

            # Over cleartext a discovered token is dropped. The warning that
            # goes with it is `maxlog=1`, so this asserts the effect rather
            # than the (once-per-process) log record.
            b = storage_for("http://example.org/obj")
            @test isempty(b.headers)
            @test b.token === nothing

            # An explicitly passed token is an error, not a silent downgrade.
            @test_throws ArgumentError storage_for(
                "http://example.org/obj"; token="explicit"
            )
            b = storage_for(
                "http://example.org/obj"; token="explicit", allow_cleartext_token=true
            )
            @test ("Authorization" => "Bearer explicit") in b.headers

            @test isempty(storage_for("https://example.org/obj"; use_token=false).headers)

            # dav(s):// is the same backend, and davs:// is encrypted.
            @test ("Authorization" => "Bearer discovered") in
                storage_for("davs://example.org/obj").headers
            @test isempty(storage_for("dav://example.org/obj").headers)

            # Explicit headers survive alongside the token.
            b = storage_for("https://example.org/obj"; headers=["X-Test" => "1"])
            @test ("X-Test" => "1") in b.headers
            @test ("Authorization" => "Bearer discovered") in b.headers
        end
    end

    @testset "storage option filtering" begin
        # One credential bag serves every scheme; a name no backend knows is a
        # typo, and typos in credentials fail silently unless they are caught.
        @test storage_for("/tmp/x"; token="t", cert="c") isa Storage.LocalBackend
        @test_throws ArgumentError storage_for("https://h/x"; bogus=1)
        @test_throws ArgumentError storage_for("/tmp/x"; bogus=1)
    end

    @testset "TLS client configuration" begin
        mktempdir() do dir
            pem = joinpath(dir, "proxy.pem")
            write(pem, "-----BEGIN CERTIFICATE-----\n")
            @test web_client() === nothing                       # the default client
            @test web_client(; cert=pem) isa HTTP.Client
            # Clients own a connection pool, so identical configurations share.
            @test web_client(; cert=pem) === web_client(; cert=pem)
            @test web_client(; cert=pem, insecure_tls=true) !== web_client(; cert=pem)
            @test_throws ArgumentError web_client(; key=pem)
        end
    end

    @testset "WebDAV verbs (in-process server)" begin
        recorded = RequestLog()
        server = HTTP.serve!(
            recording(dav_handler(), recorded), "127.0.0.1", 0; verbose=false
        )
        port = HTTP.port(server)
        base = "http://127.0.0.1:$port"
        try
            @test storage_mkdir(storage_for("$base/coll")) == :ok
            method, target, _ = last(recorded)
            @test method == "MKCOL"
            @test target == "/coll/"      # a collection is spelled with a slash

            # 405 is WebDAV for "already a collection", which is success here.
            @test storage_mkdir(storage_for("$base/locked")) == :ok
            @test storage_mkdir(storage_for("$base/denied")) == :error

            @test ensure_dir("$base/tree/sub") == :ok
            @test last(recorded)[2] == "/tree/sub/"

            @test storage_move(storage_for("$base/a"), "$base/b") == :ok
            method, target, hdrs = last(recorded)
            @test method == "MOVE" && target == "/a"
            @test header(hdrs, "Destination") == "$base/b"
            @test header(hdrs, "Overwrite") == "F"

            @test storage_copy(storage_for("$base/a"), "$base/b"; overwrite=true) == :ok
            method, _, hdrs = last(recorded)
            @test method == "COPY"
            @test header(hdrs, "Overwrite") == "T"

            # A destination is named in HTTP terms even when it is a dav:// URL.
            @test dav_destination("davs://example.org/x") == "https://example.org/x"
            @test dav_destination("dav://example.org:8080/x") == "http://example.org:8080/x"

            @testset "third-party copy" begin
                dst = storage_for("$base/dst")
                src = storage_for(
                    "$base/src"; token="remote-token", allow_cleartext_token=true
                )

                # pull: the destination is asked to fetch, and carries the
                # source's token in TransferHeaderAuthorization.
                code, msg = storage_tpc(dst, src; overwrite=true)
                @test code == :ok
                @test occursin("Created", msg)
                method, target, hdrs = last(recorded)
                @test method == "COPY" && target == "/dst"
                @test header(hdrs, "Source") == "$base/src"
                @test header(hdrs, "Destination") === nothing
                @test header(hdrs, "TransferHeaderAuthorization") == "Bearer remote-token"
                @test header(hdrs, "Overwrite") == "T"
                @test header(hdrs, "RequireChecksumVerification") == "false"

                # push: the source is asked to send, to an unauthenticated
                # destination — "Credential: none" says so explicitly.
                code, _ = storage_tpc(dst, src; mode=:push)
                @test code == :ok
                method, target, hdrs = last(recorded)
                @test method == "COPY" && target == "/src"
                @test header(hdrs, "Destination") == "$base/dst"
                @test header(hdrs, "Source") === nothing
                @test header(hdrs, "Credential") == "none"

                # A 2xx only says the transfer started; the body says how it ended.
                code, msg = storage_tpc(storage_for("$base/broken"), src)
                @test code == :error
                @test occursin("source refused the connection", msg)

                # A transfer the destination will not even start is a status,
                # not a marker stream, and has to be reported as one.
                code, msg = storage_tpc(storage_for("$base/refused"), src)
                @test code == :error
                @test occursin("rejected with HTTP 403", msg)

                @test_throws ArgumentError storage_tpc(dst, src; mode=:sideways)
            end

            @testset "reading, statting and removing an object" begin
                b = storage_for("$base/obj")
                sink = IOBuffer()
                @test storage_read(b, sink) == :ok
                @test String(take!(sink)) == "payload"

                # A ranged read is a partial response, and 206 is success.
                @test storage_read(b, sink; offset=1, length=3) == :ok
                @test String(take!(sink)) == "loa"
                @test header(last(recorded)[3], "Range") == "bytes=1-3"

                # An open-ended range names its start and nothing else.
                @test storage_read(b, sink; offset=4) == :ok
                @test header(last(recorded)[3], "Range") == "bytes=4-"

                status, info = storage_stat(b)
                @test status == :ok
                @test info.size == 7
                @test info.mtime == 784903526        # Tue, 15 Nov 1994 12:45:26 GMT
                @test !info.isdir

                # A path spelled as a collection is one.
                @test last(storage_stat(storage_for("$base/coll/"))).isdir

                @test first(storage_stat(storage_for("$base/missing"))) == :notfound
                @test first(storage_stat(storage_for("$base/denied"))) == :error

                @test storage_remove(b) == :ok
                @test last(recorded)[1] == "DELETE"
                @test storage_remove(storage_for("$base/denied")) == :error
            end

            @testset "listing a collection" begin
                entries = storage_list(storage_for("$base/coll"))
                @test last(recorded)[1] == "PROPFIND"
                @test header(last(recorded)[3], "Depth") == "1"

                # The collection's own entry heads every multistatus body and is
                # not one of its children; names arrive percent-decoded.
                @test [e[1] for e in entries] == ["one two.bin", "sub"]
                @test entries[1][2].size == 17
                @test !entries[1][2].isdir
                @test entries[2][2].isdir

                # Nothing to list is an empty listing, not an error.
                @test isempty(storage_list(storage_for("$base/gone")))
            end
        finally
            close(server)
        end
    end

    @testset "a transport that never answers" begin
        # Every verb funnels through one request helper, and a failure there is
        # a returned status — a connection refused must not throw out of a copy.
        dead = storage_for("http://127.0.0.1:1/obj")
        @test storage_read(dead, IOBuffer()) == :error
        @test first(storage_stat(dead)) == :error
        @test storage_write(dead, IOBuffer("x")) == :error
        @test storage_remove(dead) == :error
        @test storage_mkdir(dead) == :error
        @test isempty(storage_list(dead))
        @test first(storage_tpc(dead, storage_for("http://127.0.0.1:1/src"))) == :error
    end

    @testset "multistatus bodies that are not the happy one" begin
        # The parser is a regex over <response> blocks, so what it does with
        # namespace prefixes, missing properties and junk is worth pinning.
        @test isempty(parse_propfind("", "/coll"))
        @test isempty(parse_propfind("<not-xml", "/coll"))

        # No namespace prefix at all is legal, and a response without an href
        # names nothing.
        xml = """
        <multistatus><response><href>/c/a.bin</href>
        <getcontentlength>5</getcontentlength></response>
        <response><getcontentlength>9</getcontentlength></response></multistatus>
        """
        entries = parse_propfind(xml, "/c")
        @test entries == [("a.bin", Storage.StorageInfo(5, 0, false))]

        # A property that is missing is zero, not a parse failure.
        xml =
            "<D:multistatus xmlns:D=\"DAV:\"><D:response>" *
            "<D:href>/c/b.bin</D:href></D:response></D:multistatus>"
        @test parse_propfind(xml, "/c") == [("b.bin", Storage.StorageInfo(0, 0, false))]
    end

    @testset "HTTP-TPC outcome markers" begin
        @test tpc_outcome("Perf Marker\nsuccess: Created\n") ==
            (:ok, "third-party copy: Created")
        @test first(tpc_outcome("failure: no such file\n")) == :error
        # A failure anywhere in the stream wins over an earlier success line.
        @test first(tpc_outcome("success: Created\nfailure: truncated\n")) == :error
        # Some servers send no markers at all; the 2xx is all there is.
        @test tpc_outcome("") == (:ok, "third-party copy accepted (no completion marker)")
    end

    if !HAVE_OPENSSL
        @warn "openssl(1) not on PATH — HTTPS client-certificate tests skipped"
    else
        @testset "HTTPS mutual TLS" begin
            mktempdir() do dir
                ca, (servercert, serverkey), (clientcert, clientkey) = make_test_pki(dir)
                recorded = RequestLog()
                server = start_mtls_server(
                    ca, servercert, serverkey, recording(dav_handler(), recorded)
                )
                port = HTTP.port(server)
                try
                    b = storage_for(
                        "https://localhost:$port/obj";
                        cert=clientcert,
                        key=clientkey,
                        cafile=ca,
                        use_token=false,
                    )
                    sink = IOBuffer()
                    @test storage_read(b, sink) == :ok
                    @test String(take!(sink)) == "payload"
                    @test storage_mkdir(
                        storage_for(
                            "https://localhost:$port/coll";
                            cert=clientcert,
                            key=clientkey,
                            cafile=ca,
                            use_token=false,
                        ),
                    ) == :ok
                    @test [r[1] for r in recorded] == ["GET", "MKCOL"]

                    # No client certificate: the handshake fails, and the
                    # backend reports a transport error rather than throwing.
                    plain = storage_for(
                        "https://localhost:$port/obj"; cafile=ca, use_token=false
                    )
                    @test storage_read(plain, IOBuffer()) == :error
                finally
                    close(server)
                end
            end
        end

        @testset "a 401 is the endpoint asking for a credential" begin
            mktempdir() do dir
                ca, (servercert, serverkey), (clientcert, clientkey) = make_test_pki(dir)
                seen = String[]
                handler = function (req)
                    auth = HTTP.header(req, "Authorization", "")
                    push!(seen, auth)
                    isempty(auth) && return HTTP.Response(401, "who are you")
                    return HTTP.Response(200, "payload")
                end
                server = start_mtls_server(ca, servercert, serverkey, handler)
                port = HTTP.port(server)
                https(path) = storage_for(
                    "https://localhost:$port/$path";
                    cert=clientcert,
                    key=clientkey,
                    cafile=ca,
                    use_token=false,
                )
                try
                    b = https("obj")
                    sink = IOBuffer()
                    asked = CredentialRequest[]
                    with_prompter(r -> (push!(asked, r); "typed.token")) do
                        @test storage_read(b, sink) == :ok
                    end
                    @test String(take!(sink)) == "payload"
                    @test seen == ["", "Bearer typed.token"]
                    @test length(asked) == 1 && asked[1].kind === :token
                    @test occursin("401", asked[1].reason)
                    # Kept on the backend: the requests that follow carry it,
                    # and so does a third-party copy delegating from here.
                    @test b.token == "typed.token"
                    @test ("Authorization" => "Bearer typed.token") in b.headers

                    empty!(seen)
                    declined = https("obj")
                    with_prompter(_ -> nothing) do
                        @test storage_read(declined, IOBuffer()) == :error
                    end
                    @test seen == [""]          # asked once, not retried blindly
                    @test declined.token === nothing
                finally
                    close(server)
                end
            end
        end
    end

    @testset "a credential is never typed into a cleartext connection" begin
        with_prompter(_ -> "typed.token") do
            @test web_authorize!(storage_for("http://example.org/obj")) === nothing
            # Nor asked for twice: an endpoint that refuses the credential it
            # was already sent is not answered by typing the same kind again.
            already = storage_for("https://example.org/obj"; token="explicit")
            @test web_authorize!(already) === nothing
            @test web_authorize!(storage_for("https://example.org/obj"; use_token=false)) ==
                ("Authorization" => "Bearer typed.token")
        end
    end
end
