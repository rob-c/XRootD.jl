using XRootD.Storage
using XRootD.Storage:
    parse_url,
    storage_for,
    storage_stat,
    storage_read,
    storage_write,
    storage_list,
    storage_remove,
    storage_mkdir,
    storage_move,
    storage_copy,
    LocalBackend,
    WebBackend,
    S3Backend,
    S3Credentials,
    sigv4_headers,
    s3_object_url
using HTTP: HTTP
using Sockets: Sockets
using Dates: DateTime
using SHA: sha256

"Look one header up case-insensitively, the way an HTTP peer must."
function header(headers, name::AbstractString)
    for (k, v) in headers
        lowercase(k) == lowercase(name) && return v
    end
    return nothing
end

@testset "Storage" begin
    @testset "URL parsing" begin
        u = parse_url("root://host:1094//data/file")
        @test u.scheme == "root" && u.host == "host" && u.port == 1094
        @test u.path == "/data/file"                 # double-slash collapsed

        u = parse_url("https://example.org/bucket/obj")
        @test u.scheme == "https" && u.port == 443 && u.tls
        @test u.path == "/bucket/obj"

        u = parse_url("s3://mybucket/key/name")
        @test u.scheme == "s3" && u.host == "mybucket" && u.path == "/key/name"

        u = parse_url("/local/path")
        @test u.scheme == "file" && u.path == "/local/path"

        u = parse_url("dav://[::1]:8080/x")
        @test u.host == "[::1]" && u.port == 8080
    end

    @testset "backend dispatch" begin
        @test storage_for("/tmp/x") isa LocalBackend
        @test storage_for("http://h/x") isa WebBackend
        @test storage_for("s3://b/k") isa S3Backend
    end

    @testset "local round trip" begin
        dir = mktempdir()
        src = joinpath(dir, "src.bin")
        data = rand(UInt8, 5000)
        write(src, data)

        b = storage_for(src)
        code, info = storage_stat(b)
        @test code == :ok && info.size == 5000

        sink = IOBuffer()
        @test storage_read(b, sink) == :ok
        @test take!(sink) == data

        # range read
        sink = IOBuffer()
        @test storage_read(b, sink; offset=10, length=20) == :ok
        @test take!(sink) == data[11:30]

        dst = storage_for(joinpath(dir, "dst.bin"))
        @test storage_write(dst, IOBuffer(data)) == :ok
        @test read(joinpath(dir, "dst.bin")) == data

        entries = storage_list(storage_for(dir))
        @test any(e -> e[1] == "src.bin", entries)
    end

    @testset "local backend mutation surface" begin
        dir = mktempdir()

        # mkdir is recursive and idempotent
        deep = joinpath(dir, "a", "b", "c")
        @test storage_mkdir(storage_for(deep)) == :ok
        @test isdir(deep)
        @test storage_mkdir(storage_for(deep)) == :ok
        # ... and reports failure rather than throwing when the path is barred
        # by an existing file.
        blocker = joinpath(dir, "blocker")
        write(blocker, "x")
        @test storage_mkdir(storage_for(joinpath(blocker, "sub"))) == :error

        # remove is force: a missing path is not an error (matches `rm -f`).
        victim = joinpath(dir, "victim.bin")
        write(victim, "gone")
        @test storage_remove(storage_for(victim)) == :ok
        @test !ispath(victim)
        @test storage_remove(storage_for(victim)) == :ok

        # move
        from = joinpath(dir, "from.bin")
        to = joinpath(dir, "to.bin")
        write(from, "payload")
        @test storage_move(storage_for(from), to) == :ok
        @test !ispath(from)
        @test read(to, String) == "payload"
        # onto an existing destination: refused unless overwrite is asked for
        write(from, "second")
        @test storage_move(storage_for(from), to) == :error
        @test read(to, String) == "payload"
        @test storage_move(storage_for(from), to; overwrite=true) == :ok
        @test read(to, String) == "second"
        # a missing source is an error, not an exception
        @test storage_move(storage_for(from), joinpath(dir, "nowhere.bin")) == :error
        # a move off the local filesystem is not a rename
        @test storage_move(storage_for(to), "root://h//x") == :unsupported

        # copy — same policy, and the source survives
        cdst = joinpath(dir, "copy.bin")
        @test storage_copy(storage_for(to), cdst) == :ok
        @test read(cdst, String) == "second"
        @test ispath(to)
        write(cdst, "existing")
        @test storage_copy(storage_for(to), cdst) == :error
        @test read(cdst, String) == "existing"
        @test storage_copy(storage_for(to), cdst; overwrite=true) == :ok
        @test read(cdst, String) == "second"
        @test storage_copy(storage_for(joinpath(dir, "absent")), cdst) == :error
        @test storage_copy(storage_for(to), "https://h/x") == :unsupported
    end

    @testset "S3 has no namespace operations" begin
        # A key prefix exists as soon as an object uses it, so mkdir is a
        # no-op; server-side rename and copy are not implemented.
        b = storage_for("s3://bucket/prefix/key")
        @test storage_mkdir(b) == :ok
        @test storage_move(b, "s3://bucket/other") == :unsupported
        @test storage_copy(b, "s3://bucket/other") == :unsupported
        @test isempty(storage_list(b))
    end

    @testset "pump across a live pipe" begin
        # Every backend drains the copy engine's pipe through pump, so it has
        # to be exact while a producer is still writing to the far end. Reading
        # a BufferStream with `read(io, n)` is not: past 64 KiB the generic
        # bulk read races the writer and loses whole chunks.
        data = rand(UInt8, 3 * Storage.IO_CHUNK + 7)
        for trial in 1:5
            pipe = Base.BufferStream()
            producer = Threads.@spawn begin
                for off in 1:(Storage.IO_CHUNK):Base.length(data)
                    write(pipe, data[off:min(off + Storage.IO_CHUNK - 1, end)])
                end
                close(pipe)
            end
            out = IOBuffer()
            n = Storage.pump(pipe, out)
            wait(producer)
            @test n == Base.length(data)
            @test take!(out) == data
        end

        # A bounded pump stops at the count it was given and leaves the rest.
        pipe = Base.BufferStream()
        write(pipe, data)
        @test Storage.pump(pipe, IOBuffer(), 40) == 40
        @test bytesavailable(pipe) == Base.length(data) - 40
        close(pipe)
    end

    @testset "HTTP backend round trip (in-process server)" begin
        served = Dict{String,Vector{UInt8}}(
            "/hello.txt" => Vector{UInt8}(codeunits("hi there"))
        )
        router = HTTP.Router()
        HTTP.register!(
            router, "GET", "/**", function (req)
                data = get(served, req.target, nothing)
                data === nothing && return HTTP.Response(404)
                for (k, v) in req.headers
                    if lowercase(k) == "range"
                        m = match(r"bytes=(\d+)-(\d*)", v)
                        if m !== nothing
                            lo = parse(Int, m.captures[1]) + 1
                            hi = if m.captures[2] == ""
                                length(data)
                            else
                                parse(Int, m.captures[2]) + 1
                            end
                            return HTTP.Response(206, data[lo:hi])
                        end
                    end
                end
                return HTTP.Response(200, data)
            end
        )
        HTTP.register!(
            router,
            "HEAD",
            "/**",
            function (req)
                data = get(served, req.target, nothing)
                data === nothing && return HTTP.Response(404)
                return HTTP.Response(200, ["Content-Length" => string(length(data))])
            end,
        )
        HTTP.register!(router, "PUT", "/**", function (req)
            served[req.target] = req.body
            return HTTP.Response(201)
        end)

        server = HTTP.serve!(router, "127.0.0.1", 0; verbose=false)
        port = HTTP.port(server)
        try
            b = storage_for("http://127.0.0.1:$port/hello.txt")
            # HTTP.jl's in-process server recomputes Content-Length for a
            # body-less HEAD, so assert reachability here; Content-Length
            # parsing is unit-tested separately below.
            code, _ = storage_stat(b)
            @test code == :ok

            sink = IOBuffer()
            @test storage_read(b, sink) == :ok
            @test String(take!(sink)) == "hi there"

            sink = IOBuffer()
            @test storage_read(b, sink; offset=0, length=2) == :ok
            @test String(take!(sink)) == "hi"

            up = storage_for("http://127.0.0.1:$port/put.txt")
            @test storage_write(up, IOBuffer(codeunits("uploaded"))) == :ok
            @test String(served["/put.txt"]) == "uploaded"
        finally
            close(server)
        end
    end

    @testset "HTTP Content-Length / Last-Modified parsing" begin
        resp = HTTP.Response(
            200,
            [
                "Content-Length" => "1234",
                "Last-Modified" => "Sun, 06 Nov 1994 08:49:37 GMT",
            ],
        )
        @test XRootD.Storage.parse_content_length(resp) == 1234
        @test XRootD.Storage.parse_last_modified(resp) == 784111777

        # Missing, unparseable, or malformed headers report zero rather than
        # propagating a `nothing` into a StorageInfo.
        bare = HTTP.Response(200, Pair{String,String}[])
        @test XRootD.Storage.parse_content_length(bare) == 0
        @test XRootD.Storage.parse_last_modified(bare) == 0
        junk = HTTP.Response(
            200, ["content-length" => "not-a-number", "last-modified" => "yesterday"]
        )
        @test XRootD.Storage.parse_content_length(junk) == 0
        @test XRootD.Storage.parse_last_modified(junk) == 0
    end

    @testset "SigV4 matches the AWS GET example vector" begin
        # AWS "Signature Version 4" documented GET example.
        creds = S3Credentials(;
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="",
            region="us-east-1",
        )
        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hdrs = sigv4_headers(
            "GET",
            "https://examplebucket.s3.amazonaws.com/test.txt",
            creds;
            payload_hash=empty_hash,
            headers=["range" => "bytes=0-9"],
            now=DateTime(2013, 5, 24, 0, 0, 0),
        )
        auth = only(v for (k, v) in hdrs if k == "Authorization")
        @test occursin(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            auth,
        )
        @test occursin("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date", auth)
    end

    @testset "S3 object operations against an in-process endpoint" begin
        # An S3-compatible endpoint on the private network (MinIO, Ceph RGW) is
        # what makes this testable without AWS; the requests it receives are the
        # ones AWS would, signature included.
        seen = Tuple{String,String,Vector{Pair{String,String}},String}[]
        handler = function (req)
            push!(
                seen,
                (
                    req.method,
                    req.target,
                    collect(Pair{String,String}, req.headers),
                    String(req.body),
                ),
            )
            occursin("/missing", req.target) && return HTTP.Response(404)
            occursin("/denied", req.target) && return HTTP.Response(403)
            if req.method == "HEAD"
                return HTTP.Response(
                    200,
                    ["Last-Modified" => "Sun, 06 Nov 1994 08:49:37 GMT"],
                    "objectdata",
                )
            elseif req.method == "GET"
                any(kv -> lowercase(kv[1]) == "range", req.headers) &&
                    return HTTP.Response(206, "ject")
                return HTTP.Response(200, "objectdata")
            elseif req.method == "PUT"
                return HTTP.Response(200)
            elseif req.method == "DELETE"
                return HTTP.Response(204)
            end
            return HTTP.Response(405)
        end
        server = HTTP.serve!(handler, "127.0.0.1", 0; verbose=false)
        port = HTTP.port(server)
        creds = S3Credentials(;
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="",
            region="us-east-1",
        )
        endpoint = "http://127.0.0.1:$port"
        try
            b = storage_for("s3://bucket/data/obj.bin"; creds=creds, endpoint=endpoint)
            @test b.bucket == "bucket"
            @test b.key == "data/obj.bin"

            code, info = storage_stat(b)
            @test code == :ok
            @test info.size == 10
            @test info.mtime == 784111777
            method, target, hdrs, _ = last(seen)
            @test method == "HEAD" && target == "/data/obj.bin"
            # Every request is signed, and the signature names the credential
            # scope the endpoint would verify it under.
            auth = something(header(hdrs, "Authorization"), "")
            @test startswith(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
            @test occursin("/us-east-1/s3/aws4_request", auth)
            @test header(hdrs, "x-amz-date") !== nothing
            @test header(hdrs, "x-amz-content-sha256") == "UNSIGNED-PAYLOAD"
            @test header(hdrs, "x-amz-security-token") === nothing

            sink = IOBuffer()
            @test storage_read(b, sink) == :ok
            @test String(take!(sink)) == "objectdata"
            @test storage_read(b, sink; offset=2, length=4) == :ok
            @test String(take!(sink)) == "ject"
            @test header(last(seen)[3], "range") == "bytes=2-5"
            @test storage_read(b, sink; offset=6) == :ok
            @test header(last(seen)[3], "range") == "bytes=6-"

            @test storage_write(b, IOBuffer("uploaded")) == :ok
            method, _, hdrs, body = last(seen)
            @test method == "PUT" && body == "uploaded"
            # A PUT is signed over the payload itself, not UNSIGNED-PAYLOAD.
            @test header(hdrs, "x-amz-content-sha256") ==
                bytes2hex(sha256(Vector{UInt8}(codeunits("uploaded"))))

            @test storage_remove(b) == :ok
            @test last(seen)[1] == "DELETE"

            # Bucket listing is not implemented; it is empty, never an error.
            @test isempty(storage_list(b))

            missing_obj = storage_for("s3://bucket/missing"; creds=creds, endpoint=endpoint)
            @test first(storage_stat(missing_obj)) == :notfound
            @test storage_read(missing_obj, IOBuffer()) == :error

            denied = storage_for("s3://bucket/denied"; creds=creds, endpoint=endpoint)
            @test first(storage_stat(denied)) == :error
            @test storage_write(denied, IOBuffer("x")) == :error
            @test storage_remove(denied) == :error

            # A session token is carried alongside the signature when there is
            # one — the endpoint needs it to resolve the temporary credential.
            temp = storage_for(
                "s3://bucket/data/obj.bin";
                creds=S3Credentials(;
                    access_key="ASIA", secret_key="s", session_token="tok", region="eu-1"
                ),
                endpoint=endpoint,
            )
            storage_stat(temp)
            @test header(last(seen)[3], "x-amz-security-token") == "tok"

            # A trailing slash on an endpoint is a typo, not a different object.
            @test XRootD.Storage.s3_object_url(
                storage_for("s3://bucket/k"; endpoint="$endpoint/")
            ) == "$endpoint/k"
            @test XRootD.Storage.s3_object_url(storage_for("s3://bucket/k")) ==
                "https://bucket.s3.amazonaws.com/k"
        finally
            close(server)
        end
    end

    @testset "an S3 endpoint that is not there" begin
        # Nothing listening: every verb reports a transport failure instead of
        # throwing out of a copy that is halfway done.
        dead = storage_for("s3://bucket/key"; endpoint="http://127.0.0.1:1")
        @test first(storage_stat(dead)) == :error
        @test storage_read(dead, IOBuffer()) == :error
        @test storage_write(dead, IOBuffer("x")) == :error
        @test storage_remove(dead) == :error
    end
end
