using XRootD.Storage
using XRootD.Storage:
    parse_url,
    storage_for,
    storage_stat,
    storage_read,
    storage_write,
    storage_list,
    storage_remove,
    LocalBackend,
    WebBackend,
    S3Backend,
    S3Credentials,
    sigv4_headers
using HTTP: HTTP
using Sockets: Sockets
using Dates: DateTime

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

    @testset "HTTP backend round trip (in-process server)" begin
        served = Dict{String,Vector{UInt8}}(
            "/hello.txt" => Vector{UInt8}(codeunits("hi there"))
        )
        router = HTTP.Router()
        HTTP.register!(
            router,
            "GET",
            "/**",
            function (req)
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
            end,
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
end
