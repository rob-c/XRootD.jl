# Third-party copy: the wire form of the xroot rendezvous, and the dispatch
# rules that decide whether a pair of endpoints can do one at all.
#
# resp_hdr / read_request / req_sid / req_id / be32 / serve_bringup are defined
# in test/session/test_connection.jl and shared via Main.

using Sockets
using HTTP: HTTP
using XRootD: Wire
using XRootD.Storage: storage_for
using XRootD.Tools: tpc_copy, copyfile, TPC_TTL

"""
An xroot server that only knows how to be one end of a third-party copy: it
records the path (with its CGI) of every `kXR_open` and answers `kXR_sync` and
`kXR_close` cleanly. With `unsupported`, every open is refused with
`kXR_Unsupported` — the answer from a server built without TPC.
"""
function serve_tpc(sock, opens::Vector{String}, unsupported::Bool)
    try
        serve_bringup(sock)
        while isopen(sock)
            frame, payload = read_request(sock)
            sid, rid = req_sid(frame), req_id(frame)
            if rid == Wire.kXR_open
                push!(opens, String(copy(payload)))
                if unsupported
                    body = vcat(be32(3013), Vector{UInt8}(codeunits("tpc not supported")))
                    write(sock, vcat(resp_hdr(sid, Wire.kXR_error, length(body)), body))
                else
                    write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, 4), UInt8[7, 7, 7, 7]))
                end
            elseif rid == Wire.kXR_stat
                line = Vector{UInt8}(codeunits("7 0 51 1700000000"))
                write(sock, vcat(resp_hdr(sid, Wire.kXR_ok, length(line)), line))
            elseif rid in (Wire.kXR_close, Wire.kXR_sync, Wire.kXR_ping)
                write(sock, resp_hdr(sid, Wire.kXR_ok, 0))
            end
        end
    catch
        # client hung up — done
    end
    return nothing
end

"Start a TPC mock; returns `(listener, port)` and fills `opens` in request order."
function start_tpc_server(opens::Vector{String}; unsupported::Bool=false)
    server = listen(ip"127.0.0.1", 0)
    _, port = getsockname(server)
    @async while isopen(server)
        local sock
        try
            sock = accept(server)
        catch
            break
        end
        @async serve_tpc(sock, opens, unsupported)
    end
    return server, Int(port)
end

"Split an opened path's `?a=b&c=d` rendezvous CGI into a Dict."
function tpc_params(path::AbstractString)
    q = split(path, '?'; limit=2)
    length(q) == 2 || return Dict{String,String}()
    return Dict(
        String(first(kv)) => String(last(kv)) for
        kv in (split(p, '='; limit=2) for p in split(q[2], '&')) if length(kv) == 2
    )
end

@testset "third-party copy" begin
    @testset "xroot rendezvous on the wire" begin
        opens = String[]
        server, port = start_tpc_server(opens)
        try
            src = storage_for("root://127.0.0.1:$port//data/in.dat")
            dst = storage_for("root://127.0.0.1:$port//data/out.dat")
            code, msg = tpc_copy(src, dst; overwrite=true)
            @test code == :ok
            @test occursin("/data/in.dat", msg)

            # Exactly two opens: register the key at the source, then hand it
            # to the destination, which is the end that moves the bytes.
            @test length(opens) == 2
            placement, transfer = opens
            @test startswith(placement, "/data/in.dat?")
            @test startswith(transfer, "/data/out.dat?")

            p = tpc_params(placement)
            @test p["tpc.stage"] == "placement"
            @test p["tpc.dst"] == "127.0.0.1"
            @test p["tpc.ttl"] == string(TPC_TTL)

            t = tpc_params(transfer)
            @test t["tpc.stage"] == "copy"
            @test t["tpc.src"] == "127.0.0.1"
            @test t["tpc.lfn"] == "/data/in.dat"
            @test t["tpc.ttl"] == string(TPC_TTL)
            @test occursin("@", t["tpc.org"])     # user@host, for the source's log
            @test t["tpc.key"] == p["tpc.key"]    # one rendezvous, one key
            @test length(p["tpc.key"]) == 32      # 16 random bytes, hex
        finally
            close(server)
        end
    end

    @testset "a server without TPC support" begin
        opens = String[]
        server, port = start_tpc_server(opens; unsupported=true)
        try
            src = storage_for("root://127.0.0.1:$port//data/in.dat")
            dst = storage_for("root://127.0.0.1:$port//data/out.dat")
            # kXR_Unsupported is a missing capability, not a failed transfer:
            # it must leave the caller free to fall back to streaming.
            code, msg = tpc_copy(src, dst)
            @test code == :unsupported
            @test occursin("placement", msg)
            @test length(opens) == 1               # never got as far as the copy
        finally
            close(server)
        end
    end

    @testset "endpoint pairs without a third-party path" begin
        opens = String[]
        server, port = start_tpc_server(opens)
        try
            xrd = storage_for("root://127.0.0.1:$port//data/in.dat")
            web = storage_for("https://example.org/obj"; use_token=false)
            local_ = storage_for("/tmp/nonexistent-tpc-source")
            for (a, b) in ((xrd, web), (web, xrd), (local_, local_), (local_, xrd))
                @test first(tpc_copy(a, b)) == :unsupported
            end
            @test isempty(opens)
        finally
            close(server)
        end
    end

    @testset "HTTP-TPC between two web endpoints" begin
        # Two http:// endpoints do have a third-party path, and `tpc_copy`
        # hands the pair straight to the WLCG HTTP-TPC COPY.
        seen = Vector{Any}[]
        handler = function (req::HTTP.Request)
            push!(seen, Any[req.method, req.target, req.headers])
            req.method == "COPY" || return HTTP.Response(405, "")
            return HTTP.Response(200, "Perf Marker\nsuccess: Created\n")
        end
        server = HTTP.serve!(handler, "127.0.0.1", 0; verbose=false)
        base = "http://127.0.0.1:$(HTTP.port(server))"
        try
            src = storage_for("$base/src"; use_token=false)
            dst = storage_for("$base/dst"; use_token=false)

            code, msg = tpc_copy(src, dst; overwrite=true)
            @test code == :ok
            @test occursin("Created", msg)
            # :pull is the default, so the destination is the active endpoint.
            method, target, hdrs = only(seen)
            @test method == "COPY" && target == "/dst"
            @test header(hdrs, "Source") == "$base/src"
            @test header(hdrs, "Overwrite") == "T"

            empty!(seen)
            code, _ = tpc_copy(src, dst; mode=:push)
            @test code == :ok
            @test only(seen)[2] == "/src"
        finally
            close(server)
        end
    end

    @testset "copyfile fallback policy" begin
        dir = mktempdir()
        src = joinpath(dir, "a.bin")
        dst = joinpath(dir, "b.bin")
        write(src, rand(UInt8, 1024))

        # :first falls back to a streaming copy when the endpoints cannot.
        ok, _ = copyfile(src, dst; tpc=:first)
        @test ok
        @test read(dst) == read(src)

        # :only refuses to stream instead.
        ok, msg = copyfile(src, joinpath(dir, "c.bin"); tpc=:only)
        @test !ok
        @test occursin("third-party copy failed", msg)
        @test !isfile(joinpath(dir, "c.bin"))

        @test_throws ArgumentError copyfile(src, dst; force=true, tpc=:sideways)
    end
end
