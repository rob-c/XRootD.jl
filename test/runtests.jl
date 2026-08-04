using Test
using XRootD
using Sockets: Sockets
using XRootD_jll: XRootD_jll

# No test may block waiting for someone to type a credential: the suite is run
# from terminals as well as from CI, and a server that asks for one must be
# answered by the test rather than by whoever is watching. This disables only
# the terminal prompter — the tests that exercise prompting install their own,
# which is unaffected.
ENV["XRDC_NO_PROMPT"] = "1"

"Wait until a TCP server accepts connections on `port` (like libxrdc's wait41)."
function wait_for_server(port::Int; timeout::Float64=30.0)
    deadline = time() + timeout
    while time() < deadline
        try
            close(Sockets.connect("127.0.0.1", port))
            return true
        catch
            sleep(0.2)
        end
    end
    return false
end

@testset verbose = true "XRootD.jl" begin
    @testset "package smoke" begin
        @test isdefined(XRootD, :Wire)
    end
    include("wire/test_primitives.jl")
    include("wire/test_constants.jl")
    include("wire/test_frames.jl")
    include("wire/test_requests.jl")
    include("wire/test_responses.jl")
    include("wire/test_codec_conformance.jl")
    include("session/test_url.jl")
    include("session/test_env.jl")
    include("session/test_retry.jl")
    include("session/test_connection.jl")
    include("session/test_auth.jl")
    include("session/test_prompt.jl")
    include("session/test_x509.jl")
    include("session/test_resilience.jl")
    include("session/test_slowpeer.jl")
    include("client/test_types.jl")
    include("client/test_file.jl")
    include("conformance/server.jl")
    include("conformance/test_rw.jl")
    include("conformance/test_datapath.jl")
    include("conformance/test_failclosed.jl")
    include("conformance/test_scale.jl")
    include("conformance/fs_server.jl")
    include("conformance/test_fs.jl")
    include("conformance/test_fs_extended.jl")
    include("conformance/test_fs_failclosed.jl")
    include("conformance/test_fs_urls.jl")
    include("conformance/test_fs_tools.jl")
    include("conformance/test_api.jl")
    include("conformance/test_file_ops.jl")
    include("conformance/test_file_extended.jl")
    include("conformance/info_server.jl")
    include("conformance/test_query.jl")
    include("conformance/test_errors.jl")
    include("conformance/test_async.jl")
    include("conformance/test_transport.jl")
    include("conformance/auth_server.jl")
    include("conformance/test_auth_exchange.jl")
    include("conformance/tls_server.jl")
    include("conformance/test_tls_negotiation.jl")
    include("conformance/redir_server.jl")
    include("conformance/test_redirect.jl")
    include("conformance/hostile_server.jl")
    include("conformance/test_hostile.jl")
    include("storage/test_storage.jl")
    include("storage/test_stream.jl")
    include("storage/test_web_auth.jl")
    include("storage/test_web_slow.jl")
    include("tools/test_tools.jl")
    include("tools/test_tpc.jl")
    include("api/test_api.jl")
    include("test_quality.jl")

    if XRootD_jll.is_available()
        @testset verbose = true "integration (legacy parity)" begin
            xrootd_server = run(XRootD_jll.xrootd(); wait=false)
            try
                @test wait_for_server(1094)
                include("legacy/testFileSystem.jl")
                include("legacy/testFile.jl")
                include("integration/test_file_v5.jl")
                include("integration/test_extended.jl")
                include("integration/test_tools.jl")
                include("integration/test_stream.jl")
                include("integration/test_api.jl")
                include("integration/test_tls.jl")
                include("parity/harness.jl")
                include("parity/test_parity.jl")
            finally
                kill(xrootd_server)
            end
        end
    else
        @warn "XRootD_jll unavailable on this platform — integration tests skipped"
    end
end
