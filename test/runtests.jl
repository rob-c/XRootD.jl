using Test
using XRootD
using Sockets: Sockets
using XRootD_jll: XRootD_jll

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
    include("session/test_connection.jl")
    include("session/test_auth.jl")
    include("session/test_resilience.jl")
    include("client/test_types.jl")
    include("client/test_file.jl")
    include("conformance/server.jl")
    include("conformance/test_rw.jl")
    include("conformance/test_failclosed.jl")
    include("conformance/test_scale.jl")
    include("storage/test_storage.jl")
    include("tools/test_tools.jl")
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
