using Test
using XRootD

@testset verbose = true "XRootD.jl" begin
    @testset "package smoke" begin
        @test isdefined(XRootD, :Wire)
    end
    include("wire/test_primitives.jl")
    include("wire/test_constants.jl")
    include("wire/test_frames.jl")
    include("wire/test_requests.jl")
    include("wire/test_responses.jl")
    include("session/test_connection.jl")
    include("client/test_types.jl")
    include("test_quality.jl")
end
