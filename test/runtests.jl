using Test
using XRootD

@testset verbose = true "XRootD.jl" begin
    @testset "package smoke" begin
        @test isdefined(XRootD, :Wire)
    end
    include("wire/test_primitives.jl")
    include("wire/test_constants.jl")
end
