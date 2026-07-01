using Test
using XRootD

@testset verbose = true "XRootD.jl" begin
    @testset "package smoke" begin
        @test isdefined(XRootD, :Wire)
    end
end
