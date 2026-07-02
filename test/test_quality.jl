using Aqua
using JET

@testset "quality" begin
    @testset "Aqua" begin
        Aqua.test_all(XRootD)
    end
    @testset "JET" begin
        JET.test_package(XRootD; target_defined_modules=true)
    end
end
