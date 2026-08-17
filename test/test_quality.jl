using Aqua
using JET

@testset "quality" begin
    @testset "Aqua" begin
        # persistent_tasks precompiles a dummy dependent package in a fresh
        # depot, which re-runs Reseau's precompile workload — and that does a
        # TLS handshake with Reseau's test/resources/unittests.crt, expired
        # 2026-08-06. Until a Reseau release regenerates the certificate,
        # the check cannot pass from a cold cache anywhere, CI included.
        Aqua.test_all(XRootD; persistent_tasks=false)
    end
    @testset "JET" begin
        JET.test_package(XRootD; target_defined_modules=true)
    end
end
