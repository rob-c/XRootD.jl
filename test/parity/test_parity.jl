# The cross-implementation parity suite: the same scenarios through
# XRootD.jl, libxrdc, and the official client, asserting identical observable
# behavior and cross-client interoperability. Runs inside the integration
# block (a live XRootD_jll server is already up).

const Xrdcp = XRootD.Tools.Xrdcp
using XRootD.Tools: checksum_file

@testset "cross-implementation parity" begin
    data = rand(UInt8, 8192)
    write("/tmp/parity_src", data)

    @testset "checksum parity vs libxrdc" begin
        if libxrdc_available()
            for (tool, algo) in
                [("xrdadler32", :adler32), ("xrdcrc32c", :crc32c), ("xrdcrc64", :crc64)]
                ref, rc = run_libxrdc(tool, ["/tmp/parity_src"])
                @test rc == 0
                @test checksum_file("/tmp/parity_src", algo) == first_token(ref)
            end
        else
            @info "libxrdc binaries not found; checksum parity skipped"
        end
    end

    @testset "data-movement interop (XRootD.jl → server → official client)" begin
        # XRootD.jl writes the file to the server...
        remote = "root://localhost:1094//tmp/parity_remote"
        @test Xrdcp.main(["-f", "/tmp/parity_src", remote]) == 0
        @test read("/tmp/parity_remote") == data      # bytes landed intact

        # ...and the official xrdcp reads it back identically.
        out, rc = run_official(:xrdcp, ["-f", remote, "/tmp/parity_official_back"])
        @test rc == 0
        @test read("/tmp/parity_official_back") == data
    end

    @testset "data-movement interop (official client → server → XRootD.jl)" begin
        # The official xrdcp writes...
        remote = "root://localhost:1094//tmp/parity_official_up"
        _, rc = run_official(:xrdcp, ["-f", "/tmp/parity_src", remote])
        @test rc == 0
        # ...and XRootD.jl reads it back identically.
        @test Xrdcp.main(["-f", remote, "/tmp/parity_jl_back"]) == 0
        @test read("/tmp/parity_jl_back") == data
    end

    @testset "libxrdc → server → XRootD.jl interop" begin
        if libxrdc_available()
            remote = "root://localhost:1094//tmp/parity_libxrdc_up"
            _, rc = run_libxrdc("xrdcp", ["-f", "/tmp/parity_src", remote])
            @test rc == 0
            @test Xrdcp.main(["-f", remote, "/tmp/parity_libxrdc_back"]) == 0
            @test read("/tmp/parity_libxrdc_back") == data
        else
            @info "libxrdc binaries not found; libxrdc interop skipped"
        end
    end

    foreach(
        p -> isfile(p) && rm(p),
        (
            "/tmp/parity_src",
            "/tmp/parity_remote",
            "/tmp/parity_official_back",
            "/tmp/parity_official_up",
            "/tmp/parity_jl_back",
            "/tmp/parity_libxrdc_up",
            "/tmp/parity_libxrdc_back",
        ),
    )
end
