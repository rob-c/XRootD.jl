# roots:// TLS integration: a second xrootd instance configured with a
# self-signed certificate; the client upgrades in-protocol and runs plain
# FileSystem ops over the encrypted session.

using XRootD.XrdCl
using XRootD: Session

@testset "roots:// TLS" begin
    dir = mktempdir()
    cert = joinpath(dir, "cert.pem")
    key = joinpath(dir, "key.pem")
    run(
        pipeline(
            `openssl req -x509 -newkey rsa:2048 -keyout $key -out $cert -days 1
             -nodes -subj "/CN=localhost"`;
            stdout=devnull,
            stderr=devnull,
        ),
    )

    cfg = joinpath(dir, "xrootd_tls.cfg")
    write(
        cfg,
        """
        xrd.port 10944
        xrd.tls $cert $key
        xrd.tlsca noverify
        """,
    )
    tls_server = run(`$(XRootD_jll.xrootd()) -c $cfg`; wait=false)
    try
        @test wait_for_server(10944)

        fs = FileSystem("roots://localhost:10944"; insecure_tls=true)
        st, _ = ping(fs)
        @test isOK(st)
        st, si = stat(fs, "/tmp")
        @test isOK(st)
        @test isdir(si)

        # a File round trip over TLS
        write("/tmp/tls_testfile", "encrypted hello")
        # File() does not take TLS kwargs yet; use the FileSystem copy path
        st, _ = copy(fs, "/tmp/tls_testfile", "/tmp/tls_testfile2"; force=true)
        @test isOK(st)
        @test read("/tmp/tls_testfile2", String) == "encrypted hello"
        foreach(rm, ("/tmp/tls_testfile", "/tmp/tls_testfile2"))

        # want_tls against a non-TLS server fails with a clear error
        @test_throws ErrorException Session.connect("localhost", 1094; want_tls=true)
    finally
        kill(tls_server)
    end
end
