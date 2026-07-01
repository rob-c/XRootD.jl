using XRootD.Wire:
    kXR_auth,
    kXR_query,
    kXR_dirlist,
    kXR_protocol,
    kXR_login,
    kXR_ping,
    kXR_stat,
    kXR_clone,
    kXR_setattr,
    kXR_link,
    kXR_ok,
    kXR_oksofar,
    kXR_error,
    kXR_redirect,
    kXR_wait,
    kXR_status,
    ROOTD_PQ,
    kXR_PROTOCOLVERSION,
    kXR_secreqs,
    kXR_ableTLS,
    kXR_wantTLS,
    kXR_ExpLogin,
    kXR_asyncap,
    kXR_ver005,
    kXR_dstat,
    kXR_vfs,
    SESSION_ID_LEN,
    request_name

@testset "Wire constants" begin
    # spot-check against nginx-xrootd src/protocol/opcodes.h
    @test kXR_auth === UInt16(3000)
    @test kXR_dirlist === UInt16(3004)
    @test kXR_protocol === UInt16(3006)
    @test kXR_login === UInt16(3007)
    @test kXR_ping === UInt16(3011)
    @test kXR_stat === UInt16(3017)
    @test kXR_clone === UInt16(3032)
    @test kXR_setattr === UInt16(3500)   # nginx-xrootd vendor extension
    @test kXR_link === UInt16(3503)

    @test kXR_ok === UInt16(0)
    @test kXR_oksofar === UInt16(4000)
    @test kXR_error === UInt16(4003)
    @test kXR_redirect === UInt16(4004)
    @test kXR_wait === UInt16(4005)
    @test kXR_status === UInt16(4007)

    @test ROOTD_PQ === UInt32(2012)
    @test kXR_PROTOCOLVERSION === UInt32(0x00000520)
    @test kXR_secreqs | kXR_ableTLS === 0x03
    @test kXR_wantTLS === 0x04
    @test kXR_ExpLogin === 0x03
    @test kXR_asyncap | kXR_ver005 === 0x85
    @test kXR_dstat === 0x02
    @test kXR_vfs === 0x01
    @test SESSION_ID_LEN == 16

    @test request_name(3017) == "kXR_stat"
    @test request_name(3501) == "kXR_symlink"
    @test request_name(42) == "kXR_unknown(42)"
end
