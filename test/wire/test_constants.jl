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

using XRootD: Wire
using XRootD.Wire:
    NULL_FHANDLE,
    kXR_attrMeta,
    kXR_attrProxy,
    kXR_attrSuper,
    kXR_bkpexist,
    kXR_ckpBegin,
    kXR_ckpCommit,
    kXR_ckpQuery,
    kXR_ckpRollback,
    kXR_ckpXeq,
    kXR_endsess,
    kXR_evict,
    kXR_file,
    kXR_isDir,
    kXR_isManager,
    kXR_isServer,
    kXR_offline,
    kXR_other,
    kXR_poscpend,
    kXR_readable,
    kXR_statx,
    kXR_tlsDemands,
    kXR_usetcp,
    kXR_writable,
    kXR_xset

@testset "Wire constants beyond 0.2.x" begin
    @test kXR_statx === UInt16(3022)
    @test kXR_endsess === UInt16(3023)

    # A plain file is the absence of every type bit rather than a bit of
    # its own, so the flags word must be read by masking, not compared.
    @test kXR_file === UInt32(0x00)
    @test kXR_xset === UInt32(0x01)
    @test kXR_isDir === UInt32(0x02)
    @test kXR_other === UInt32(0x04)
    @test kXR_offline === UInt32(0x08)
    @test kXR_readable | kXR_writable === UInt32(0x30)
    @test kXR_poscpend === UInt32(0x40)
    @test kXR_bkpexist === UInt32(0x80)

    @test kXR_ckpBegin === 0x00
    @test kXR_ckpCommit === 0x01
    @test kXR_ckpQuery === 0x02
    @test kXR_ckpRollback === 0x03
    @test kXR_ckpXeq === 0x04

    # kXR_evict rides in the prepare request's optionX half-word, which is why
    # it can hold 0x0001 while the options byte's 0x01 means kXR_cancel — and
    # why it is not the 0x80 that byte spends on kXR_usetcp.
    @test kXR_evict === UInt16(0x0001)
    @test kXR_usetcp === 0x80

    # The kXR_protocol reply's role and attribute bits share a word with the
    # TLS demands, and sit well clear of them.
    @test kXR_isServer === UInt32(0x00000001)
    @test kXR_isManager === UInt32(0x00000002)
    @test kXR_attrMeta === UInt32(0x00000100)
    @test kXR_attrProxy === UInt32(0x00000200)
    @test kXR_attrSuper === UInt32(0x00000400)
    @test (kXR_isServer | kXR_isManager) & kXR_tlsDemands === UInt32(0)

    @test NULL_FHANDLE === (0x00, 0x00, 0x00, 0x00)

    # Server error codes are their own enumeration: they share the 3000-range
    # with the request opcodes without sharing meaning, so the two name
    # lookups must not be interchanged.
    @test Wire.error_name(3011) == "kXR_NotFound"
    @test Wire.error_name(3018) == "kXR_ItExists"
    @test Wire.error_name(3003) == "kXR_FileLocked"
    @test Wire.error_name(3022) == "kXR_error(3022)"   # unassigned, though kXR_statx
    @test request_name(3011) == "kXR_ping"        # ... and 3011 is an opcode
    @test Wire.error_name(0) == "kXR_error(0)"
end
