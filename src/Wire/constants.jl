# XRootD protocol constants. Names are kept verbatim from the protocol
# vocabulary (nginx-xrootd src/protocol/opcodes.h + flags.h) so every value
# is greppable against the C reference; this deliberately departs from Julia
# naming style.

#! format: off

# ---- request opcodes (ClientRequestHdr.requestid) ----
const kXR_auth      = UInt16(3000)
const kXR_query     = UInt16(3001)
const kXR_chmod     = UInt16(3002)
const kXR_close     = UInt16(3003)
const kXR_dirlist   = UInt16(3004)
const kXR_gpfile    = UInt16(3005)
const kXR_protocol  = UInt16(3006)
const kXR_login     = UInt16(3007)
const kXR_mkdir     = UInt16(3008)
const kXR_mv        = UInt16(3009)
const kXR_open      = UInt16(3010)
const kXR_ping      = UInt16(3011)
const kXR_chkpoint  = UInt16(3012)
const kXR_read      = UInt16(3013)
const kXR_rm        = UInt16(3014)
const kXR_rmdir     = UInt16(3015)
const kXR_sync      = UInt16(3016)
const kXR_stat      = UInt16(3017)
const kXR_set       = UInt16(3018)
const kXR_write     = UInt16(3019)
const kXR_fattr     = UInt16(3020)
const kXR_prepare   = UInt16(3021)
const kXR_statx     = UInt16(3022)
const kXR_endsess   = UInt16(3023)
const kXR_bind      = UInt16(3024)
const kXR_readv     = UInt16(3025)
const kXR_pgwrite   = UInt16(3026)
const kXR_locate    = UInt16(3027)
const kXR_truncate  = UInt16(3028)
const kXR_sigver    = UInt16(3029)
const kXR_pgread    = UInt16(3030)
const kXR_writev    = UInt16(3031)
const kXR_clone     = UInt16(3032)

# ---- nginx-xrootd vendor extensions (capability-negotiated via
# kXR_Qconfig "xrdfs.ext"; never sent to stock servers) ----
const kXR_setattr   = UInt16(3500)
const kXR_symlink   = UInt16(3501)
const kXR_readlink  = UInt16(3502)
const kXR_link      = UInt16(3503)

# ---- response status (ServerResponseHdr.status) ----
const kXR_ok        = UInt16(0)
const kXR_oksofar   = UInt16(4000)
const kXR_attn      = UInt16(4001)
const kXR_authmore  = UInt16(4002)
const kXR_error     = UInt16(4003)
const kXR_redirect  = UInt16(4004)
const kXR_wait      = UInt16(4005)
const kXR_waitresp  = UInt16(4006)
const kXR_status    = UInt16(4007)

# ---- kXR_attn action codes (still-active subset) ----
const kXR_asyncms   = UInt32(5002)
const kXR_asynresp  = UInt32(5008)

# ---- kXR_protocol response flags (server type + TLS negotiation) ----
const kXR_haveTLS  = UInt32(0x80000000)  # server accepts in-protocol TLS upgrade
const kXR_gotoTLS  = UInt32(0x40000000)  # client must upgrade immediately
const kXR_tlsLogin = UInt32(0x04000000)  # the login exchange requires TLS

# ---- handshake / kXR_protocol ----
const ROOTD_PQ             = UInt32(2012)        # 5th word of the client hello
const kXR_PROTOCOLVERSION  = UInt32(0x00000520)  # protocol 5.2.0
const kXR_secreqs  = 0x01  # request the server's security-protocol trailer
const kXR_ableTLS  = 0x02  # client can upgrade to in-protocol TLS
const kXR_wantTLS  = 0x04  # client requires TLS - abort if unavailable
const kXR_ExpLogin = 0x03  # "a kXR_login follows"

# ---- kXR_login capver ----
const kXR_asyncap = 0x80   # client handles asynchronous responses
const kXR_ver005  = 0x05   # XRootD v5 client (TLS + sigver capable)

const SESSION_ID_LEN = 16  # opaque sessid bytes in the login response

# ---- kXR_dirlist options ----
const kXR_online = 0x01
const kXR_dstat  = 0x02
const kXR_dcksm  = 0x04

# ---- kXR_stat options ----
const kXR_vfs = 0x01

# ---- kXR_open options (u16; flags.h) ----
const kXR_compress  = UInt16(0x0001)
const kXR_delete    = UInt16(0x0002)  # open for write, truncate to zero
const kXR_force     = UInt16(0x0004)
const kXR_new       = UInt16(0x0008)  # fail if the file exists
const kXR_open_read = UInt16(0x0010)
const kXR_open_updt = UInt16(0x0020)  # O_RDWR
const kXR_refresh   = UInt16(0x0080)
const kXR_mkpath    = UInt16(0x0100)  # create parent directories
const kXR_open_apnd = UInt16(0x0200)
const kXR_retstat   = UInt16(0x0400)  # return stat info with the open reply
const kXR_open_wrto = UInt16(0x8000)  # write-only

# ---- kXR_mkdir options byte ----
const kXR_mkdirpath = 0x01

# ---- kXR_query infotype (XQueryType; opcodes.h) ----
const kXR_QStats  = UInt16(1)
const kXR_QPrep   = UInt16(2)
const kXR_Qcksum  = UInt16(3)
const kXR_Qxattr  = UInt16(4)
const kXR_Qspace  = UInt16(5)
const kXR_Qconfig = UInt16(7)
const kXR_Qvisa   = UInt16(8)
const kXR_Qopaque = UInt16(16)
const kXR_Qopaquf = UInt16(32)
const kXR_Qopaqug = UInt16(64)

# ---- kXR_writev options byte ----
const kXR_wv_doSync = 0x01   # fsync each touched handle after the write

# ---- kXR_sigver (flags.h) ----
const kXR_SHA256_sig = 0x01  # HMAC algorithm is HMAC-SHA256
const kXR_nodata_sig = 0x01  # payload NOT included in the HMAC

# ---- kXR_fattr subcodes + options (opcodes.h / flags.h) ----
const kXR_fattrDel  = 0x00
const kXR_fattrGet  = 0x01
const kXR_fattrList = 0x02
const kXR_fattrSet  = 0x03
const kXR_fa_isNew  = 0x01   # (set) fail if the attribute already exists
const kXR_fa_aData  = 0x10   # (list) include values in the response

# ---- kXR_prepare options byte (flags.h) ----
const kXR_cancel = 0x01
const kXR_notify = 0x02
const kXR_noerrs = 0x04
const kXR_stage  = 0x08
const kXR_wmode  = 0x10

# ---- kXR_setattr (vendor ext) ----
const kXR_sa_times = Int32(0x01)   # apply atime/mtime
const kXR_sa_owner = Int32(0x02)   # apply uid/gid
const SETATTR_PREFIX_LEN = 44

# ---- paged I/O (kXR_pgread / kXR_pgwrite; ops_file_pg.c) ----
const kXR_pgPageSZ      = 4096   # page size; CRC32c per page
const kXR_pgRetry       = 0x01   # pgwrite reqflags: resend of a corrupt page
const kXR_FinalResult   = 0x00   # kXR_status resptype: last frame
const kXR_PartialResult = 0x01   # kXR_status resptype: more frames follow
const STATUS_BODY_LEN   = 24     # kXR_status body: crc[4] sid[2] reqid[1]
                                 # resptype[1] rsvd[4] dlen[4] offset[8]
const PGW_CSE_HDRLEN    = 8      # pgwrite CSE trailer: cseCRC[4] dlFirst[2] dlLast[2]
const PGW_MAX_RETRY     = 3      # kXR_pgRetry attempts per corrupt page

# ---- client-side I/O caps (libxrdc brix_ops.h / brix.h) ----
# A response is untrusted input: every accumulating read bounds what it will
# buffer, so a server that keeps sending kXR_oksofar cannot grow the client's
# heap without limit.
const VEC_MAXSEGS  = 1024                # readv/writev segment count cap
const VEC_MAXBYTES = 256 * 1024 * 1024   # aggregate readv/writev payload cap
const DLEN_MAX     = 64 * 1024 * 1024    # sanity cap on one response body

# ---- stat flags bitfield (flags.h; StatInfo.flags) ----
const kXR_xset     = UInt32(0x01)  # executable / searchable
const kXR_isDir    = UInt32(0x02)
const kXR_other    = UInt32(0x04)  # neither regular file nor directory
const kXR_offline  = UInt32(0x08)
const kXR_readable = UInt32(0x10)
const kXR_writable = UInt32(0x20)
const kXR_poscpend = UInt32(0x40)

#! format: on

const _REQUEST_NAMES = Dict{UInt16,String}(
    kXR_auth => "kXR_auth",
    kXR_query => "kXR_query",
    kXR_chmod => "kXR_chmod",
    kXR_close => "kXR_close",
    kXR_dirlist => "kXR_dirlist",
    kXR_gpfile => "kXR_gpfile",
    kXR_protocol => "kXR_protocol",
    kXR_login => "kXR_login",
    kXR_mkdir => "kXR_mkdir",
    kXR_mv => "kXR_mv",
    kXR_open => "kXR_open",
    kXR_ping => "kXR_ping",
    kXR_chkpoint => "kXR_chkpoint",
    kXR_read => "kXR_read",
    kXR_rm => "kXR_rm",
    kXR_rmdir => "kXR_rmdir",
    kXR_sync => "kXR_sync",
    kXR_stat => "kXR_stat",
    kXR_set => "kXR_set",
    kXR_write => "kXR_write",
    kXR_fattr => "kXR_fattr",
    kXR_prepare => "kXR_prepare",
    kXR_statx => "kXR_statx",
    kXR_endsess => "kXR_endsess",
    kXR_bind => "kXR_bind",
    kXR_readv => "kXR_readv",
    kXR_pgwrite => "kXR_pgwrite",
    kXR_locate => "kXR_locate",
    kXR_truncate => "kXR_truncate",
    kXR_sigver => "kXR_sigver",
    kXR_pgread => "kXR_pgread",
    kXR_writev => "kXR_writev",
    kXR_clone => "kXR_clone",
    kXR_setattr => "kXR_setattr",
    kXR_symlink => "kXR_symlink",
    kXR_readlink => "kXR_readlink",
    kXR_link => "kXR_link",
)

"""
    request_name(id::Integer) -> String

The protocol name of a request opcode (`3017` → `"kXR_stat"`), for traces and
error messages. Unknown ids render as `"kXR_unknown(id)"`. Mirrors libxrdc's
`xrdc_reqid_name`.
"""
function request_name(id::Integer)
    return get(_REQUEST_NAMES, UInt16(id), "kXR_unknown($(Int(id)))")
end
