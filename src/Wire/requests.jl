# Concrete request codecs. Field layouts: nginx-xrootd wire_core_requests.h;
# default flag/capability values: bootstrap_pack.h (the exact bytes libxrdc
# sends during connection bring-up).

"""
    ProtocolRequest(; flags::UInt8 = kXR_secreqs | kXR_ableTLS)

`kXR_protocol` — the first request after the handshake. Announces the client
protocol version (`kXR_PROTOCOLVERSION`), capability `flags` (pass
`kXR_secreqs | kXR_ableTLS | kXR_wantTLS` to require TLS), and that a login
follows (`kXR_ExpLogin`).
"""
struct ProtocolRequest <: Request
    clientpv::UInt32
    flags::UInt8
    expect::UInt8
end

function ProtocolRequest(; flags::UInt8=kXR_secreqs | kXR_ableTLS)
    return ProtocolRequest(kXR_PROTOCOLVERSION, flags, kXR_ExpLogin)
end

requestid(::ProtocolRequest) = kXR_protocol

function body!(frame::Vector{UInt8}, r::ProtocolRequest)
    set_u32!(frame, 5, r.clientpv)
    frame[9] = r.flags
    frame[10] = r.expect
    return frame
end

"""
    LoginRequest(username::AbstractString;
                 pid::Integer = getpid(),
                 capver::UInt8 = kXR_ver005 | kXR_asyncap)

`kXR_login` — starts the session. `username` is NUL-padded/truncated into the
8-byte wire field; `pid` is informational; `capver` advertises a v5,
async-capable client. `dlen = 0` (anonymous — credentials go in a subsequent
`kXR_auth`).
"""
struct LoginRequest <: Request
    username::String
    pid::Int32
    capver::UInt8
end

function LoginRequest(
    username::AbstractString; pid::Integer=getpid(), capver::UInt8=kXR_ver005 | kXR_asyncap
)
    return LoginRequest(String(username), Int32(pid), capver)
end

requestid(::LoginRequest) = kXR_login

function body!(frame::Vector{UInt8}, r::LoginRequest)
    set_u32!(frame, 5, reinterpret(UInt32, r.pid))
    set_padded_string!(frame, 9, 8, r.username)
    frame[19] = r.capver   # bytes 17 (ability2), 18 (ability), 20 (rsvd) stay 0
    return frame
end

"""
    AuthRequest(credtype::AbstractString, cred::Vector{UInt8})

`kXR_auth` — answers a `kXR_authmore`/security requirement with a credential.
`credtype` is the 4-byte protocol tag (`"unix"`, `"ztn"`, `"sss"`); `cred` is
the raw credential payload (e.g. the JWT bytes for ztn).
"""
struct AuthRequest <: Request
    credtype::String
    cred::Vector{UInt8}

    function AuthRequest(credtype::AbstractString, cred::Vector{UInt8})
        if ncodeunits(credtype) > 4
            throw(ArgumentError("credtype must be ≤ 4 bytes, got $(repr(credtype))"))
        end
        return new(String(credtype), cred)
    end
end

requestid(::AuthRequest) = kXR_auth

function body!(frame::Vector{UInt8}, r::AuthRequest)
    set_padded_string!(frame, 17, 4, r.credtype)   # bytes 5:16 reserved
    return frame
end

payload(r::AuthRequest) = r.cred

"""
    PingRequest()

`kXR_ping` — liveness probe; empty body, empty payload.
"""
struct PingRequest <: Request end

requestid(::PingRequest) = kXR_ping

"""
    StatRequest(path::AbstractString;
                options::UInt8 = 0x00,
                fhandle::NTuple{4,UInt8} = (0x00, 0x00, 0x00, 0x00))

`kXR_stat` — stat a path (the usual case) or an open file handle (empty
`path` + real `fhandle`). `options = kXR_vfs` requests virtual-filesystem
(statvfs) information instead. The response body is the ASCII stat line
`"<id> <size> <flags> <mtime>"` (see [`parse_stat_line`](@ref)).
"""
struct StatRequest <: Request
    path::String
    options::UInt8
    fhandle::NTuple{4,UInt8}
end

function StatRequest(
    path::AbstractString;
    options::UInt8=0x00,
    fhandle::NTuple{4,UInt8}=(0x00, 0x00, 0x00, 0x00),
)
    return StatRequest(String(path), options, fhandle)
end

requestid(::StatRequest) = kXR_stat

function body!(frame::Vector{UInt8}, r::StatRequest)
    frame[5] = r.options                       # bytes 6:16 reserved (zero)
    set_bytes!(frame, 17, collect(r.fhandle))
    return frame
end

payload(r::StatRequest) = codeunits(r.path)

"""
    DirlistRequest(path::AbstractString; options::UInt8 = kXR_dstat)

`kXR_dirlist` — list a directory. The default `kXR_dstat` asks for per-entry
stat lines (the server then prepends the `".\\n0 0 0 0\\n"` sentinel — see
[`parse_dirlist`](@ref)). Large listings arrive chunked via `kXR_oksofar`;
accumulating chunks is the Session layer's job.
"""
struct DirlistRequest <: Request
    path::String
    options::UInt8
end

function DirlistRequest(path::AbstractString; options::UInt8=kXR_dstat)
    return DirlistRequest(String(path), options)
end

requestid(::DirlistRequest) = kXR_dirlist

function body!(frame::Vector{UInt8}, r::DirlistRequest)
    frame[20] = r.options   # body bytes 1:15 reserved; options is byte 16
    return frame
end

payload(r::DirlistRequest) = codeunits(r.path)
