# A server that exercises the security exchange: the `kXR_login` security
# trailer that asks for a credential, the `kXR_auth` round that answers it,
# and the `kXR_sigver` prefix a high-security server requires in front of a
# mutating request.
#
# None of this is visible from a session that came up: a client that skipped
# authentication and a client that authenticated correctly both end with a
# `ready` connection. What distinguishes them is the frame in between, so the
# server records every credential it is offered and verifies every signature
# itself, from the key and the request bytes, rather than trusting the
# client's encoders.

using Sockets
using SHA: hmac_sha256
using XRootD: Wire, Session

const AUTH_NotAuthorized = 3010   # XErrorCode kXR_NotAuthorized

# The opcodes a sec_level ≥ 2 server insists on seeing signed, listed here
# rather than read from the client so the two sides can disagree.
const AUTH_SIGNED_OPS = Set{UInt16}([
    Wire.kXR_open,
    Wire.kXR_write,
    Wire.kXR_writev,
    Wire.kXR_pgwrite,
    Wire.kXR_truncate,
    Wire.kXR_rm,
    Wire.kXR_rmdir,
    Wire.kXR_mkdir,
    Wire.kXR_mv,
    Wire.kXR_chmod,
    Wire.kXR_fattr,
    Wire.kXR_set,
    Wire.kXR_prepare,
])

"""
A server for the security exchange.

`sec` is the trailer appended to the `kXR_login` reply — `"&P=ztn,v:10400&P=unix"`
and friends — which is how a server states what it will accept. `auth_status`
is the status the `kXR_auth` round is answered with, so a test can reject a
credential the way a real server does.

`signing_key`, when set, makes the server verify a `kXR_sigver` prefix in
front of every mutating request and flag one that is missing or wrong.

`creds` records each `(credtype, credential)` offered, `signed` the opcodes
that arrived signed, and `ops` every request seen after login.
"""
Base.@kwdef mutable struct AuthServer
    sec::String = ""
    auth_status::UInt16 = Wire.kXR_ok
    auth_message::String = "credential rejected"
    signing_key::Union{Vector{UInt8},Nothing} = nothing
    violations::Vector{String} = String[]
    logins::Vector{String} = String[]
    creds::Vector{Tuple{String,Vector{UInt8}}} = Tuple{String,Vector{UInt8}}[]
    ops::Vector{UInt16} = UInt16[]
    signed::Vector{UInt16} = UInt16[]
    seqnos::Vector{UInt64} = UInt64[]
    conns::Int = 0
end

flag!(s::AuthServer, msg::AbstractString) = push!(s.violations, String(msg))

"The `kXR_login` reply: 16-byte session id, then the security trailer."
function auth_login_body(s::AuthServer)
    return vcat(UInt8.(1:16), Vector{UInt8}(codeunits(s.sec)))
end

"""
Check the `kXR_sigver` prefix `sig` against the request `frame`/`payload` it
covers, the way a server does: recompute the HMAC from the key and the bytes
that arrived, and require the sequence number to advance.
"""
function auth_check_sigver(s::AuthServer, sig, frame, payload)
    key = something(s.signing_key)
    expect = Wire.get_u16(sig, 5)
    reqid = Wire.get_u16(frame, 3)
    expect == reqid || flag!(s, "kXR_sigver: covers $(expect), next request is $(reqid)")
    sig[7] == 0x00 || flag!(s, "kXR_sigver: version byte is $(sig[7]), not 0")
    sig[17] == Wire.kXR_SHA256_sig ||
        flag!(s, "kXR_sigver: crypto byte is $(sig[17]), not HMAC-SHA256")
    Wire.get_u16(sig, 1) == Wire.get_u16(frame, 1) ||
        flag!(s, "kXR_sigver: streamid differs from the request it signs")

    seqno = Wire.get_u64(sig, 9)
    isempty(s.seqnos) ||
        seqno > s.seqnos[end] ||
        flag!(s, "kXR_sigver: seqno $(seqno) did not advance past $(s.seqnos[end])")
    push!(s.seqnos, seqno)

    mac = sig[25:end]
    length(mac) == 32 || flag!(s, "kXR_sigver: hmac is $(length(mac)) bytes, not 32")
    seqbytes = UInt8[(seqno >> (8 * (7 - i))) % UInt8 for i in 0:7]
    msg = vcat(seqbytes, frame[1:24], payload)
    hmac_sha256(key, msg) == mac || flag!(s, "kXR_sigver: hmac does not verify")
    push!(s.signed, reqid)
    return nothing
end

"Answer the one `kXR_auth` round: record the credential, then accept or refuse."
function auth_serve_auth(s::AuthServer, sock, frame, payload)
    credtype = String(rstrip(String(copy(frame[17:20])), '\0'))
    all(iszero, frame[5:16]) || flag!(s, "kXR_auth: reserved bytes are not zero")
    push!(s.creds, (credtype, Vector{UInt8}(payload)))
    sid = Wire.get_u16(frame, 1)
    if s.auth_status == Wire.kXR_ok
        cs_ok(sock, sid)
    elseif s.auth_status == Wire.kXR_error
        cs_error(sock, sid, AUTH_NotAuthorized, s.auth_message)
    else
        write(sock, vcat(cs_hdr(sid, s.auth_status, 4), cs_be32(1)))
    end
    return nothing
end

function auth_serve_conn(s::AuthServer, sock)
    try
        hello = read(sock, 20)
        length(hello) == 20 || throw(EOFError())
        Wire.get_u32(hello, 17) == Wire.ROOTD_PQ ||
            flag!(s, "handshake: bad protocol token")
        write(sock, vcat(cs_hdr(0x0000, Wire.kXR_ok, 8), cs_be32(0x310), cs_be32(1)))

        pf, _ = cs_take(sock)
        Wire.get_u16(pf, 3) == Wire.kXR_protocol ||
            flag!(s, "bring-up: expected kXR_protocol")
        (pf[9] & Wire.kXR_secreqs) == 0 &&
            flag!(s, "kXR_protocol: client did not ask for the security trailer")
        write(
            sock,
            vcat(cs_hdr(Wire.get_u16(pf, 1), Wire.kXR_ok, 8), cs_be32(0x520), cs_be32(1)),
        )

        lf, _ = cs_take(sock)
        Wire.get_u16(lf, 3) == Wire.kXR_login || flag!(s, "bring-up: expected kXR_login")
        push!(s.logins, String(rstrip(String(copy(lf[9:16])), '\0')))
        body = auth_login_body(s)
        write(sock, vcat(cs_hdr(Wire.get_u16(lf, 1), Wire.kXR_ok, length(body)), body))

        pending = nothing   # a kXR_sigver frame waiting for what it signs
        while true
            frame, payload = cs_take(sock)
            reqid = Wire.get_u16(frame, 3)
            sid = Wire.get_u16(frame, 1)
            if reqid == Wire.kXR_sigver
                pending === nothing || flag!(s, "kXR_sigver: two prefixes in a row")
                s.signing_key === nothing &&
                    flag!(s, "kXR_sigver: signed on a connection that requires no signing")
                pending = vcat(frame, payload)
                continue
            end
            push!(s.ops, reqid)
            if s.signing_key !== nothing
                if pending !== nothing
                    auth_check_sigver(s, pending, frame, payload)
                elseif reqid in AUTH_SIGNED_OPS
                    flag!(s, "$(Wire.request_name(reqid)) arrived unsigned")
                end
            end
            pending = nothing
            if reqid == Wire.kXR_auth
                auth_serve_auth(s, sock, frame, payload)
            else
                cs_ok(sock, sid)
            end
        end
    catch
        # the client hanging up ends the connection, which several tests want
    finally
        isopen(sock) && close(sock)
    end
    return nothing
end

"Start a security-exchange server; returns (srv, port). Keywords set [`AuthServer`](@ref)."
function start_auth_server(; kwargs...)
    s = AuthServer(; kwargs...)
    listener = listen(ip"127.0.0.1", 0)
    _, port = getsockname(listener)
    @async while isopen(listener)
        local sock
        try
            sock = accept(listener)
        catch
            break
        end
        s.conns += 1
        @async auth_serve_conn(s, sock)
    end
    return s, Int(port)
end

"""
Bring a session up against an [`AuthServer`](@ref), returning `(conn, err)`:
a credential the server refuses fails the bring-up, and the failure is the
result the test is after.

`prompter` answers any credential the client cannot find; the default declines
every request, so a test that means to authenticate anonymously does so
whether or not a terminal happens to be attached. Nothing is remembered
between bring-ups.
"""
function auth_bringup(port::Int; prompter=(_ -> nothing), kwargs...)
    previous = Session.prompt_credentials!(prompter)
    Session.forget_credentials!()
    try
        conn = try
            Session.connect("127.0.0.1", port; x509=false, kwargs...)
        catch err
            return nothing, err
        end
        return conn, nothing
    finally
        Session.prompt_credentials!(previous)
        Session.forget_credentials!()
    end
end

"""
An environment with no ambient bearer token: `discover_token` walks
`\$BEARER_TOKEN`, `\$BEARER_TOKEN_FILE`, `\$XDG_RUNTIME_DIR/bt_u<uid>` and
`/tmp/bt_u<uid>`, and a token left in any of them by the machine running the
tests would decide the answer instead of the test.
"""
function without_token(f)
    return mktempdir() do empty_dir
        return withenv(
            f,
            "BEARER_TOKEN" => nothing,
            "BEARER_TOKEN_FILE" => joinpath(empty_dir, "absent"),
            "XDG_RUNTIME_DIR" => empty_dir,
        )
    end
end

"Write a one-key SSS keytab and hand its path to `f`."
function with_keytab(f; id::Int=42, key::String="00112233445566778899aabbccddeeff")
    return mktempdir() do dir
        path = joinpath(dir, "sss.keytab")
        write(path, "0 u:tester g:staff N:$id k:$key\n")
        return f(path)
    end
end
