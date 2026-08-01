# A server that only negotiates. It brings a connection as far as the
# `kXR_protocol` reply, answers with whatever TLS flags the test asked for,
# and then records what the client did next: opened a TLS handshake, sent a
# cleartext `kXR_login`, or went away.
#
# That one decision is the whole of the client's TLS policy, and it is not
# observable from a working session — a session that reached `ready` says
# nothing about whether it *should* have upgraded first. Watching the first
# byte after the protocol reply says it exactly: a TLS record begins 0x16,
# and a request frame begins with the high half of a streamid, which is 0x00.

using Sockets
using XRootD: Wire, Session

"""
A bring-up-only server. `flags` is the word it puts in the `kXR_protocol`
reply, which is where a real server advertises `kXR_haveTLS` and demands an
upgrade with `kXR_gotoTLS`, `kXR_tlsLogin` or `kXR_tlsSess`.

`asked` records the capability byte from each client `kXR_protocol` request,
and `next` what followed the reply — `"tls"`, `"login"` or `"gone"`.
"""
Base.@kwdef mutable struct TlsServer
    flags::UInt32 = UInt32(1)             # kXR_isServer, no TLS advertised
    violations::Vector{String} = String[]
    logins::Vector{String} = String[]
    asked::Vector{UInt8} = UInt8[]
    next::Vector{String} = String[]
    conns::Int = 0
end

flag!(s::TlsServer, msg::AbstractString) = push!(s.violations, String(msg))

"What the client did after the protocol reply, from its first byte."
function tls_next_move(sock)
    lead = read(sock, 1)
    isempty(lead) && return "gone", UInt8[]
    lead[1] == 0x16 && return "tls", lead
    rest = read(sock, 23)
    length(rest) == 23 || return "gone", lead
    return "login", vcat(lead, rest)
end

function tls_serve_conn(s::TlsServer, sock)
    try
        hello = read(sock, 20)
        length(hello) == 20 || throw(EOFError())
        Wire.get_u32(hello, 17) == Wire.ROOTD_PQ ||
            flag!(s, "handshake: bad protocol token")
        write(sock, vcat(cs_hdr(0x0000, Wire.kXR_ok, 8), cs_be32(0x310), cs_be32(1)))

        frame, _ = cs_take(sock)
        Wire.get_u16(frame, 3) == Wire.kXR_protocol ||
            flag!(s, "bring-up: expected kXR_protocol")
        push!(s.asked, frame[9])
        frame[10] == Wire.kXR_ExpLogin ||
            flag!(s, "kXR_protocol: expect byte is $(frame[10]), not kXR_ExpLogin")
        write(
            sock,
            vcat(
                cs_hdr(Wire.get_u16(frame, 1), Wire.kXR_ok, 8),
                cs_be32(Wire.kXR_PROTOCOLVERSION),
                cs_be32(s.flags),
            ),
        )

        move, bytes = tls_next_move(sock)
        push!(s.next, move)
        move == "login" || return nothing
        Wire.get_u16(bytes, 3) == Wire.kXR_login ||
            flag!(s, "bring-up: expected kXR_login, got $(Wire.get_u16(bytes, 3))")
        dlen = Int(Wire.get_u32(bytes, 21))
        dlen > 0 && read(sock, dlen)
        push!(s.logins, String(rstrip(String(bytes[9:16]), '\0')))
        write(sock, vcat(cs_hdr(Wire.get_u16(bytes, 1), Wire.kXR_ok, 16), UInt8.(1:16)))
        # Nothing else is served: the session is up, which is all these tests
        # need. The client closes it, and the read below ends with the socket.
        read(sock)
    catch
        # a client that hung up mid-negotiation is the point of several tests
    finally
        isopen(sock) && close(sock)
    end
    return nothing
end

"Start a negotiating server; returns (srv, port). Keywords set [`TlsServer`](@ref)."
function start_tls_server(; kwargs...)
    s = TlsServer(; kwargs...)
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
        @async tls_serve_conn(s, sock)
    end
    return s, Int(port)
end

"""
The move the server saw, waiting for it: a client that refuses to go on
gives up before the server has read the end of the connection, so the two
sides record the same event in either order.
"""
function tls_await_move(s::TlsServer; timeout::Float64=5.0)
    deadline = time() + timeout
    while isempty(s.next) && time() < deadline
        sleep(0.02)
    end
    return isempty(s.next) ? "" : s.next[end]
end

"""
Bring a session up against a `TlsServer` and report what it did, without
letting a failed connect become a failed test: TLS against a server that
speaks none must fail, and the interesting part is that it was attempted.
"""
function tls_bringup(port::Int; kwargs...)
    conn = try
        Session.connect("127.0.0.1", port; kwargs...)
    catch err
        return nothing, err
    end
    close(conn)
    return conn, nothing
end
