# A redirector: the manager half of the protocol. It brings a connection up
# exactly like the other two conformance servers (`serve_bringup` is shared)
# and then answers every request with `kXR_redirect` — or, when told to, with
# an endless stream of `kXR_wait`.
#
# The point of the file is the *client* side of a redirect: a manager sends
# no data, it sends a destination and an opaque blob, and the client has to
# reconnect, re-login and re-issue the request with that blob attached. The
# redirect frames are hand-built from the byte helpers in server.jl so a
# malformed one can be posted deliberately.

using Sockets
using XRootD: Wire

"""
A redirecting front end. Every request is answered with a redirect to
`target_host:target_port` (a `target_port` of 0 tells the client to keep the
port it used, which is what the protocol means by a zero port; a negative one
sends it to `|target_port|` over TLS), with `cgi` attached as the redirector's
opaque data.

`body` replaces the whole redirect body when set — that is how a malformed
redirect is put on the wire. `wait_secs > 0` answers `kXR_wait` instead, for
as long as the client keeps asking.

`conns`, `ops` and `paths` record what arrived, so a test can assert that a
bounded client stopped where it should have.
"""
Base.@kwdef mutable struct RedirServer
    target_host::String = "127.0.0.1"
    target_port::Int = 0
    cgi::String = ""
    body::Union{Nothing,Vector{UInt8}} = nothing
    wait_secs::Int = 0
    violations::Vector{String} = String[]
    logins::Vector{String} = String[]
    ops::Vector{UInt16} = UInt16[]
    paths::Vector{String} = String[]
    conns::Int = 0
end

flag!(s::RedirServer, msg::AbstractString) = push!(s.violations, String(msg))

function rdr_reset!(s::RedirServer)
    empty!(s.violations)
    empty!(s.logins)
    empty!(s.ops)
    empty!(s.paths)
    s.conns = 0
    return s
end

"The `kXR_redirect` body: `port[4]` (signed) then `host[?cgi]`."
function rdr_body(s::RedirServer)
    s.body === nothing || return copy(s.body)
    target = s.target_host * (isempty(s.cgi) ? "" : "?" * s.cgi)
    port = cs_be32(reinterpret(UInt32, Int32(s.target_port)))
    return vcat(port, Vector{UInt8}(codeunits(target)))
end

function rdr_serve_conn(s::RedirServer, sock)
    try
        serve_bringup(s, sock)
        while isopen(sock)
            frame, payload = cs_take(sock)
            sid, rid = Wire.get_u16(frame, 1), Wire.get_u16(frame, 3)
            sid == 0x0000 && flag!(s, "$(Wire.request_name(rid)): streamid 0")
            push!(s.ops, rid)
            # Every request these tests send names its path in the payload;
            # recording it raw is what shows the CGI the client attached.
            push!(s.paths, String(copy(payload)))
            if s.wait_secs > 0
                body = vcat(cs_be32(s.wait_secs), Vector{UInt8}(codeunits("later")))
                write(sock, vcat(cs_hdr(sid, Wire.kXR_wait, length(body)), body))
            else
                body = rdr_body(s)
                write(sock, vcat(cs_hdr(sid, Wire.kXR_redirect, length(body)), body))
            end
        end
    catch
        # the client hung up, which is the expected end of a redirect
    finally
        isopen(sock) && close(sock)
    end
    return nothing
end

"Start a redirector; returns (srv, port). Keywords set the [`RedirServer`](@ref) knobs."
function start_redirector(; kwargs...)
    s = RedirServer(; kwargs...)
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
        @async rdr_serve_conn(s, sock)
    end
    return s, Int(port)
end

"""
A TCP port on the loopback with nothing listening: bind one, learn its
number, give it back. A redirect to it is a redirect to a dead server.
"""
function dead_port()
    listener = listen(ip"127.0.0.1", 0)
    _, port = getsockname(listener)
    close(listener)
    return Int(port)
end
