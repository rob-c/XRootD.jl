# A server that brings a connection up correctly and then answers every
# request with the same status and the same body, whatever was asked. The
# bodies it is pointed at are not valid encodings of anything.
#
# The decoders are tested directly in test/wire; this server reaches them the
# way a real peer does — through the framing, the multiplexer and the code
# that turns a reply into a result — because a decoder that survives in
# isolation still has to survive one reached through `roundtrip`.

using Sockets
using XRootD: Wire

"""
A hostile server. `status` and `body` are what every request is answered
with; `ops` records the requestids that arrived, so a test can tell an
operation that was refused locally from one that reached the wire.
"""
Base.@kwdef mutable struct HostileServer
    status::UInt16 = Wire.kXR_ok
    body::Vector{UInt8} = UInt8[]
    violations::Vector{String} = String[]
    logins::Vector{String} = String[]
    ops::Vector{UInt16} = UInt16[]
end

flag!(s::HostileServer, msg::AbstractString) = push!(s.violations, String(msg))

function hostile_serve_conn(s::HostileServer, sock)
    try
        serve_bringup(s, sock)
        while isopen(sock)
            frame, _ = cs_take(sock)
            push!(s.ops, Wire.get_u16(frame, 3))
            write(
                sock, vcat(cs_hdr(Wire.get_u16(frame, 1), s.status, length(s.body)), s.body)
            )
        end
    catch
        # the client hung up, which is the only way this loop ends
    finally
        isopen(sock) && close(sock)
    end
    return nothing
end

"Start a hostile server; returns (srv, port). The knobs are set between calls."
function start_hostile(; kwargs...)
    s = HostileServer(; kwargs...)
    listener = listen(ip"127.0.0.1", 0)
    _, port = getsockname(listener)
    @async while isopen(listener)
        local sock
        try
            sock = accept(listener)
        catch
            break
        end
        @async hostile_serve_conn(s, sock)
    end
    return s, Int(port)
end

"""
The reply bodies a broken or malicious server can produce. The lengths
straddle every fixed-size record in the protocol — a file handle is 4 bytes,
a session id 16, a stat line is text of no fixed length — and the last three
are length prefixes that promise far more data than follows, which is what
turns a decoder that allocates before it reads into a memory switch.
"""
function hostile_bodies()
    out = Vector{UInt8}[]
    for n in (0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33),
        b in (0x00, 0xff, UInt8('S'), UInt8('\n'))

        push!(out, fill(b, n))
    end
    push!(out, UInt8[0x7f, 0xff, 0xff, 0xff])
    push!(out, UInt8[0xff, 0xff, 0xff, 0xff, UInt8('x')])
    push!(out, vcat(zeros(UInt8, 16), UInt8[0x7f, 0xff, 0xff, 0xff]))
    return out
end
