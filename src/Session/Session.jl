"""
    XRootD.Session

Layer 2 of the client: connection lifecycle for the `root://` protocol.
Owns the TCP socket and the bring-up sequence (handshake → `kXR_protocol` →
`kXR_login` → auth), then multiplexes concurrent synchronous operations over
the connection: one reader Task routes each response frame to the Channel
registered for its streamid.

This is the Julia translation of libxrdc's connection layer
(`client/lib/conn.c` for bring-up, `client/lib/aio*.c` for the multiplexing
design — Julia Tasks/Channels replace the epoll loop).
"""
module Session

using Sockets: Sockets, TCPSocket
using OpenSSL: OpenSSL
using ..Wire

include("connection.jl")

end # module Session
