"""
    XRootD.Session

Layer 2 of the client: connection lifecycle for the `root://` protocol.
Owns the TCP socket and the bring-up sequence (handshake → `kXR_protocol` →
`kXR_login` → auth), then multiplexes concurrent synchronous operations over
the connection: one reader Task routes each response frame to the Channel
registered for its streamid.

A credential the server wants but discovery cannot find is asked for on the
terminal when there is one ([`prompt_credentials!`](@ref) redirects that
anywhere else, `XRDC_NO_PROMPT` turns it off).

This is the Julia translation of libxrdc's connection layer
(`client/lib/conn.c` for bring-up, `client/lib/aio*.c` for the multiplexing
design — Julia Tasks/Channels replace the epoll loop).
"""
module Session

using Sockets: Sockets, TCPSocket
using OpenSSL: OpenSSL
using OpenSSL_jll: libssl
using SHA: sha256
using ..Wire

include("blowfish.jl")
include("env.jl")
include("retry.jl")
include("redact.jl")
include("url.jl")
include("prompt.jl")
include("x509.jl")
include("connection.jl")
include("sss.jl")
include("auth.jl")
include("sigver.jl")

end # module Session
