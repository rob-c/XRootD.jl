"""
    XRootD.Wire

Layer 1 of the client: pure codecs for the XRootD `root://` wire protocol.
Encodes client requests to exact byte frames and decodes server response
bytes into plain Julia values. Performs **no I/O** — every function here is
testable against literal byte vectors.

Layouts follow the nginx-xrootd protocol reference (`src/protocol/opcodes.h`,
`wire_core_requests.h`, `frame_hdr.h`, `flags.h`), cross-checked against the
official `XProtocol.hh`, and match what the `libxrdc` C client puts on the
wire.
"""
module Wire

using CRC32c: crc32c

include("primitives.jl")
include("constants.jl")
include("frames.jl")
include("requests.jl")
include("responses.jl")

end # module Wire
