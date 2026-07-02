"""
    XRootD

Pure-Julia client for the [XRootD](https://xrootd.slac.stanford.edu) protocol:
high-performance, scalable, fault-tolerant access to data repositories.

As of 0.3, XRootD.jl no longer wraps the XrdCl C++ library. The protocol is
implemented natively in Julia, in layers:

- [`XRootD.Wire`](@ref) — wire-format codecs (no I/O).
- `XRootD.Session` — connections, auth, request multiplexing (plan 02).
- Client `File`/`FileSystem` API, web backends, and tools follow in later
  plans; see `docs/superpowers/plans/2026-07-02-pure-julia-client-roadmap.md`.

## Attribution

The wire-format ground truth, client semantics, and architecture implemented
here were developed in the `libxrdc` pure-C client and protocol reference of
the nginx-xrootd project (`client/lib/`, `src/protocol/`). This package is a
Julia translation of that prior work.
"""
module XRootD

include("Wire/Wire.jl")
include("Session/Session.jl")
include("Client/XrdCl.jl")
include("Storage/Storage.jl")
include("Tools/Tools.jl")

using Sockets: Sockets
include("precompile.jl")

end # module XRootD
