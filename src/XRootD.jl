"""
    XRootD

Pure-Julia client for the [XRootD](https://xrootd.slac.stanford.edu) protocol:
high-performance, scalable, fault-tolerant access to data repositories.

As of 0.3, XRootD.jl no longer wraps the XrdCl C++ library. The protocol is
implemented natively in Julia, in layers:

- `XRootD.Wire` — wire-format codecs (no I/O).
- `XRootD.Session` — connections, TLS, authentication (unix / bearer token /
  sss), request multiplexing, and resilience.
- `XRootD.XrdCl` — the public `File` / `FileSystem` API.
- `XRootD.Storage` — backend-agnostic storage dispatching on URL scheme
  (`root(s)://`, `http(s)://`/`dav(s)://`, `s3(s)://`, local paths).
- `XRootD.Tools` — the copy engine and `xrdcp` / `xrdfs` / checksum CLI
  equivalents.

On top of those sits the everyday API: a [`StoragePath`](@ref) is a file
anywhere this client can reach, and `filesize`, `open`, `read`, `readdir` and
`cp` work on one the way they work on a local file. Every verb also has an
`XRootD.`-qualified form that takes the URL as a string —
[`XRootD.ls`](@ref), [`XRootD.download`](@ref), [`XRootD.open`](@ref) — because
`read("root://…")` would be Base reading a local file of that name.

    using XRootD

    XRootD.ls("root://eospublic.cern.ch//eos/opendata/cms")
    file = XRootD.download("root://eospublic.cern.ch//eos/opendata/cms/data.root")

    f = xrd"root://eospublic.cern.ch//eos/opendata/cms/data.root"
    filesize(f)
    open(f) do io
        read(io, 1024)
    end

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

# The everyday API lives here, in the module people type the name of. Its verbs
# shadow the `Base` names they mirror (`XRootD.read`, `XRootD.open`, …), so
# anything below this line that means Base's must say so.
include("api.jl")

using Sockets: Sockets
include("precompile.jl")

end # module XRootD
