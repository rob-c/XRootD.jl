# XRootD.jl

Pure-Julia client for the [XRootD](https://xrootd.slac.stanford.edu)
high-performance, scalable, fault-tolerant data-access protocol.

As of 0.3, XRootD.jl implements the XRootD protocol natively in Julia — there
is no longer a CxxWrap binding to the XrdCl C++ library, and the package has
no compiled binary dependencies beyond standard Julia packages.

## Installation

```julia
using Pkg
Pkg.add("XRootD")
```

## Getting started

The `XRootD.XrdCl` module provides the two main types — `FileSystem` for
namespace operations and `File` for I/O — with a `(status, result)` return
convention.

```julia
using XRootD.XrdCl

fs = FileSystem("root://localhost:1094")     # or roots:// for TLS

st, _ = ping(fs)
isError(st) && error(st)

st, statinfo = stat(fs, "/tmp")
if isOK(st) && isdir(statinfo)
    st, entries = readdir(fs, "/tmp")
    foreach(println, entries)
end

# File I/O
f = File()
st, _ = open(f, "root://localhost:1094//tmp/testfile.txt", OpenFlags.New | OpenFlags.Write)
write(f, "Hello\nWorld\n")
close(f)

st, _ = open(f, "root://localhost:1094//tmp/testfile.txt", OpenFlags.Read)
st, lines = readlines(f)
close(f)
```

## Architecture

The client is built in layers, each depending only on the one below:

- `XRootD.Wire` — pure wire-format codecs (no I/O).
- `XRootD.Session` — connections, TLS, authentication (unix / bearer token /
  sss), request multiplexing, resilience.
- `XRootD.XrdCl` — the public `File` / `FileSystem` API.
- `XRootD.Storage` — backend-agnostic storage dispatching on URL scheme
  (`root(s)://`, `http(s)://`/`dav(s)://`, `s3(s)://`, local paths).
- `XRootD.Tools` — the copy engine and `xrdcp` / `xrdfs` / checksum CLI
  equivalents (`bin/*.jl`).

## Migration from 0.2.x

The `File` / `FileSystem` API and the `(status, result)` convention are
unchanged, so most 0.2.x code runs as-is. Notable changes:

- `roots://` URLs now negotiate in-protocol TLS.
- New operations: `sync`, `readv`, `writev`, `pgread`, `pgwrite`,
  `getxattr` / `setxattr` / `listxattr` / `removexattr`, `statvfs`,
  `checksum`, `prepare`, `symlink` / `hardlink` / `readlink`.
- No `XRootD_jll` / CxxWrap dependency; the test-only server still comes from
  `XRootD_jll`.

## Attribution

The wire-format ground truth, client semantics, and architecture implemented
here were developed in the `libxrdc` pure-C client and protocol reference of
the nginx-xrootd project. This package is a Julia translation of that prior
work.

## API

```@contents
Pages = ["api.md"]
Depth = 2
```
