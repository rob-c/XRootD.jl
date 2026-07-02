# XRootD.jl

Pure-Julia client for the [XRootD](https://xrootd.slac.stanford.edu)
high-performance data-access protocol.

!!! warning "0.3 rewrite in progress"
    XRootD.jl is being rewritten as a native Julia implementation of the
    XRootD protocol, replacing the previous CxxWrap binding to the XrdCl C++
    library. The 0.2.x `File`/`FileSystem` API will return unchanged as the
    rewrite lands. For the 0.2.x documentation, select the `v0.2.4` version
    of these docs.

## Architecture

The client is built in layers; only `Wire` exists so far:

- `XRootD.Wire` — pure codecs for the wire protocol (no I/O).
- `Session`, `File`/`FileSystem`, web backends, and `xrdcp`/`xrdfs` tool
  equivalents follow — see the roadmap in the repository under
  `docs/superpowers/plans/`.

## Attribution

The wire-format ground truth, client semantics, and architecture implemented
here were developed in the `libxrdc` pure-C client and protocol reference of
the nginx-xrootd project. This package is a Julia translation of that prior
work.

## Wire API

```@autodocs
Modules = [XRootD, XRootD.Wire]
```
