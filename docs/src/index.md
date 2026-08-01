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
  sss / X.509 client certificates), request multiplexing, resilience.
- `XRootD.XrdCl` — the public `File` / `FileSystem` API.
- `XRootD.Storage` — backend-agnostic storage dispatching on URL scheme
  (`root(s)://`, `http(s)://`/`dav(s)://`, `s3(s)://`, local paths).
- `XRootD.Tools` — the copy engine and `xrdcp` / `xrdfs` / checksum CLI
  equivalents (`bin/*.jl`).

## Credentials

Every storage backend takes the same bag of credential keywords, and
`storage_for` hands each one only the options its scheme understands — so a
single set of flags can be applied to a copy whose two endpoints speak
different protocols. `xrdcp` exposes the same set on the command line.

| Keyword | Schemes | Meaning |
|---|---|---|
| `token` | `root(s)`, `http(s)`, `dav(s)` | WLCG bearer token: `ztn` on xroot, `Authorization: Bearer` over HTTP. Discovered from `$BEARER_TOKEN`, `$BEARER_TOKEN_FILE`, `$XDG_RUNTIME_DIR/bt_u<uid>`, `/tmp/bt_u<uid>` when not given. |
| `use_token` | `http(s)`, `dav(s)` | Set `false` to suppress discovery for this endpoint. |
| `allow_cleartext_token` | `http(s)`, `dav(s)` | Permit sending a token over an unencrypted `http://` connection. |
| `cert`, `key` | `roots`, `https`, `davs` | X.509 client certificate and private key. A proxy PEM holds both, so `key` may be omitted. Discovered from `$X509_USER_PROXY`, `/tmp/x509up_u<uid>`, `$X509_USER_CERT`/`$X509_USER_KEY`, then `~/.globus/usercert.pem` + `userkey.pem`. |
| `cafile` | `roots`, `https`, `davs` | Extra CA bundle to trust, for a site CA outside the system store. `$X509_CERT_DIR` is picked up automatically for `roots://`. |
| `x509` | `root(s)` | Set `false` to skip X.509 discovery entirely. |
| `keytab` | `root(s)` | `sss` shared-secret keytab. |
| `insecure_tls` | `roots`, `https`, `davs` | Skip peer verification. For debugging only. |
| `headers` | `http(s)`, `dav(s)` | Extra request headers. |
| `creds`, `endpoint` | `s3(s)` | S3 credentials and endpoint override. |

A token is a bearer credential: anyone who sees it can use it. A token that
was *discovered* is therefore dropped rather than sent over cleartext
`http://` (with a warning), and one passed *explicitly* raises an
`ArgumentError` unless `allow_cleartext_token=true` says the risk is
understood. Legacy GSI (the pre-TLS X.509 handshake on the xroot control
stream) is not implemented; X.509 credentials authenticate through TLS, which
is what current servers expect.

## Copying and third-party copy

`copyfile` streams through a bounded pipe — the source backend fills it while
the destination drains it — so a copy costs a fixed amount of memory rather
than the size of the object, and `verify=true` re-reads the destination and
compares checksums.

```julia
using XRootD.Tools: copyfile

copyfile("root://src.example.org//data/in.root",
         "davs://dst.example.org/data/out.root";
         verify=true, tpc=:first)
```

With `tpc=:first` the endpoints are asked to move the bytes between
themselves and a streaming copy is the fallback; `tpc=:only` fails instead of
falling back. Both third-party protocols are implemented: WLCG HTTP-TPC
(`COPY` carrying `Source:` or `Destination:` plus
`TransferHeaderAuthorization:`) between two HTTP/WebDAV endpoints, and the
xroot rendezvous (`tpc.stage=placement` at the source, `tpc.stage=copy` at
the destination) between two xroot endpoints. A pair with no common
third-party path — anything involving a local path or an S3 object, or one
endpoint of each protocol — reports `:unsupported`, which is what `:first`
falls back on. The xroot rendezvous is tested against the wire format, not
against a production TPC deployment.

`dav(s)://` endpoints support the WebDAV write verbs, so they can be a copy
destination: `storage_mkdir` issues `MKCOL` (an existing collection's `405`
counts as success), `storage_move` issues `MOVE` and `storage_copy` `COPY`,
both with an `Overwrite:` header.

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
