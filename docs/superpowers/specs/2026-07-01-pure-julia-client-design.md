# XRootD.jl 0.3: Pure-Julia client — design

Date: 2026-07-01
Status: approved (2026-07-02, with the attribution, dual-parity testing, and
code-quality requirements below)

## Attribution

The protocol understanding, architecture, and operational semantics implemented
here were developed in the `libxrdc` pure-C client
(`/home/rcurrie/HEP-x/nginx-xrootd/client/`). That work — the wire-protocol
ground truth, the async/resilience design, the auth flows, and the CLI
behavior — is the reference this implementation translates into Julia. The
CLI tools' `--version`/help output and the package documentation credit
`libxrdc` as the prior art, and module docstrings for translated designs
(Session mux, copy pump, resilience policy) cite the corresponding `libxrdc`
sources.

## Goal

Replace the CxxWrap/WrapIt binding to the official XrdCl C++ library with a
from-scratch pure-Julia implementation of the XRootD client, reaching feature
parity with `libxrdc` — the pure-C client under
`/home/rcurrie/HEP-x/nginx-xrootd/client/` — at both the library-API level and
for a selected subset of its CLI tools.

This is a breaking release (0.3.0). The `gen/` WrapIt machinery and the
CxxWrap / JLL dependencies are removed entirely.

## Scope

In scope:

- `root://` wire protocol (handshake, `kXR_protocol`, login, auth, full
  operation set) implemented natively in Julia.
- `roots://` (TLS) via OpenSSL.jl, driven by `kXR_protocol` capability
  negotiation.
- Auth: none/unix, bearer tokens (ZTN protocol + `?authz=` opaque CGI), and
  sss (keytab parsing + `kXR_sigver` request signing).
- Web backends: `http(s)://`, `dav(s)://`, `s3(s)://` built on HTTP.jl —
  range/streaming download, resumable upload, WebDAV PROPFIND listing,
  AWS Signature v4 signing.
- Resilience: bounded reconnect windows with replay of idempotent requests,
  keepalive pings, redirect and `kXR_wait` handling.
- Full file I/O parity: `read`/`write`, `readv`/`writev`, `pgread`/`pgwrite`
  (protocol v5, per-page CRC32c), `sync`, `truncate`.
- Full filesystem parity: existing ops plus xattr (`fattr`
  get/set/list/del), `prepare`, `statvfs`, `symlink`/`link`/`readlink`,
  `query_checksum`, deep `locate`.
- Checksums: crc32c (stdlib `CRC32c`, hardware-accelerated), adler32 (pure
  Julia), crc64/xz (table-driven), local and remote.
- Copy engine: chunked pump between any two storage endpoints, parallel
  in-flight chunks, post-copy checksum verification, recursive tree copy.
- CLI tool equivalents, as Julia functions plus thin `bin/*.jl` entry
  scripts: `xrdcp` (incl. recursive), `xrdfs` (subcommands + interactive
  shell), `xrdadler32`, `xrdcrc32c`, `xrdcrc64`, `xrdckverify`.

Out of scope (non-goals):

- FUSE mount (`xrootdfs`) and the LD_PRELOAD POSIX shim.
- GSI/X.509 proxy and Kerberos authentication.
- Diagnostics suite (`xrddiag`, `mpxstats`, `xrdstorascan`, battery/doctor/
  clockskew), `xrdprep`/`xrdqstats`/`xrdmapc`/`wait41` CLI tools (the
  underlying `prepare`/`query` operations ARE exposed at API level).
- io_uring / epoll-style native event loops (Julia Tasks replace them).

Stretch (not core scope, design must not preclude them):

- ZIP central-directory member access (`root://...#member`).
- Native third-party copy (TPC).

## Architecture

Five layers, strictly one-directional dependencies (each layer only calls the
one below it):

```
┌─ Layer 5  Tools/       xrdcp / xrdfs / checksum CLIs (functions + bin/ scripts)
┌─ Layer 4  Storage.jl   abstract backend + URL scheme dispatch
│                        root(s):// → Client   http/dav/s3 → Web   path → local
┌─ Layer 3  Client/      File / FileSystem / Responses — public API,
│                        (status, result) tuple convention; Web/ sits beside
│                        it at this level as the web-protocol peer
┌─ Layer 2  Session/     connect · handshake · login · auth · TLS upgrade ·
│                        streamid multiplexing · keepalive · reconnect
│                        one reader Task per connection; each in-flight request
│                        parks on its own Channel keyed by streamid
└─ Layer 1  Wire/        kXR_* constants, request/response frame encode/decode —
                         pure functions over byte buffers, no I/O
```

### Module layout

```
src/
  XRootD.jl        top module; re-exports the public API (names unchanged)
  Wire/            frame codecs, kXR constants, big-endian (de)serialization
  Session/         connection lifecycle, mux, auth mechanisms, TLS, resilience
  Client/          File.jl, FileSystem.jl, Responses.jl (pure Julia structs)
  Web/             HTTP/WebDAV/S3 backend on HTTP.jl + SigV4 signer
  Storage.jl       abstract interface: open/read/write/stat/list/remove/...
  Checksums.jl     crc32c / adler32 / crc64-xz, local + remote dispatch
  Tools/           xrdcp.jl, xrdfs.jl, cksum.jl + shared CLI plumbing
bin/               thin launcher scripts (julia --project -e ...)
```

### Concurrency model

The C client's epoll/io_uring event loop (`aio*.c`) translates to: one reader
`Task` per TCP connection parses frames off the socket and routes each to the
`Channel` registered for its streamid; unsolicited frames (redirect,
`kXR_wait`, `kXR_status` pages, attn) are handled in the Session layer.
Operations at Layer 3 are synchronous calls — they enqueue a request, then
block on their Channel. Parallelism (e.g. the copy pump's in-flight chunk
window) comes from issuing multiple requests before waiting, or from multiple
Tasks sharing one multiplexed connection.

### Public API compatibility

`File` and `FileSystem` keep today's exported names, signatures, and the
`(status, result)` tuple return convention. `XRootDStatus`, `StatInfo`,
`LocationInfo`, `ProtocolInfo`, and the flag/enum namespaces (`OpenFlags`,
`Access`, `DirListFlags`, `QueryCode`, `MkDirFlags`, ...) become plain Julia
structs and modules with the same names and members. Acceptance bar: the
existing `test/testFile.jl` and `test/testFileSystem.jl` pass unmodified
against the native implementation.

New API surface (parity additions), following the same conventions:
`readv`, `writev`, `pgread`, `pgwrite`, `sync`, `getxattr`/`setxattr`/
`listxattr`/`removexattr`, `prepare`, `statvfs`, `symlink`/`hardlink`/
`readlink`, `checksum` (remote query + local compute), deep `locate`.

### Auth ladder

1. **none/unix** — `kXR_login` + `kXR_auth` with unix credentials (username).
2. **TLS** — advertise TLS capability in `kXR_protocol`; upgrade the socket
   with OpenSSL.jl when the server requires it; `roots://` forces it.
3. **Bearer/token** — ZTN auth exchange carrying the token, plus `?authz=`
   opaque CGI for gateway-style endpoints (the nginx-xrootd primary path).
   Token discovery: explicit argument > `BEARER_TOKEN`/`BEARER_TOKEN_FILE` >
   `XDG_RUNTIME_DIR/bt_u<uid>` (WLCG convention).
4. **sss** — keytab file parsing (`sss_keytab.c` semantics) and `kXR_sigver`
   request signing.

### Error handling

Every fallible operation returns `(status, result)` where `status` is a pure
Julia `XRootDStatus` carrying status/code/errno/message, matching current
semantics (`isOK`, `isError`). Session-internal faults (socket errors, timeouts,
failed reconnect) surface as error statuses on all parked requests — never as
uncaught exceptions from library calls. Tools map statuses to stable exit
codes (mirroring `xrdc_shellcode`).

### Testing

Parity must be demonstrated against **both** reference implementations: the
official XRootD distribution (server + `xrdcp`/`xrdfs` clients) and the
`libxrdc` C client.

1. **Wire unit tests** — byte-exact golden frames for every request/response
   codec, fixtures captured from libxrdc and official-client traffic.
2. **Integration** — against a real server: official `xrootd` container in
   CI; the nginx-xrootd gateway locally. Existing test files run unmodified
   as the compatibility gate.
3. **Cross-implementation parity suite** — a dedicated test tier that runs
   the same scripted scenarios through three clients — XRootD.jl, `libxrdc`
   binaries (`client/bin/`), and the official `xrdcp`/`xrdfs` — against the
   same servers, asserting identical observable behavior: bytes moved,
   digests, directory listings, stat fields, xattr round-trips, and exit
   codes. Interoperability is also crossed: files written by one client are
   read back and verified by the others.

### Code quality

The code must read as expert, modern Julia — indistinguishable from senior
Julia-ecosystem output (per the project rules in CLAUDE.md):

- Formatting enforced by JuliaFormatter with a committed `.JuliaFormatter.toml`
  (BlueStyle base); CI fails on unformatted code.
- Every public symbol has a docstring with signature, arguments, returns, and
  a runnable example; module-level docstrings explain layer responsibilities
  and cite the corresponding `libxrdc` sources for translated designs.
- Idiomatic patterns throughout: multiple dispatch over flags/branching,
  concrete-field structs, `do`-block resource management for open/close,
  zero-allocation hot paths in Wire/Session verified with allocation tests,
  no `Any`-typed containers in the data path.
- Quality gates in CI: Aqua.jl (project hygiene), JET.jl (type stability of
  the public API), Documenter.jl doctests.

### Dependencies

Added: HTTP.jl, OpenSSL.jl, URIs.jl. Stdlib: Sockets, CRC32c, SHA.
Removed: CxxWrap, XRootD_jll (and the `gen/` WrapIt toolchain).

## Phasing

Each phase ends green (tests passing) and is independently reviewable:

1. **Wire** — constants, codecs, golden-frame tests. No sockets.
2. **Session core** — handshake, protocol, login, unix auth, streamid mux,
   sync op path.
3. **FS-op parity** — stat, dirlist, mkdir/rm/rmdir/mv/chmod/truncate, ping,
   locate, query, protocol; existing `testFileSystem.jl` passes.
4. **File I/O** — open/read/write/close/sync, readv/writev, then
   pgread/pgwrite; existing `testFile.jl` passes.
5. **TLS + tokens + sss** — the auth ladder beyond unix.
6. **Extended ops** — xattr, prepare, statvfs, symlink/link/readlink,
   query checksum, deep locate.
7. **Resilience** — reconnect windows, replay, keepalive, redirect/wait.
8. **Web backends** — Storage abstraction, HTTP/DAV/S3 via HTTP.jl.
9. **Copy engine** — pump, parallel chunks, verify, recursive.
10. **Tools** — xrdcp, xrdfs (+ shell), checksum CLIs, exit-code mapping.
11. **Release** — docs rewrite, CxxWrap removal finalized, 0.3.0.
