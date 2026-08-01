
# Release Notes

## 0.3.0 (07-02-2026)
- **Pure-Julia rewrite.** The XRootD protocol is now implemented natively in
  Julia; the CxxWrap binding to the XrdCl C++ library and the `XRootD_jll` /
  `XRootD_cxxwrap_jll` runtime dependencies are removed (`XRootD_jll` remains
  a test-only dependency for the server). The `File` / `FileSystem` API and
  the `(status, result)` convention are unchanged.
- Layered architecture: `Wire` (codecs) → `Session` (connections, TLS, auth,
  multiplexing, resilience) → `XrdCl` (public API) → `Storage` (multi-backend
  dispatch) → `Tools` (copy engine + CLIs).
- In-protocol TLS via `roots://`, or on the server's demand (`kXR_gotoTLS`,
  `kXR_tlsLogin`, `kXR_tlsSess`); a demand the server cannot honour fails the
  session rather than falling back to cleartext.
- Authentication: unix, WLCG bearer tokens (ztn), sss shared-secret
  (pure-Julia Blowfish), and X.509 client certificates over TLS (grid proxy
  discovery, `roots://` and `https://`/`davs://`); `kXR_sigver` request
  signing for high-security servers.
- New operations: `sync`, `readv`, `writev`, `pgread`/`pgwrite` (per-page
  CRC32c), `getxattr`/`setxattr`/`listxattr`/`removexattr`, `statvfs`,
  `checksum`, `prepare`, `symlink`/`hardlink`/`readlink`.
- Resilience: redirect following (including a negative port, which names a
  TLS endpoint), reconnect-with-replay for idempotent operations, and idle
  keepalive.
- Web backends: `http(s)://`, `dav(s)://` (WebDAV), and `s3(s)://` (AWS
  Signature v4) through a `Storage` abstraction; an S3 `endpoint` may name its
  own scheme, so an S3-compatible service on a private network can be reached
  over plain HTTP.
- `Tools`: a backend-agnostic copy engine and Julia equivalents of `xrdcp`,
  `xrdfs`, `xrdadler32`, `xrdcrc32c`, `xrdcrc64`, and `xrdckverify`
  (`bin/*.jl`), verified byte-for-byte against the reference clients.
- Attribution: the protocol understanding and client semantics were
  developed in the `libxrdc` pure-C client of the nginx-xrootd project;
  this release is a Julia translation of that work.

## 0.2.4 (05-02-2026)
- Fix for #2
- Fix for #3
 
## 0.2.3 (03-09-2025)
- Upgraded to CxxWrap 0.17 to support Julia 1.12. It fixes [#1](https://github.com/JuliaHEP/XRootD.jl/issues/1)
- Removed from exports `url`, `length`, `Set` to avoid clashes with `Base`
- Invoke `wrapit` to generate wrappers in the script instead of CMake   

## 0.2.2 (11-12-2024)
- Added function walkdir to walk on a directory tree

## 0.2.1 (4-11-2024)
- Added some protection to avoid pre-compilation errors in case the XRootD binary artifacts do not exist (e.g. Windows platform)

## 0.2.0 (31-10-2024)
- Updated to XRootD 5.7.1, OpenSLL 3.0.15 and CxxWrap 0.16 (with libcxxwrap_julia_jll 0.13.2)

## 0.1.0 (31-05-2024)
- First release. It provides similar functionality as for the python bindings of the client library of XRootD
