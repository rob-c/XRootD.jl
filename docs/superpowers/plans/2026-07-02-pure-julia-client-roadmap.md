# Pure-Julia Client Rewrite — Plan Roadmap

Spec: `docs/superpowers/specs/2026-07-01-pure-julia-client-design.md`

The rewrite is too large for one plan document. It is decomposed into eight
plans, each ending in working, independently testable software. Execute them
in order; each plan's "Produces" is the next plan's foundation.

| # | Plan | Spec phases | Produces (gate) |
|---|------|-------------|-----------------|
| 1 | `2026-07-02-plan-01-foundation-wire.md` | 1 | CxxWrap removed; `Wire` codec layer green under golden-frame unit tests; formatter/Aqua/JET/CI gates live |
| 2 | plan-02-session-fs-ops | 2–3 | `Session` (handshake→protocol→login→unix auth, streamid mux, sync op path) + FS ops; legacy `testFileSystem.jl` passes unmodified against a real server |
| 3 | plan-03-file-io | 4 | `File` ops incl. readv/writev/pgread/pgwrite; legacy `testFile.jl` passes unmodified |
| 4 | plan-04-auth-tls | 5 | roots:// TLS upgrade, ZTN bearer tokens, sss keytab + kXR_sigver |
| 5 | plan-05-extended-resilience | 6–7 | xattr, prepare, statvfs, vendor symlink/readlink/link, query checksum, deep locate; reconnect windows, replay, keepalive, redirect/wait |
| 6 | plan-06-web-backends | 8 | `Storage` abstraction; HTTP/WebDAV/S3 backend on HTTP.jl |
| 7 | plan-07-copy-tools | 9–10 | copy engine (pump, parallel chunks, verify, recursive); `xrdcp`/`xrdfs`/checksum CLI equivalents |
| 8 | plan-08-parity-release | 11 + test tier 3 | cross-implementation parity suite (XRootD.jl vs libxrdc vs official xrdcp/xrdfs); docs; 0.3.0 release |

Each plan is written with the writing-plans skill **immediately before its
execution**, not up front — later plans depend on interfaces and server
behaviors discovered while executing earlier ones. Plan 1 is written and
ready.

## Cross-plan invariants

These bind every plan (they restate spec requirements as execution rules):

- **Ground truth**: wire layouts come from `nginx-xrootd/src/protocol/*.h`
  (opcodes.h, wire_core_requests.h, frame_hdr.h, flags.h, dirlist_fmt.h),
  behavior from `nginx-xrootd/client/lib/` (libxrdc). Cite the specific file
  in the docstring of every translated design. Cross-check against official
  `XProtocol.hh` when in doubt.
- **Attribution**: module docstrings and (later) CLI `--version` output credit
  libxrdc as the prior art, per the spec's Attribution section.
- **API compatibility**: `using XRootD.XrdCl` must keep working — when the
  Client layer lands (plan 2), export it under the alias `XrdCl` with the
  existing names and `(status, result)` tuple returns. The legacy tests in
  `test/legacy/` are byte-identical copies of the 0.2.x tests and are the
  acceptance gate for plans 2–3.
- **Test server**: integration tests get a real `xrootd` server from
  `XRootD_jll` as a *test-only* dependency (it is removed from package deps in
  plan 1). The cross-implementation parity suite (plan 8) additionally drives
  the libxrdc binaries in `nginx-xrootd/client/bin/` and the official
  `xrdcp`/`xrdfs`.
- **Quality gates** (live from plan 1 onward, enforced in CI): JuliaFormatter
  blue style, Aqua, JET on the public API, docstrings on every public symbol,
  no `Any`-typed containers in the data path.
- **Paths on the wire carry no trailing NUL**: `dlen = ncodeunits(path)`,
  matching libxrdc (`ops_fs.c` uses `strlen`).
