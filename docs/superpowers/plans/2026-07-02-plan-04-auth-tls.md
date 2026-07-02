# Plan 04: Auth Ladder — TLS, ZTN Tokens, SSS, Sigver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spec phase 5 — the auth ladder beyond unix: in-protocol TLS
(`roots://`), WLCG bearer tokens (ztn), sss shared-secret credentials, and
the `kXR_sigver` signing machinery.

**Architecture:** `Connection.sock` generalizes from `TCPSocket` to a stream
(`IO`), so an OpenSSL.jl `SSLStream` slots in transparently after the
`kXR_protocol` reply (libxrdc `tls.c`: upgrade after protocol, before
login). Auth mechanism selection parses the login reply's `&P=...` security
trailer and picks the best available: ztn > sss > unix.

**Tech Stack:** OpenSSL.jl (TLS), stdlib SHA (HMAC-SHA256 for sigver),
pure-Julia Blowfish-CFB64 (sss; P/S boxes computed from π via BigFloat).

## Global Constraints

Plans 01–03 constraints, plus (ground truth libxrdc `tls.c`,
`sec/sec_token.c`, `sec/sec_sss.c`, `sigver.c`, and the shared kernel
`src/core/compat/sss_bf.{h,c}` + `src/auth/sss/sss_internal.h`):

- TLS upgrade happens after the `kXR_protocol` reply and before `kXR_login`;
  `roots://` forces `kXR_wantTLS`. Certificate verification defaults ON
  (CA dir from `$X509_CERT_DIR`); tests use an insecure-verify escape for
  the self-signed test server.
- ztn: discovery `$BEARER_TOKEN` → `$BEARER_TOKEN_FILE` →
  `$XDG_RUNTIME_DIR/bt_u<uid>` → `/tmp/bt_u<uid>`; credtype `"ztn"`,
  payload `"ztn\0" * jwt` (tag repeated), trailing whitespace stripped;
  single round.
- sss credential blob: 16-byte outer header
  (`"sss\0" ver(1) spare(0) kn(0) enc=BF32 key_id(8 BE)`) +
  Blowfish-CFB64(zero IV, no padding, keytab key) over
  `40-byte data header [nonce32 | gen_time BE | USEDATA] + NAME TLV +
  IEEE-CRC32`; gen_time is seconds since the SSS base epoch. Exact inner
  constants from `sss_bf.c`/`sss_internal.h` at implementation time.
- sigver: HMAC-SHA256(signing_key, seqno_be(8) || request_hdr(24) ||
  payload) sent as a PREFIX `kXR_sigver` frame (own streamid, dlen=32);
  spec-conformant servers send NO response on success. Gated on
  `sec_level ≥ 2` and a signing key; carries the same validation-gap note
  as libxrdc (no level-2 server in the harness).

## Tasks

### Task 1: TLS transport (roots://)
- [ ] Add OpenSSL.jl; `Connection.sock::IO`; `connect(...; want_tls)` sends
  `kXR_wantTLS`, checks the protocol-reply TLS flags, wraps the socket in
  an `SSLStream` (client mode, hostname check unless `insecure_tls`), then
  logs in over TLS. `FileSystem`/`File` URLs with `roots://` set
  `want_tls=true`. Integration test: self-signed cert + `xrootd -c` config
  with `xrd.tls`; `roots://localhost` FileSystem ping/stat round trip
  (insecure verify). Unit test: `want_tls` against a non-TLS mock fails
  with a clear error. Commit `feat(session): in-protocol TLS (roots://)`.

### Task 2: ZTN bearer tokens
- [ ] `discover_token(; explicit=nothing)::Union{String,Nothing}` with the
  ladder above; `authenticate` parses the `&P=` trailer into an ordered
  mechanism list and tries ztn (when a token exists) before sss/unix. Mock
  test: server trailer `&P=ztn` + credtype/payload assertion on the auth
  frame. Commit `feat(session): ztn bearer-token authentication`.

### Task 3: SSS shared-secret auth
- [ ] Pure-Julia Blowfish (P/S boxes from π hex digits via BigFloat,
  self-test against two published Blowfish ECB vectors) + CFB64 driver;
  keytab parser (format per libxrdc `sss_keytab.c`); credential builder
  byte-identical to `xrootd_sss_build_credential`. Unit tests: Blowfish
  vectors, CFB64 round trip, keytab parse, blob decrypt-and-verify
  round trip. Integration IF XRootD_jll ships `libXrdSecsss`: server with
  `sec.protocol sss -s <keytab>`; otherwise mock-server assertion.
  Commit `feat(session): sss shared-secret authentication`.

### Task 4: kXR_sigver signing
- [ ] `SigverRequest` codec (body: expectrid u16, version u8, flags u8,
  seqno u64, crypto u8 = kXR_SHA256_sig, rsvd; dlen=32; payload = HMAC);
  `Connection` gains `sec_level`, `signing_key`, `sig_seqno`; `send_signed`
  prefixes the sigver frame when required (opcode policy from the server
  verifier). Unit test: HMAC layout over a known key/request. Commit
  `feat(session): kXR_sigver request signing`.

## Completion gate

Full `Pkg.test()` green including the TLS integration round trip; quality
gates pass with the new deps.
