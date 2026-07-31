# Lessons learned: implementing XRootD.jl against nginx-xrootd/libxrdc

Date: 2026-07-02

This is a write-up of what a clean-room Julia reimplementation of the XRootD
client (`XRootD.jl` 0.3, plans 01–08) surfaced about the `nginx-xrootd`
codebase — its `libxrdc` C client, its server, and the shared protocol
reference. Each lesson is framed so it can be **checked against nginx-xrootd**:
it states what was observed, the evidence, the exact file(s) to look at, and a
status.

Status legend:

- **BUG** — a confirmed defect in nginx-xrootd (client or server), reproduced.
- **DIVERGENCE** — two parts of nginx-xrootd disagree with each other; needs a
  decision on which is canonical.
- **CHECK** — a subtlety where a latent bug could hide; worth an audit.
- **CONSISTENT** — verified to agree end-to-end; recorded so a future change
  doesn't regress it.

Ground truth for XRootD.jl's behavior throughout was stock `xrootd` 5.8 (from
`XRootD_jll`) plus the co-developed `libxrdc` binaries; every wire fact below
was exercised by the XRootD.jl test suite (~600 assertions, incl. a
three-way parity tier: XRootD.jl vs libxrdc vs official `xrdcp`).

---

## 1. `kXR_writev` — the libxrdc client contradicts nginx-xrootd's own server  **[BUG — FIXED UPSTREAM]**

> **Resolved 2026-07-31** (nginx-xrootd `bc8688823`). `brix_file_writev`
> (`client/lib/protocols/root/ops_file_rw.c`) now sends
> `brix_payload_ext pe = { payload, plen, nseg * 16 }` — the full buffer goes
> on the wire, the header `dlen` frames the descriptor block alone. Item 1 of
> "to check" below is done; items 2 and 3 (checkpoint framing, server-vs-client
> test) still stand. The rest of this section is kept as the record of the
> diagnosis.

**Observed.** XRootD.jl's first `kXR_writev` framing (data counted inside
`dlen`, copied from libxrdc) was rejected by stock xrootd with
`kXR_ArgInvalid: "Write vector is invalid"`, followed by a link drop. Moving
the segment data to a *trailer outside `dlen`* (so `dlen` frames only the
`N×16` descriptor block) made it pass.

**Root cause in nginx-xrootd.** Three places encode/decode writev, and they
do **not** agree:

| Site | File | Contract |
|---|---|---|
| Client encoder | `client/lib/ops_file_rw.c:407` | `plen = nseg*16 + total_data` — **data inside `dlen`** |
| Server, standalone `kXR_writev` | `src/protocols/root/write/writev.c` (`xrootd_writev_body_extra`) | `dlen % 16 == 0`, `dlen` = descriptors **only**, data is trailing "extra" |
| Server, checkpoint-embedded writev | `src/protocols/root/write/chkpoint_xeq.c:309` | `n_segs*16 + total_wlen == sub_dlen` — **data inside `sub_dlen`** |

The client encoder matches the **checkpoint** framing, but the **standalone**
`kXR_writev` handler (and stock XrdXrootd) require the descriptors-only
framing. So `libxrdc`'s `xrdc_file_writev` is wrong against both stock xrootd
**and nginx-xrootd's own standalone server**.

**Why it stayed hidden.** `xrdcp` pumps with `kXR_write`, never `kXR_writev`
(confirmed: `client/lib/copy_pump.c` / `ops_file_rw.c` `xrdc_file_write`), so
the parity copy tests pass. Only the FUSE driver / any explicit `writev`
caller exercises the broken path.

**To check against nginx-xrootd.**
1. Fix `xrdc_file_writev` to emit descriptors in `dlen` and stream the data
   after (mirror `writev.c`'s contract).
2. Decide whether the checkpoint-embedded framing (`chkpoint_xeq.c`) should
   also be descriptors-only for consistency, or whether the two contexts are
   intentionally different (if so, document it — a single `write_list` block
   with two framings is a foot-gun).
3. Add a server-vs-client writev test to the nginx-xrootd suite; the current
   suite misses it because no CLI path emits `kXR_writev`.

XRootD.jl reference: `src/Wire/requests.jl` (`WriteVRequest`, `payload` =
descriptors, `trailer` = data) and `src/Wire/frames.jl` (`trailer` support in
`encode`).

---

## 2. `kXR_status` frames carry data *beyond* `dlen`  **[CHECK]**

**Observed.** Paged I/O (`kXR_pgread`/`kXR_pgwrite`) replies use `kXR_status`
framing: an 8-byte response header with `dlen = 24`, then a 24-byte status
body, then **`pgdlen` more bytes of page data that are not counted in the
header `dlen`**. A response reader that trusts `dlen` alone desynchronizes the
stream. XRootD.jl's connection reader special-cases this
(`src/Session/connection.jl`, the `kXR_status` branch reads the 24-byte body
then `pgdlen` extra).

**nginx-xrootd.** The client handles it correctly
(`client/lib/ops_file_pg.c` `read_status_frame` → then `xrdc_read_full(pg,
pgdlen)`). The lesson is for any **framing-only** consumer that assumes
"one header `dlen` == whole frame."

**To check against nginx-xrootd.** Audit every site that reads/relays frames
by `dlen` — especially the server's proxy/upstream relay and any capture
tooling — to confirm the `kXR_status` `pgdlen` trailer is accounted for.
`grep -rn "kXR_status" src/` and confirm each reader adds the trailer, the way
`client/lib/ops_file_pg.c` does.

---

## 3. Two different CRC-32s live in the protocol  **[CHECK]**

**Observed.** XRootD uses **CRC-32C (Castagnoli)** for paged-I/O page
integrity and the `kXR_status` header, but **CRC-32/IEEE (zlib)** for the SSS
credential blob. Crossing them silently breaks either integrity checking or
auth. XRootD.jl keeps them in separate modules (`Tools`/`Session` use stdlib
`CRC32c`; `Session/sss.jl` implements IEEE CRC-32).

**nginx-xrootd.** `libxrdc` keeps them separate too — `ops_file_pg.c:82`
uses `xrootd_crc32c_value`, `sss_keytab.c:37` uses `xrootd_crc32_ieee`. Good.

**To check against nginx-xrootd.** Audit the **server** side for the same
discipline: any `crc32` symbol should be unambiguously the C or the IEEE
variant. `grep -rn "crc32" src/` and confirm no site uses the wrong kernel
(the shared kernels are `core/compat/crc32_ieee.*` and the crc32c path).

---

## 4. SSS wire constants are easy to misread  **[CHECK]**

**Observed.** In the SSS credential's 16-byte outer header the encoding
marker `enc` is the **ASCII character `'0'` (0x30)**, not the integer `0`;
the data-header option `USEDATA` **is** `0x00`. Reading `enc` as integer 0
produces a blob the server rejects. XRootD.jl encodes `SSS_ENC_BF32 =
UInt8('0')` (`src/Session/sss.jl`), matching the server reference
`src/protocols/root/protocol/sss.h` (`XROOTD_SSS_ENC_BF32 '0'`).

Related fixed facts that must line up on both ends: `XROOTD_SSS_HDR_LEN=16`,
`XROOTD_SSS_DATA_HDR_LEN=40`, `XROOTD_SSS_BASE_TIME=1222183880`,
`TYPE_NAME=0x01`, name TLV length **includes** the trailing NUL, and the
credential body is Blowfish-CFB64 with an **all-zero 8-byte IV, no padding**.

**To check against nginx-xrootd.** Confirm the server's SSS verifier
(`src/auth/sss/…`, shared kernel `src/core/compat/sss_bf.c`) reads `enc` as a
char and uses the same base epoch; a mismatch would only show under real SSS
auth (which the default test server doesn't exercise — see gap in §9).

---

## 5. Paths have no trailing NUL outbound, but some responses add one  **[CONSISTENT / CHECK]**

**Observed.** Request path payloads are sent **without** a trailing NUL:
`dlen = strlen(path)` (libxrdc `ops_fs.c` uses `strlen`; XRootD.jl uses
`ncodeunits`). But several **responses** append a NUL the client must tolerate
but not require: `kXR_error` messages, the dirlist body, and the stat line.
XRootD.jl decoders read bounded and `rstrip` a trailing NUL everywhere
(`src/Wire/responses.jl`).

**To check against nginx-xrootd.** This asymmetry is a classic source of
off-by-one bugs. Confirm the server never *requires* an inbound path NUL and
always/never appends one consistently per response type; `basic.c`
(response/basic.c) already documents "trailing NUL matters because several
clients treat the text as a C string" — verify the dirlist and stat encoders
follow the same rule.

---

## 6. Three ops share one "arg1 SP arg2 + arg1len" payload shape  **[CONSISTENT]**

**Observed.** `kXR_mv`, `kXR_symlink`, and `kXR_link` all encode
`arg1 * " " * arg2` in the payload with `arg1len = ncodeunits(arg1)` in body
bytes 15–16 (big-endian int16). XRootD.jl implements all three identically
(`src/Wire/requests.jl`), matching libxrdc `ops_fs.c` (mv) and the vendor-ext
header for symlink/link.

**To check against nginx-xrootd.** Confirm the three server decoders share
one helper (they should, given the identical shape) so a fix to one can't skip
the others. The vendor ops are gated on `kXR_Qconfig "xrdfs.ext"` — verify the
gate is enforced before the decoder runs.

---

## 7. Vendor extension opcodes ride above the standard range  **[CONSISTENT]**

**Observed.** `kXR_setattr=3500`, `symlink=3501`, `readlink=3502`,
`link=3503` sit well above the max standard opcode (`kXR_clone=3032`) and are
capability-negotiated. XRootD.jl only emits them for callers that opt in; a
stock server never sees one.

**To check against nginx-xrootd.** Confirm the per-opcode RTT table bound
(`reqid - kXR_1stRequest < XRDC_NOP`) still holds for these high ids (the
opcodes.h comment claims it does — worth a assertion/test). If any client-side
table is sized to the standard range without the bounds check, 3500+ indexes
out of bounds.

---

## 8. The protocol headers moved mid-stream  **[CHECK]**

**Observed.** During this work the protocol reference relocated from
`src/protocol/*.h` to `src/protocols/root/protocol/*.h`. A clean-room client
(or any external consumer) that pins the old path silently loses its ground
truth.

**To check against nginx-xrootd.** If external clients are expected to
clean-room against these headers, consider a stable, documented location or a
compatibility shim; note the move in a CHANGELOG. XRootD.jl's plan docs cite
specific header paths — those citations are now stale for the pre-move commits.

---

## 9. Auth mechanisms beyond `unix` are untested by the default server  **[CHECK]**

**Observed.** The `XRootD_jll` test server (and, I believe, nginx-xrootd's
default test config) authenticates with `unix`, so ztn/sss/`kXR_sigver` get no
live integration coverage. XRootD.jl verifies these at the **codec** level
(Blowfish ECB vectors, zlib CRC-32 vector, HMAC-SHA256 over a known request,
byte-exact SSS blob layout) but not against a live authenticating server —
the same validation gap `sigver.c` documents ("not exercised by the test
harness; its GSI servers run at level 0").

**To check against nginx-xrootd.** This is a shared blind spot. A test server
config with `sec.protocol sss`/ztn and `security_level >= 2` would give both
libxrdc and XRootD.jl real coverage of the auth ladder and `kXR_sigver`.

---

## 10. `kXR_dirlist` dstat detection hinges on a 9-byte sentinel  **[CONSISTENT]**

**Observed.** With `kXR_dstat` set, the server prepends `".\n0 0 0 0\n"` and
the client detects stat-mode by the 9-byte prefix `".\n0 0 0 0"`; without the
exact sentinel, every line (including stat lines) is treated as a filename.
XRootD.jl keys on the same prefix (`src/Wire/responses.jl` `parse_dirlist`).

**To check against nginx-xrootd.** Confirm the server always emits the full
sentinel (including both newlines) whenever `kXR_dstat`/`kXR_dcksm` is set, and
that intermediate `kXR_oksofar` chunks do **not** repeat it — the client
accumulates raw and parses once.

---

## Appendix: Julia-specific lessons (not about nginx-xrootd)

Recorded for completeness; these are implementation notes for XRootD.jl, not
findings to check against the C code.

- **First-call JIT latency dominated small ops.** A 13-byte copy took 4.4 s
  of first-call compilation; a `PrecompileTools` workload cut it to 0.27 s.
  (In C this cost simply doesn't exist — a reminder that "fast client" means
  different things across runtimes.)
- **`OpenSSL.SSLStream` supports only `unsafe_read`/`unsafe_write`, not byte
  I/O.** The frame reader was rewritten around `unsafe_read` so the same code
  path drives cleartext `TCPSocket` and TLS transparently.
- **`Timer`-callback keepalive was flaky** (a callback that blocks on a
  response Channel starves the timer); a dedicated Task loop is reliable.
- **JET caught real type-instabilities** that C's static types make moot:
  `RegexMatch` captures are `Union{Nothing,SubString}`, and
  `(status, result)` returns with `result::Union{Nothing,T}` must be narrowed
  explicitly before use. Both are safe to ignore in C, load-bearing in Julia.
