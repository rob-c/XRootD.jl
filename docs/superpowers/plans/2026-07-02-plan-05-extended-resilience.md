# Plan 05: Extended Operations & Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spec phase 6–7. Extended filesystem operations (xattr, statvfs,
prepare, vendor symlink/hardlink/readlink, remote checksum, deep locate)
plus connection resilience (redirect following, reconnect-with-replay,
keepalive).

**Architecture:** New Wire codecs + Client wrappers following the plan 02–03
patterns; resilience lives in the Session layer as a redirect/reconnect loop
around `roundtrip` for idempotent operations.

**Tech Stack:** existing stack.

## Global Constraints

Plans 01–04 constraints, plus (ground truth: libxrdc `fattr.c`, `ops_fs.c`,
`ops_ext.c`, `resilient.c`; protocol headers under
`src/protocols/root/protocol/`):

- **fattr** (kXR_fattr 3020): body fhandle[4] (0=path-based), subcode byte
  (Del=0 Get=1 List=2 Set=3), numattr byte, options byte
  (fa_isNew=0x01 set-guard, fa_aData=0x10 list-with-values), rsvd[9].
  Path-based payload: `"<path>\0"` + nvec + (set) vvec. nvec entry
  `[int16 rc=0][name\0]`; vvec entry `[int32 BE vlen][value]`. Get/Set/Del
  response: `[u8 errcount][u8 numattr][nvec-with-rc]` (Get appends a vvec);
  List response: NUL-separated names.
- **statvfs**: kXR_stat with options=kXR_vfs; response is the oss space
  report text `"<rw> <fs-nodes> <fs-free-kb> <fs-util%> <stage> ..."`
  (parse leniently — expose the raw string plus parsed free/total when the
  numeric fields are present).
- **vendor ext** (capability-gated via kXR_Qconfig "xrdfs.ext"):
  kXR_setattr 3500 (44-byte BE prefix + path), kXR_symlink 3501
  (payload `target * " " * link`, arg1len=len(target) at body 15:16),
  kXR_readlink 3502 (payload path; response = target, dlen bytes),
  kXR_link 3503 (payload `old * " " * new`, arg1len=len(old)). setattr
  prefix: flags i32 (sa_times=1 sa_owner=2), atime_s i64, atime_ns i64,
  mtime_s i64, mtime_ns i64, uid i32, gid i32.
- **prepare** (kXR_prepare 3021): body options byte
  (cancel=1 notify=2 noerrs=4 stage=8 wmode=16), prty byte, port u16,
  optionX u16 (evict), rsvd[10]; payload newline-separated paths.
- **checksum**: kXR_query infotype=kXR_Qcksum, arg=path; response
  `"<algo> <hexdigest>"`.
- **resilience**: on a transport sever, reconnect to the home endpoint
  (or the last redirect target) and replay idempotent ops. Redirect
  (kXR_redirect) is followed transparently for idempotent ops. Keepalive:
  a periodic kXR_ping when the connection is idle beyond a window. Bounded
  by a max-stall window (default 30s, env `XRDC_MAX_STALL_MS`); `no_retry`
  disables. Idempotency: reads/stat/dirlist/locate/query are replayable;
  mutations are replayed only when the transport never delivered the request.

## Tasks

### Task 1: Wire codecs — fattr, setattr, symlink/readlink/link, prepare
- [ ] Golden tests + implementations for `FattrGetRequest`/`FattrSetRequest`/
  `FattrDelRequest`/`FattrListRequest`, `SetattrRequest`, `SymlinkRequest`,
  `ReadlinkRequest`, `LinkRequest`, `PrepareRequest`; decoders
  `parse_fattr_getset`, `parse_fattr_list`, `parse_statvfs`. Commit
  `feat(wire): extended operation codecs`.

### Task 2: Client extended API
- [ ] `getxattr`/`setxattr`/`listxattr`/`removexattr`, `statvfs`,
  `symlink`/`hardlink`/`readlink`, `prepare`, `checksum` on `FileSystem`;
  `getxattr`/`setxattr`/`listxattr`/`removexattr` on `File` (fhandle form).
  Mock + integration tests (xattr and checksum against XRootD_jll; vendor
  symlink ops guarded on capability, tested against the mock since stock
  xrootd lacks them). Commit `feat(client): xattr, statvfs, prepare,
  links, checksum`.

### Task 3: Resilience — redirect following + reconnect/replay
- [ ] `roundtrip` grows an idempotency-aware retry wrapper: kXR_redirect →
  reconnect to the target and re-issue; transport sever → reconnect to home
  and replay (idempotent ops, or mutations proven un-sent) within the stall
  window. `FileSystem`/`File` mark each op's idempotency class. Mock tests:
  a redirect frame steers a stat to a second mock server; a mid-flight
  socket close triggers one reconnect+replay. Commit
  `feat(session): redirect following and reconnect-with-replay`.

### Task 4: Keepalive
- [ ] An idle-timer Task per connection sends kXR_ping after an idle window
  so long-lived handles survive server idle timeouts. Off by default in
  tests (configurable window). Commit `feat(session): idle keepalive`.

## Completion gate

Full `Pkg.test()` green including xattr/checksum/statvfs integration and the
resilience mock tests.
