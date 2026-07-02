# Plan 02: Session Layer & FileSystem-Op Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working native client: `Session` (connect → handshake → protocol →
login → unix auth, streamid-multiplexed sync ops) plus the public
`XRootD.XrdCl` FileSystem API — gated on the legacy 0.2.x
`test/legacy/testFileSystem.jl` passing unmodified against a real `xrootd`
server.

**Architecture:** Spec phases 2–3. Layer 2 (`Session/`) owns the TCP socket:
one reader Task routes response frames to per-streamid Channels; operations
are synchronous `roundtrip` calls that accumulate `kXR_oksofar` chunks and
honor `kXR_wait`. Layer 3 (`XrdCl` module = `Client/`) provides the 0.2.x
API: `FileSystem`, `(status, result)` tuples, `StatInfo`/`XRootDStatus`/flag
namespaces. `copy` needs bytes to flow, so the file open/read/write/close
wire codecs land here too (internal); the public `File` API is plan 03.

**Tech Stack:** Julia stdlib `Sockets`; test-only `XRootD_jll` (real server),
mock in-process TCP servers for Session unit tests.

## Global Constraints

All of plan 01's constraints, plus:

- Legacy tests run VERBATIM — `test/legacy/testFileSystem.jl` is not edited.
- Public module is `XRootD.XrdCl` (the 0.2.x name), so `using XRootD.XrdCl`
  keeps working.
- kXR mode bits == POSIX low 9 bits (0x100 = user-read … 0x001 = other-exec),
  so integer modes pass through unchanged.
- `kXR_mv` payload is `src * " " * dst` with `arg1len = ncodeunits(src)`
  (libxrdc `ops_fs.c`).
- unix auth credential: credtype `"unix"`, payload `"unix\0" * username`
  (libxrdc `sec/sec_unix.c`), single round.
- Stat lines may carry the optional extended tail
  `" <ctime> <atime> <mode-octal> <owner> <group>"` (stat_line.h); StatInfo
  must parse both forms.

## File Structure

```
src/Wire/requests.jl    +Open/Read/Write/Close/Sync + Mkdir/Rm/Rmdir/Mv/
                        Chmod/Truncate/Locate/Query requests
src/Wire/constants.jl   +open flags, mkdirpath, query codes, stat-flag bits
src/Wire/responses.jl   +extended stat tail, parse_locate, decode_open
src/Session/Session.jl  module: include connection.jl
src/Session/connection.jl  Connection, connect, roundtrip, reader task, close
src/Client/XrdCl.jl     module XrdCl: includes below, exports
src/Client/status.jl    XRootDStatus, isOK, isError
src/Client/responses.jl StatInfo, Location, ProtocolInfo + Base overloads
src/Client/enums.jl     OpenFlags, Access, DirListFlags, QueryCode, MkDirFlags
src/Client/filesystem.jl FileSystem + all ops incl. copy
test/wire/test_requests.jl, test_responses.jl   (extend)
test/session/test_connection.jl                 (mock-server tests)
test/client/test_types.jl                       (status/statinfo/enums)
test/runtests.jl        + integration block starting XRootD_jll xrootd
test/Project.toml       + XRootD_jll
```

---

### Task 1: Wire codecs for FS and file operations

**Interfaces produced** (all `<: Wire.Request`, encoded via `Wire.encode`):
- `MkdirRequest(path; mode::UInt16=0x0000, mkpath::Bool=false)` — body:
  byte 5 = options (0x01 = create parents), bytes 6:18 reserved,
  bytes 19:20 mode (u16 BE); payload = path.
- `RmRequest(path)`, `RmdirRequest(path)` — all-zero body; payload = path.
- `MvRequest(src, dst)` — bytes 5:18 reserved, bytes 19:20 `arg1len` (i16 BE
  = ncodeunits(src)); payload = `src * " " * dst`.
- `ChmodRequest(path, mode::UInt16)` — bytes 5:18 reserved, 19:20 mode.
- `TruncateRequest(path, size::Int64)` — bytes 5:8 fhandle (zeros for
  path-based), 9:16 offset (i64 BE), 17:20 reserved; payload = path.
- `LocateRequest(path; options::UInt16=0x0000)` — bytes 5:6 options
  (kXR_refresh…), rest reserved; payload = path.
- `QueryRequest(infotype::UInt16, args)` — bytes 5:6 infotype, 7:8 reserved,
  9:12 fhandle (zeros), 13:20 reserved; payload = args.
- `OpenRequest(path; mode::UInt16=0x0000, options::UInt16)` — bytes 5:6 mode,
  7:8 options, 9:10 optiont (0), 11:16 reserved, 17:20 fhtemplt (0);
  payload = path.
- `ReadRequest(fhandle::NTuple{4,UInt8}, offset::Int64, rlen::Int32)` —
  bytes 5:8 fhandle, 9:16 offset, 17:20 rlen.
- `WriteRequest(fhandle, offset::Int64, data::Vector{UInt8})` — bytes 5:8
  fhandle, 9:16 offset, 17:20 reserved; payload = data.
- `CloseRequest(fhandle)` — bytes 5:8 fhandle. `SyncRequest(fhandle)` — same.
- Constants: `kXR_compress=0x0001, kXR_delete=0x0002 (open truncate flag),
  kXR_force=0x0004, kXR_new=0x0008, kXR_open_read=0x0010,
  kXR_open_updt=0x0020, kXR_refresh=0x0080, kXR_mkpath=0x0100,
  kXR_open_apnd=0x0200, kXR_retstat=0x0400, kXR_open_wrto=0x8000` (UInt16);
  `kXR_mkdirpath=0x01`; query codes `kXR_QStats=1, kXR_QPrep=2, kXR_Qcksum=3,
  kXR_Qxattr=4, kXR_Qspace=5, kXR_Qconfig=7, kXR_Qvisa=8, kXR_Qopaque=16,
  kXR_Qopaquf=32, kXR_Qopaqug=64` (UInt16); stat flags `kXR_xset=0x01,
  kXR_isDir=0x02, kXR_other=0x04, kXR_offline=0x08, kXR_readable=0x10,
  kXR_writable=0x20, kXR_poscpend=0x40` (UInt32).
  The open flag keeps its protocol name `kXR_delete` (no collision — the rm
  opcode is `kXR_rm`).
- Response decoders: `decode_open(body) -> (; fhandle::NTuple{4,UInt8},
  cpsize::Int32, stat)` (stat = trailing ASCII stat line when kXR_retstat,
  else `nothing`); `parse_locate(body) -> Vector{@NamedTuple{node::Char,
  access::Char, address::String}}` from space-separated `XY<host:port>`
  tokens; extend `parse_stat_line` to return the optional extended tail
  `(; …, ctime, atime, mode::String, owner::String, group::String,
  has_ext::Bool)` (empty/zero when absent).

**Steps** (same TDD cycle as plan 01 tasks 5–7):
- [ ] Append golden-frame tests to `test/wire/test_requests.jl` for every
  request above (compute opcode hex from the DECIMAL constants:
  mkdir 3008=0x0bc0, mv 3009=0x0bc1, open 3010=0x0bc2, chmod 3002=0x0bba,
  rm 3014=0x0bc6, rmdir 3015=0x0bc7, truncate 3028=0x0bd4,
  locate 3027=0x0bd3, query 3001=0x0bb9, read 3013=0x0bc5,
  write 3019=0x0bcb, close 3003=0x0bbb, sync 3016=0x0bc8) and decoder tests
  to `test/wire/test_responses.jl` (locate tokens, extended stat line,
  open body with/without stat).
- [ ] Run: expect UndefVarError. Implement in `src/Wire/{constants,requests,
  responses}.jl`. Run: PASS. Format, commit
  `feat(wire): fs and file operation codecs`.

---

### Task 2: Session layer — connection, bring-up, roundtrip

**Interfaces produced** (module `XRootD.Session`):
- `Connection` (mutable): socket, host/port/username, `protover::UInt32`,
  `sessid`, `pending::Dict{UInt16,Channel{Tuple{Wire.ResponseHeader,Vector{UInt8}}}}`,
  `wlock::ReentrantLock`, `plock::ReentrantLock`, `nextsid::UInt16`,
  `reader::Task`, `closed::Bool`.
- `connect(host::AbstractString, port::Integer;
           username=get(ENV,"USER","nobody"), want_tls=false)::Connection` —
  handshake + kXR_protocol pipelined in ONE write (44 bytes, libxrdc
  conn.c); synchronous reads for the two replies; kXR_login; if the login
  sec trailer mentions `unix`, one `AuthRequest("unix", "unix\0user")`
  round; then starts the reader Task. TLS is plan 04 — `want_tls` errors.
- `roundtrip(conn, req::Wire.Request)::Tuple{Wire.ResponseHeader,Vector{UInt8}}`
  — allocates a streamid + Channel, writes the frame under `wlock`, then
  takes responses: `kXR_oksofar` accumulates body and continues;
  `kXR_wait` sleeps `Wire.wait_seconds(body)` then re-sends the same frame;
  anything else returns. Always unregisters the streamid.
- `Base.close(conn)` — closes socket; reader task fails all pending channels.
- Reader task: loop `read(sock, 8)` → `decode_header` → `read(sock, dlen)`;
  `kXR_attn` frames: `kXR_asynresp` re-routes the INNER header+body (body
  layout: actnum[4] rsvd[4] hdr[8] data[dlen-16]); `kXR_asyncms` logged with
  `@debug`; everything else routed by streamid. On socket EOF/error: put a
  synthetic `(header(status=kXR_error), errnum=3005/"connection lost")` to
  all pending and mark closed.
- Redirects are NOT followed here (single standalone server in scope);
  `roundtrip` returns the redirect header — the Client layer treats it as an
  error for now (plan 05 adds following).

**Steps:**
- [ ] Write `test/session/test_connection.jl` with an in-process mock server
  (Sockets listener Task that reads the 44-byte bring-up, replies with
  canned handshake/protocol/login frames, then answers one `PingRequest`
  with kXR_ok, one `DirlistRequest` with a 2-chunk kXR_oksofar + kXR_ok
  sequence, one `StatRequest` with kXR_wait(1s) then kXR_ok, and one
  `RmRequest` with kXR_error 3011). Assert bring-up state (protover,
  sessid), oksofar accumulation, wait retry, error passthrough, and that
  `close` fails pending requests.
- [ ] Run: fails (module missing). Implement `src/Session/`. Run: PASS.
  Format, commit `feat(session): connection bring-up and multiplexed roundtrip`.

---

### Task 3: Client types — XRootDStatus, StatInfo, enums

**Interfaces produced** (module `XRootD.XrdCl`, exported):
- `XRootDStatus(status=0x0000, code=0x0000, errNo=0, message="")`;
  `isOK(st) = st.status == 0x0000`; `isError`; `Base.show` renders
  `[SUCCESS]`/`[ERROR] (code, errNo): message`; built from wire responses via
  internal `status_from(hdr, body)`.
- `StatInfo` — fields `id::String, size::Int64, flags::UInt32,
  modtime::Int64, ctime::Int64, atime::Int64, mode::String, octmode::String,
  owner::String, group::String`. Built from the (possibly extended) stat
  line. `mode` is the 4-char octal string (e.g. `"0644"`), `octmode` the
  9-char symbolic form (`"rw-r--r--"`) derived from it. Base overloads:
  `isdir` (flags & kXR_isDir), `isfile` (!isdir && !(flags & kXR_other)),
  `isreadable`, `iswritable`; exported `isExecutable` (kXR_xset),
  `isOffline` (kXR_offline). `Base.show` prints all fields.
- `Location(address::String, node::Char, access::Char)` + `Base.show`;
  `ProtocolInfo(version::UInt32, hostinfo::UInt32)` + `Base.show`.
- Flag namespaces as `baremodule`s re-exporting wire values:
  `OpenFlags` (None=0, Compress=1, Delete=2, Force=4, New=8, Read=16,
  Update=32, Refresh=128, MakePath=256, Append=512, Write=0x8000),
  `Access` (UR=0x100, UW=0x080, UX=0x040, GR=0x020, GW=0x010, GX=0x008,
  OR=0x004, OW=0x002, OX=0x001, None=0),
  `DirListFlags` (None=0, Stat=1, Locate=2, Recursive=4, Merge=8, Chunked=16,
  Zip=32), `QueryCode` (Stats=1, Prepare=2, Checksum=3, XAttr=4, Space=5,
  Config=7, Visa=8, Opaque=16, OpaqueFile=32), `MkDirFlags` (None=0,
  MakePath=1). All UInt16 consts so `|` composes.

**Steps:**
- [ ] Write `test/client/test_types.jl`: status show/isOK; StatInfo from
  basic + extended lines incl. octmode derivation (`"0775"` →
  `"rwxrwxr-x"`), isdir/isfile/isreadable/isExecutable; enum spot values;
  Location/ProtocolInfo show smoke.
- [ ] Run: fails. Implement `src/Client/{status,responses,enums}.jl` +
  module `XrdCl` skeleton wired into `src/XRootD.jl`. Run: PASS. Format,
  commit `feat(client): XrdCl status/statinfo/enum types`.

---

### Task 4: FileSystem operations

**Interfaces produced** (exported from `XrdCl`; signatures identical to
0.2.x — legacy test is the contract):
- `FileSystem(url::String)` — parses `root://host[:port]`, lazily connects
  (`Session.connect`) on first use, reconnects if closed.
- `ping`, `Base.stat`, `locate(fs, path, flags)`, `query(fs, code, arg)`,
  `Base.readdir(fs, path, flags=DirListFlags.None; join=false, sort=false)`,
  `Base.walkdir(fs, root; topdown=true)` (Channel of
  `(root, dirs, files)`; errors close the channel with `ErrorException`),
  `Base.rm`, `Base.mv`, `Base.mkdir(fs, path, mode=Access.None)`,
  `rmdir`, `Base.chmod(fs, path, mode)`, `Base.truncate(fs, path, size)`,
  `protocol(fs)`, `Base.copy(fs, src, dest; force=false)`.
- All return `(XRootDStatus, result)`; `result` is `nothing` for mutations,
  `StatInfo`/`Vector{String}`/`Vector{Location}`/`String`/`ProtocolInfo`
  as in 0.2.x.
- `copy` implementation (internal helpers `open_file`, `read_at`,
  `write_at`, `close_file` over `Session.roundtrip` with the Task-1 file
  codecs): open src `kXR_open_read`; open dst with `kXR_open_updt |
  kXR_mkpath | (force ? kXR_delete : kXR_new)` mode 0o644; pump 1 MiB
  chunks; close both. Returns error status on any failed step (closing
  what was opened).
- `walkdir` uses `readdir`-with-dstat internally (entries + stats from one
  round trip per directory).

**Steps:**
- [ ] Extend the Task-2 mock server tests with a FileSystem-level test:
  `FileSystem` against the mock, `ping` + `stat` + error mapping
  (kXR_error 3011 → `!isOK(st)` with message).
- [ ] Run: fails. Implement `src/Client/filesystem.jl`. Run: PASS. Format,
  commit `feat(client): FileSystem operations`.

---

### Task 5: Integration — legacy testFileSystem.jl against a real server

**Steps:**
- [ ] Add `XRootD_jll` (uuid `cf5b7e95-2b45-53a5-8b71-ac0ecf6bbaa9`? — take
  the uuid from the registry at execution time, do not trust this line) to
  `test/Project.toml`.
- [ ] Extend `test/runtests.jl`: after unit testsets, when
  `XRootD_jll.is_available()`, start `xrootd` (serving default `/tmp`) as
  in the 0.2.x runtests (`run(ignorestatus(...); wait=false)` + readiness
  wait loop on TCP connect to 1094), `include("legacy/testFileSystem.jl")`,
  kill server in `finally`.
- [ ] Run the full suite. Fix empirically whatever the real server exposes
  differently (extended stat availability, login sec trailer, locate token
  shapes). The legacy file itself is NOT modified.
- [ ] Full `Pkg.test()` green. Format, commit
  `feat(client): legacy FileSystem parity against real xrootd`.

## Completion gate

`Pkg.test()` green including `test/legacy/testFileSystem.jl` verbatim against
the XRootD_jll server, plus all unit suites and quality gates.
