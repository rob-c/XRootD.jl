# Plan 07: Copy Engine & CLI Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spec phases 9–10. A backend-agnostic copy engine (chunked pump,
parallel in-flight chunks, post-copy checksum verification, recursive tree
copy) and Julia equivalents of the `xrdcp`, `xrdfs`, and checksum CLI tools —
callable functions plus thin `bin/*.jl` entry scripts.

**Architecture:** Layer 5. The copy engine pumps between any two
[`Storage`](@ref) backends. The tools are `Tools/` modules exposing a
`main(args)::Int` (exit code), wrapped by `bin/*.jl` launchers. Exit codes
mirror libxrdc `xrdc_shellcode`.

**Tech Stack:** existing stack; stdlib CRC32c/Adler for local checksum tools.

## Global Constraints

Plans 01–06 constraints, plus (ground truth: libxrdc `copy*.c`, `apps/`):

- Copy directions inferred from the two URLs' schemes; local↔remote and
  remote↔remote both flow through the client (no server TPC in this plan).
- Post-copy verification compares the destination's server checksum (or a
  recomputed local digest) against the source when both expose one.
- Recursive copy walks the source tree (dirlist/list) and recreates it under
  the destination.
- Checksum tools: `xrdadler32` (Adler-32), `xrdcrc32c` (CRC32c, hardware via
  stdlib), `xrdcrc64` (CRC-64/XZ, table-driven), `xrdckverify` (verify a
  file against its recorded checksum). Each works on a local path or a
  `root://` URL (pull bytes, compute).
- Exit codes: 0 success; 2 usage error; other = mapped from the operation's
  status (mirror `xrdc_shellcode`).

## Tasks

### Task 1: Copy engine
- [x] `copyfile(src_url, dst_url; force, verify, parallel)` over Storage: a
  chunked pump with a bounded window of in-flight reads (parallel chunks on
  a multiplexed connection), optional post-copy checksum verification;
  `copytree(src, dst)` recursive. Tests: local→local, and (integration)
  local→root and root→root via XRootD_jll, with a verify pass. Commit
  `feat(tools): backend-agnostic copy engine`.

### Task 2: Checksums
- [x] `Checksums` module: `adler32`, `crc32c`, `crc64xz` over an IO/bytes;
  `checksum_file(url, algo)` (local or root://); `verify_file(url)` against
  an xattr/`.cks` record. Unit tests vs known vectors; integration vs a
  root:// file. Commit `feat(tools): checksum algorithms`.

### Task 3: xrdcp
- [x] `Tools.Xrdcp.main(args)`: parse `[-f] [-r] [--verify] src dst`, drive
  the copy engine, map to an exit code. `bin/xrdcp.jl` launcher. Tests:
  invoke `main` in-process for local→root→local round trips; a byte-compare
  against the source. Commit `feat(tools): xrdcp`.

### Task 4: xrdfs
- [x] `Tools.Xrdfs.main(args)`: subcommands `ls`/`stat`/`mkdir`/`rm`/
  `rmdir`/`mv`/`cat`/`query`/`statvfs` against a `root://` host; a no-command
  interactive REPL loop. `bin/xrdfs.jl`. Tests: `main(["host","ls","/tmp"])`
  etc. against XRootD_jll, asserting output + exit code. Commit
  `feat(tools): xrdfs`.

### Task 5: checksum CLIs
- [x] `bin/xrdadler32.jl`, `bin/xrdcrc32c.jl`, `bin/xrdcrc64.jl`,
  `bin/xrdckverify.jl` over the Checksums module, each a `main(args)` +
  launcher with libxrdc-style output and exit codes; `--version` credits
  libxrdc. Tests: compute a known file's digest, verify pass/fail. Commit
  `feat(tools): checksum command-line tools`.

## Completion gate

Full `Pkg.test()` green including copy-engine integration (local↔root↔root)
and tool `main()` tests.
