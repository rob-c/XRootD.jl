# Plan 08: Cross-Implementation Parity Suite & 0.3.0 Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spec phase 11 + the dual-parity testing requirement. A
cross-implementation parity suite that runs the same scenarios through
XRootD.jl, the `libxrdc` binaries, and the official `xrdcp`/`xrdfs`, plus the
docs rewrite and 0.3.0 release preparation.

**Architecture:** A new integration tier that shells out to the reference
binaries and compares observable behavior with XRootD.jl. Documentation is
regenerated from the now-complete public API.

**Tech Stack:** existing stack; the reference binaries at
`nginx-xrootd/client/bin/` (libxrdc) and in `XRootD_jll` (official).

## Global Constraints

Plans 01–07 constraints, plus:

- The parity tier is skipped gracefully when a reference binary is absent
  (so CI without libxrdc still passes); it is enabled when the binaries are
  found.
- Comparisons assert IDENTICAL observable behavior: bytes moved, digests,
  directory listings, stat fields, and exit codes.
- Interoperability is crossed: a file written by one client is read back and
  verified by the others.

## Tasks

### Task 1: Reference-binary harness
- [ ] `test/parity/harness.jl`: locate the libxrdc binaries
  (`nginx-xrootd/client/bin/`) and the official ones (`XRootD_jll.xrdcp`,
  `XRootD_jll.xrdfs`); helpers to run each and capture stdout/exit code.
  A `parity_available()` gate. Commit `test(parity): reference-binary harness`.

### Task 2: Data-movement parity
- [ ] Same file copied to the server by XRootD.jl's `xrdcp` main, the
  official `xrdcp`, and libxrdc's `xrdcp`; assert byte-identical results and
  matching exit codes. Cross-read: each client reads what the others wrote.
  Commit `test(parity): xrdcp data-movement parity`.

### Task 3: Metadata + checksum parity
- [ ] `xrdfs ls`/`stat` output compared field-by-field across the three
  clients; checksum digests (`xrdadler32`/`xrdcrc32c`/`xrdcrc64`) compared
  against the libxrdc tools on the same inputs. Commit
  `test(parity): metadata and checksum parity`.

### Task 4: Documentation rewrite
- [ ] Rewrite `docs/src/index.md` and add API pages for the public modules
  (`XrdCl`, `Storage`, `Tools`); update the README getting-started for the
  native client; a migration note from 0.2.x. Ensure the Documenter build is
  clean (drop `warnonly` where possible). Commit `docs: 0.3 native-client
  documentation`.

### Task 5: Release prep
- [ ] Set `version = "0.3.0"`; write `docs/src/release_notes.md` for 0.3;
  final `Pkg.test()`; update the top-level module docstring's layer list to
  reflect all shipped layers. Commit `release: prepare 0.3.0`.

## Completion gate

Full `Pkg.test()` green including the parity tier (where reference binaries
exist); docs build clean; version at 0.3.0.
