# Plan 06: Storage Abstraction & Web Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spec phase 8. A `Storage` abstraction that dispatches on URL scheme,
with backends for XRootD (`root(s)://`, wrapping the Client), local paths,
HTTP/WebDAV (`http(s)://`, `dav(s)://`), and S3 (`s3(s)://`) — the multi-
protocol substrate the copy engine and tools (plan 07) build on.

**Architecture:** Layer 4 of the spec. A small `Storage` interface —
`storage_stat`, `storage_read` (streaming), `storage_write` (streaming),
`storage_list`, `storage_remove` — with one method set per backend, selected
by [`storage_for(url)`]. The XRootD backend delegates to `FileSystem`/`File`;
the web backends are built on HTTP.jl; S3 adds AWS Signature v4.

**Tech Stack:** HTTP.jl (client + in-process test server), URIs.jl, stdlib
SHA (SigV4 HMAC/SHA256).

## Global Constraints

Plans 01–05 constraints, plus (ground truth: libxrdc `url.c`, `webfile.c`,
`http*.c`, `s3.c`, `vfs_s3*.c`):

- URL schemes and default ports (url.c): `https`/`davs`/`s3s` → TLS, ports
  443; `http`/`dav`/`s3` → cleartext, ports 80; `s3`/`s3s` are S3-flavored.
- HTTP read: `GET` with `Range: bytes=off-` for partial/streaming; write:
  `PUT` (chunked or content-length); stat: `HEAD` (Content-Length →
  size, Last-Modified → mtime); WebDAV list: `PROPFIND` depth 1 → parse the
  multistatus XML for hrefs + sizes.
- S3 SigV4: canonical request → string-to-sign → signing key
  (HMAC chain date→region→service→"aws4_request") → `Authorization` header;
  `x-amz-content-sha256` is the payload hash (or `UNSIGNED-PAYLOAD` for
  streaming). Credentials from `$AWS_ACCESS_KEY_ID` /
  `$AWS_SECRET_ACCESS_KEY` / `$AWS_SESSION_TOKEN`, region from
  `$AWS_DEFAULT_REGION`. Validate the signer against the AWS-documented
  GET/PUT example vectors.

## Tasks

### Task 1: URL parsing + Storage interface
- [x] `Backend` scheme detection and `parse_url(url)` (scheme, host, port,
  path, tls); the abstract `Storage` interface with the five verbs and a
  `storage_for(url; kwargs...)` factory. Local + XRootD backends
  (XRootD delegates to FileSystem/File). Unit tests for parsing + local
  round trip; integration reuse of the XRootD backend against XRootD_jll.
  Commit `feat(storage): url parsing, interface, local + xrootd backends`.

### Task 2: HTTP / WebDAV backend
- [x] `WebStorage` on HTTP.jl: GET-with-range read, PUT write, HEAD stat,
  PROPFIND list. Tests against an in-process HTTP.jl server serving a temp
  dir (GET/HEAD/PUT round trip; a canned PROPFIND multistatus body parsed).
  Commit `feat(storage): http/webdav backend`.

### Task 3: S3 backend + SigV4
- [x] `sigv4_sign(...)` validated against the AWS example vectors; `S3Storage`
  (GET/PUT/HEAD/GET-bucket-list, path- and virtual-host style). Signer unit
  tests + an in-process mock S3 (HTTP.jl server asserting the Authorization
  header shape) round trip. Commit `feat(storage): s3 backend with sigv4`.

## Completion gate

Full `Pkg.test()` green including the in-process HTTP round trip and the
SigV4 vector tests.
