# Plan 01: Foundation & Wire Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the CxxWrap binding and land `XRootD.Wire` — pure, I/O-free
codecs for the XRootD wire protocol — fully covered by golden-frame unit
tests, with formatter/Aqua/JET/CI quality gates live.

**Architecture:** Layer 1 of the approved spec
(`docs/superpowers/specs/2026-07-01-pure-julia-client-design.md`): request
structs that encode to exact wire bytes, and response decoders that turn
bytes into named tuples. No sockets anywhere in this plan — everything is
testable against literal byte vectors. Plan 02 (Session) consumes these
codecs.

**Tech Stack:** Julia ≥ 1.10, stdlib only (`Test`); dev/test tools:
JuliaFormatter (blue style), Aqua.jl, JET.jl.

## Global Constraints

- Wire-format ground truth: `nginx-xrootd/src/protocol/` headers — cite the
  specific header in each docstring. Behavior ground truth: `libxrdc`
  (`nginx-xrootd/client/lib/`).
- Attribution: module docstrings credit libxrdc (spec "Attribution" section).
- All multi-byte wire integers are big-endian.
- Paths on the wire carry NO trailing NUL: `dlen = ncodeunits(path)`
  (libxrdc `ops_fs.c` uses `strlen`).
- Constants keep their protocol names verbatim (`kXR_stat`, `ROOTD_PQ`) even
  where that departs from Julia naming style — traceability to the spec and
  C headers wins.
- Every public symbol gets a docstring. Blue formatting style, enforced.
- The legacy 0.2.x tests are moved (content-identical) to `test/legacy/` and
  NOT run by this plan — they become the acceptance gate for plans 02–03.
- Julia compat floor: 1.10. No CxxWrap, no JLL package dependencies.

---

### Task 1: Package foundation reset

Strip the CxxWrap machinery, create the new module skeleton, formatter
config, and a green (smoke-only) test suite.

**Files:**
- Modify: `Project.toml` (full replacement)
- Delete: `gen/` (whole directory), `src/File.jl`, `src/FileSystem.jl`,
  `src/Responses.jl`, `src/XrdCl.jl`
- Modify: `src/XRootD.jl` (full replacement)
- Create: `src/Wire/Wire.jl`, `.JuliaFormatter.toml`
- Move: `test/testFile.jl` → `test/legacy/testFile.jl`,
  `test/testFileSystem.jl` → `test/legacy/testFileSystem.jl` (content
  unchanged — `git mv` only)
- Modify: `test/runtests.jl` (full replacement)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: module `XRootD` containing submodule `XRootD.Wire`;
  `Pkg.test()` green; later tasks append `include(...)` lines to
  `src/Wire/Wire.jl` and `test/runtests.jl`.

- [x] **Step 1: Remove the CxxWrap machinery and move legacy tests**

```bash
cd /home/rcurrie/HEP-x/XRootD.jl
git rm -r gen
git rm src/File.jl src/FileSystem.jl src/Responses.jl src/XrdCl.jl
mkdir -p test/legacy
git mv test/testFile.jl test/legacy/testFile.jl
git mv test/testFileSystem.jl test/legacy/testFileSystem.jl
```

- [x] **Step 2: Replace `Project.toml`**

```toml
name = "XRootD"
uuid = "164e3b87-dc46-4cbc-97a6-5b310108fce0"
authors = ["Pere Mato <pere.mato@cern.ch>"]
version = "0.3.0-DEV"

[compat]
Aqua = "0.8"
JET = "0.9, 0.10"
julia = "1.10"

[extras]
Aqua = "4c88cf16-eb10-579e-8560-4a9242c79595"
JET = "c3a54625-cd67-489e-a8e7-0a5a0ff4e31b"
Test = "8dfed614-e22c-5e08-85e1-65c5234f0b40"

[targets]
test = ["Aqua", "JET", "Test"]
```

- [x] **Step 3: Replace `src/XRootD.jl`**

```julia
"""
    XRootD

Pure-Julia client for the [XRootD](https://xrootd.slac.stanford.edu) protocol:
high-performance, scalable, fault-tolerant access to data repositories.

As of 0.3, XRootD.jl no longer wraps the XrdCl C++ library. The protocol is
implemented natively in Julia, in layers:

- [`XRootD.Wire`](@ref) — wire-format codecs (no I/O).
- `XRootD.Session` — connections, auth, request multiplexing (plan 02).
- Client `File`/`FileSystem` API, web backends, and tools follow in later
  plans; see `docs/superpowers/plans/2026-07-02-pure-julia-client-roadmap.md`.

## Attribution

The wire-format ground truth, client semantics, and architecture implemented
here were developed in the `libxrdc` pure-C client and protocol reference of
the nginx-xrootd project (`client/lib/`, `src/protocol/`). This package is a
Julia translation of that prior work.
"""
module XRootD

include("Wire/Wire.jl")

end # module XRootD
```

- [x] **Step 4: Create `src/Wire/Wire.jl`**

```julia
"""
    XRootD.Wire

Layer 1 of the client: pure codecs for the XRootD `root://` wire protocol.
Encodes client requests to exact byte frames and decodes server response
bytes into plain Julia values. Performs **no I/O** — every function here is
testable against literal byte vectors.

Layouts follow the nginx-xrootd protocol reference (`src/protocol/opcodes.h`,
`wire_core_requests.h`, `frame_hdr.h`, `flags.h`), cross-checked against the
official `XProtocol.hh`, and match what the `libxrdc` C client puts on the
wire.
"""
module Wire

end # module Wire
```

- [x] **Step 5: Create `.JuliaFormatter.toml`**

```toml
style = "blue"
```

- [x] **Step 6: Replace `test/runtests.jl`**

```julia
using Test
using XRootD

@testset verbose = true "XRootD.jl" begin
    @testset "package smoke" begin
        @test isdefined(XRootD, :Wire)
    end
end
```

- [x] **Step 7: Run the test suite**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS (1 test).

- [x] **Step 8: Format and commit**

```bash
julia -e 'using Pkg; Pkg.activate(; temp=true); Pkg.add("JuliaFormatter"); using JuliaFormatter; format(".")'
git add -A
git commit -m "refactor!: remove CxxWrap binding, start pure-Julia 0.3 skeleton"
```

---

### Task 2: Big-endian byte primitives

**Files:**
- Create: `src/Wire/primitives.jl`
- Modify: `src/Wire/Wire.jl` (add include)
- Create: `test/wire/test_primitives.jl`
- Modify: `test/runtests.jl` (add include)

**Interfaces:**
- Consumes: nothing.
- Produces (used by every later Wire file):
  `get_u16(buf, off)::UInt16`, `get_u32(buf, off)::UInt32`,
  `get_u64(buf, off)::UInt64`, `set_u16!(buf, off, v)`, `set_u32!(buf, off, v)`,
  `set_u64!(buf, off, v)`, `set_bytes!(buf, off, src)`,
  `set_padded_string!(buf, off, width, s)::Nothing`,
  `get_bounded_string(buf, off, maxlen)::String`.
  All offsets are 1-based. Setters return `buf`; all are bounds-checked.

- [x] **Step 1: Write the failing test — `test/wire/test_primitives.jl`**

```julia
using XRootD.Wire:
    get_u16, get_u32, get_u64, set_u16!, set_u32!, set_u64!,
    set_bytes!, set_padded_string!, get_bounded_string

@testset "Wire primitives" begin
    @testset "big-endian round trips" begin
        buf = zeros(UInt8, 12)
        set_u16!(buf, 1, 0x0bbe)
        @test buf[1:2] == UInt8[0x0b, 0xbe]
        @test get_u16(buf, 1) === 0x0bbe

        set_u32!(buf, 3, 0x00000520)
        @test buf[3:6] == UInt8[0x00, 0x00, 0x05, 0x20]
        @test get_u32(buf, 3) === 0x00000520

        set_u64!(buf, 5, 0x0102030405060708)
        @test buf[5:12] == UInt8[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        @test get_u64(buf, 5) === 0x0102030405060708
    end

    @testset "bounds are checked" begin
        buf = zeros(UInt8, 4)
        @test_throws BoundsError get_u32(buf, 2)
        @test_throws BoundsError set_u16!(buf, 4, 0x0001)
    end

    @testset "byte and string fields" begin
        buf = zeros(UInt8, 8)
        set_bytes!(buf, 3, UInt8[0xaa, 0xbb])
        @test buf == UInt8[0, 0, 0xaa, 0xbb, 0, 0, 0, 0]

        fill!(buf, 0xff)
        set_padded_string!(buf, 1, 8, "julia")          # NUL-padded to width
        @test buf == UInt8[0x6a, 0x75, 0x6c, 0x69, 0x61, 0x00, 0x00, 0x00]
        set_padded_string!(buf, 1, 4, "toolongname")    # truncated at width
        @test buf[1:4] == UInt8[0x74, 0x6f, 0x6f, 0x6c]

        # bounded string: stops at NUL, never reads past maxlen
        raw = UInt8[0x68, 0x69, 0x00, 0x78]
        @test get_bounded_string(raw, 1, 4) == "hi"
        @test get_bounded_string(raw, 1, 2) == "hi"
        @test get_bounded_string(UInt8[0x61, 0x62], 1, 2) == "ab"  # no NUL on wire
    end
end
```

- [x] **Step 2: Add `include("wire/test_primitives.jl")` inside the top
  testset in `test/runtests.jl`, then run to verify it fails**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: FAIL — `UndefVarError` (`get_u16` not defined in `XRootD.Wire`).

- [x] **Step 3: Write `src/Wire/primitives.jl`**

```julia
# Big-endian accessors over byte buffers. The XRootD wire is big-endian
# throughout; these are the only functions in the package that touch
# individual wire bytes (mirrors nginx-xrootd frame_hdr.h's accessor set).
# All offsets are 1-based.

"""
    get_u16(buf::AbstractVector{UInt8}, off::Integer) -> UInt16

Read a big-endian `UInt16` from `buf` starting at 1-based offset `off`.
"""
function get_u16(buf::AbstractVector{UInt8}, off::Integer)
    checkbounds(buf, off:(off + 1))
    return (UInt16(buf[off]) << 8) | UInt16(buf[off + 1])
end

"""
    get_u32(buf::AbstractVector{UInt8}, off::Integer) -> UInt32

Read a big-endian `UInt32` from `buf` starting at 1-based offset `off`.
"""
function get_u32(buf::AbstractVector{UInt8}, off::Integer)
    checkbounds(buf, off:(off + 3))
    v = UInt32(0)
    for i in 0:3
        v = (v << 8) | UInt32(buf[off + i])
    end
    return v
end

"""
    get_u64(buf::AbstractVector{UInt8}, off::Integer) -> UInt64

Read a big-endian `UInt64` from `buf` starting at 1-based offset `off`.
"""
function get_u64(buf::AbstractVector{UInt8}, off::Integer)
    checkbounds(buf, off:(off + 7))
    v = UInt64(0)
    for i in 0:7
        v = (v << 8) | UInt64(buf[off + i])
    end
    return v
end

"""
    set_u16!(buf::AbstractVector{UInt8}, off::Integer, v::UInt16) -> buf

Write `v` big-endian into `buf` at 1-based offset `off`.
"""
function set_u16!(buf::AbstractVector{UInt8}, off::Integer, v::UInt16)
    checkbounds(buf, off:(off + 1))
    buf[off] = (v >> 8) % UInt8
    buf[off + 1] = v % UInt8
    return buf
end

"""
    set_u32!(buf::AbstractVector{UInt8}, off::Integer, v::UInt32) -> buf

Write `v` big-endian into `buf` at 1-based offset `off`.
"""
function set_u32!(buf::AbstractVector{UInt8}, off::Integer, v::UInt32)
    checkbounds(buf, off:(off + 3))
    for i in 0:3
        buf[off + i] = (v >> (8 * (3 - i))) % UInt8
    end
    return buf
end

"""
    set_u64!(buf::AbstractVector{UInt8}, off::Integer, v::UInt64) -> buf

Write `v` big-endian into `buf` at 1-based offset `off`.
"""
function set_u64!(buf::AbstractVector{UInt8}, off::Integer, v::UInt64)
    checkbounds(buf, off:(off + 7))
    for i in 0:7
        buf[off + i] = (v >> (8 * (7 - i))) % UInt8
    end
    return buf
end

"""
    set_bytes!(buf::AbstractVector{UInt8}, off::Integer, src::AbstractVector{UInt8}) -> buf

Copy `src` into `buf` starting at 1-based offset `off`.
"""
function set_bytes!(buf::AbstractVector{UInt8}, off::Integer, src::AbstractVector{UInt8})
    checkbounds(buf, off:(off + length(src) - 1))
    copyto!(buf, off, src, 1, length(src))
    return buf
end

"""
    set_padded_string!(buf::AbstractVector{UInt8}, off::Integer, width::Integer, s::AbstractString) -> buf

Write `s` into the fixed `width`-byte field at `off`: NUL-padded when shorter,
truncated when longer (the wire contract of e.g. `ClientLoginRequest.username`
— NUL-padded, NOT NUL-terminated at exactly `width` bytes).
"""
function set_padded_string!(
    buf::AbstractVector{UInt8}, off::Integer, width::Integer, s::AbstractString
)
    checkbounds(buf, off:(off + width - 1))
    bytes = codeunits(s)
    n = min(length(bytes), width)
    copyto!(buf, off, bytes, 1, n)
    for i in n:(width - 1)
        buf[off + i] = 0x00
    end
    return buf
end

"""
    get_bounded_string(buf::AbstractVector{UInt8}, off::Integer, maxlen::Integer) -> String

Read at most `maxlen` bytes from `buf` at `off`, stopping early at a NUL.
Wire strings are NOT guaranteed NUL-terminated (see frame_hdr.h on the
kXR_error message) — never assume a terminator exists.
"""
function get_bounded_string(buf::AbstractVector{UInt8}, off::Integer, maxlen::Integer)
    maxlen <= 0 && return ""
    checkbounds(buf, off:(off + maxlen - 1))
    last = off + maxlen - 1
    stop = last
    for i in off:last
        if buf[i] == 0x00
            stop = i - 1
            break
        end
    end
    return String(buf[off:stop])
end
```

- [x] **Step 4: Add `include("primitives.jl")` inside `module Wire` in
  `src/Wire/Wire.jl`, run tests to verify they pass**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS.

- [x] **Step 5: Format and commit**

```bash
julia -e 'using Pkg; Pkg.activate(; temp=true); Pkg.add("JuliaFormatter"); using JuliaFormatter; format(".")'
git add src/Wire test/wire test/runtests.jl
git commit -m "feat(wire): big-endian byte primitives"
```

---

### Task 3: Protocol constants

**Files:**
- Create: `src/Wire/constants.jl`
- Modify: `src/Wire/Wire.jl` (add `include("constants.jl")` after primitives)
- Create: `test/wire/test_constants.jl`
- Modify: `test/runtests.jl` (add include)

**Interfaces:**
- Consumes: nothing.
- Produces: `const kXR_*` opcode/status/flag constants and
  `request_name(id::Integer)::String`. Exact names and types below — later
  tasks and plans use them verbatim.

- [x] **Step 1: Write the failing test — `test/wire/test_constants.jl`**

```julia
using XRootD.Wire:
    kXR_auth, kXR_query, kXR_dirlist, kXR_protocol, kXR_login, kXR_ping,
    kXR_stat, kXR_clone, kXR_setattr, kXR_link, kXR_ok, kXR_oksofar,
    kXR_error, kXR_redirect, kXR_wait, kXR_status, ROOTD_PQ,
    kXR_PROTOCOLVERSION, kXR_secreqs, kXR_ableTLS, kXR_wantTLS, kXR_ExpLogin,
    kXR_asyncap, kXR_ver005, kXR_dstat, kXR_vfs, SESSION_ID_LEN, request_name

@testset "Wire constants" begin
    # spot-check against nginx-xrootd src/protocol/opcodes.h
    @test kXR_auth === UInt16(3000)
    @test kXR_dirlist === UInt16(3004)
    @test kXR_protocol === UInt16(3006)
    @test kXR_login === UInt16(3007)
    @test kXR_ping === UInt16(3011)
    @test kXR_stat === UInt16(3017)
    @test kXR_clone === UInt16(3032)
    @test kXR_setattr === UInt16(3500)   # nginx-xrootd vendor extension
    @test kXR_link === UInt16(3503)

    @test kXR_ok === UInt16(0)
    @test kXR_oksofar === UInt16(4000)
    @test kXR_error === UInt16(4003)
    @test kXR_redirect === UInt16(4004)
    @test kXR_wait === UInt16(4005)
    @test kXR_status === UInt16(4007)

    @test ROOTD_PQ === UInt32(2012)
    @test kXR_PROTOCOLVERSION === UInt32(0x00000520)
    @test kXR_secreqs | kXR_ableTLS === 0x03
    @test kXR_wantTLS === 0x04
    @test kXR_ExpLogin === 0x03
    @test kXR_asyncap | kXR_ver005 === 0x85
    @test kXR_dstat === 0x02
    @test kXR_vfs === 0x01
    @test SESSION_ID_LEN == 16

    @test request_name(3017) == "kXR_stat"
    @test request_name(3501) == "kXR_symlink"
    @test request_name(42) == "kXR_unknown(42)"
end
```

- [x] **Step 2: Add the runtests include, run to verify it fails**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: FAIL with `UndefVarError: kXR_auth`.

- [x] **Step 3: Write `src/Wire/constants.jl`**

```julia
# XRootD protocol constants. Names are kept verbatim from the protocol
# vocabulary (nginx-xrootd src/protocol/opcodes.h + flags.h) so every value
# is greppable against the C reference; this deliberately departs from Julia
# naming style.

#! format: off

# ---- request opcodes (ClientRequestHdr.requestid) ----
const kXR_auth      = UInt16(3000)
const kXR_query     = UInt16(3001)
const kXR_chmod     = UInt16(3002)
const kXR_close     = UInt16(3003)
const kXR_dirlist   = UInt16(3004)
const kXR_gpfile    = UInt16(3005)
const kXR_protocol  = UInt16(3006)
const kXR_login     = UInt16(3007)
const kXR_mkdir     = UInt16(3008)
const kXR_mv        = UInt16(3009)
const kXR_open      = UInt16(3010)
const kXR_ping      = UInt16(3011)
const kXR_chkpoint  = UInt16(3012)
const kXR_read      = UInt16(3013)
const kXR_rm        = UInt16(3014)
const kXR_rmdir     = UInt16(3015)
const kXR_sync      = UInt16(3016)
const kXR_stat      = UInt16(3017)
const kXR_set       = UInt16(3018)
const kXR_write     = UInt16(3019)
const kXR_fattr     = UInt16(3020)
const kXR_prepare   = UInt16(3021)
const kXR_statx     = UInt16(3022)
const kXR_endsess   = UInt16(3023)
const kXR_bind      = UInt16(3024)
const kXR_readv     = UInt16(3025)
const kXR_pgwrite   = UInt16(3026)
const kXR_locate    = UInt16(3027)
const kXR_truncate  = UInt16(3028)
const kXR_sigver    = UInt16(3029)
const kXR_pgread    = UInt16(3030)
const kXR_writev    = UInt16(3031)
const kXR_clone     = UInt16(3032)

# ---- nginx-xrootd vendor extensions (capability-negotiated via
# kXR_Qconfig "xrdfs.ext"; never sent to stock servers) ----
const kXR_setattr   = UInt16(3500)
const kXR_symlink   = UInt16(3501)
const kXR_readlink  = UInt16(3502)
const kXR_link      = UInt16(3503)

# ---- response status (ServerResponseHdr.status) ----
const kXR_ok        = UInt16(0)
const kXR_oksofar   = UInt16(4000)
const kXR_attn      = UInt16(4001)
const kXR_authmore  = UInt16(4002)
const kXR_error     = UInt16(4003)
const kXR_redirect  = UInt16(4004)
const kXR_wait      = UInt16(4005)
const kXR_waitresp  = UInt16(4006)
const kXR_status    = UInt16(4007)

# ---- kXR_attn action codes (still-active subset) ----
const kXR_asyncms   = UInt32(5002)
const kXR_asynresp  = UInt32(5008)

# ---- handshake / kXR_protocol ----
const ROOTD_PQ             = UInt32(2012)        # 5th word of the client hello
const kXR_PROTOCOLVERSION  = UInt32(0x00000520)  # protocol 5.2.0
const kXR_secreqs  = 0x01  # request the server's security-protocol trailer
const kXR_ableTLS  = 0x02  # client can upgrade to in-protocol TLS
const kXR_wantTLS  = 0x04  # client requires TLS - abort if unavailable
const kXR_ExpLogin = 0x03  # "a kXR_login follows"

# ---- kXR_login capver ----
const kXR_asyncap = 0x80   # client handles asynchronous responses
const kXR_ver005  = 0x05   # XRootD v5 client (TLS + sigver capable)

const SESSION_ID_LEN = 16  # opaque sessid bytes in the login response

# ---- kXR_dirlist options ----
const kXR_online = 0x01
const kXR_dstat  = 0x02
const kXR_dcksm  = 0x04

# ---- kXR_stat options ----
const kXR_vfs = 0x01

#! format: on

const _REQUEST_NAMES = Dict{UInt16,String}(
    kXR_auth => "kXR_auth",
    kXR_query => "kXR_query",
    kXR_chmod => "kXR_chmod",
    kXR_close => "kXR_close",
    kXR_dirlist => "kXR_dirlist",
    kXR_gpfile => "kXR_gpfile",
    kXR_protocol => "kXR_protocol",
    kXR_login => "kXR_login",
    kXR_mkdir => "kXR_mkdir",
    kXR_mv => "kXR_mv",
    kXR_open => "kXR_open",
    kXR_ping => "kXR_ping",
    kXR_chkpoint => "kXR_chkpoint",
    kXR_read => "kXR_read",
    kXR_rm => "kXR_rm",
    kXR_rmdir => "kXR_rmdir",
    kXR_sync => "kXR_sync",
    kXR_stat => "kXR_stat",
    kXR_set => "kXR_set",
    kXR_write => "kXR_write",
    kXR_fattr => "kXR_fattr",
    kXR_prepare => "kXR_prepare",
    kXR_statx => "kXR_statx",
    kXR_endsess => "kXR_endsess",
    kXR_bind => "kXR_bind",
    kXR_readv => "kXR_readv",
    kXR_pgwrite => "kXR_pgwrite",
    kXR_locate => "kXR_locate",
    kXR_truncate => "kXR_truncate",
    kXR_sigver => "kXR_sigver",
    kXR_pgread => "kXR_pgread",
    kXR_writev => "kXR_writev",
    kXR_clone => "kXR_clone",
    kXR_setattr => "kXR_setattr",
    kXR_symlink => "kXR_symlink",
    kXR_readlink => "kXR_readlink",
    kXR_link => "kXR_link",
)

"""
    request_name(id::Integer) -> String

The protocol name of a request opcode (`3017` → `"kXR_stat"`), for traces and
error messages. Unknown ids render as `"kXR_unknown(id)"`. Mirrors libxrdc's
`xrdc_reqid_name`.
"""
function request_name(id::Integer)
    return get(_REQUEST_NAMES, UInt16(id), "kXR_unknown($(Int(id)))")
end
```

- [x] **Step 4: Add the Wire.jl include, run tests to verify they pass**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS.

- [x] **Step 5: Format and commit**

```bash
julia -e 'using Pkg; Pkg.activate(; temp=true); Pkg.add("JuliaFormatter"); using JuliaFormatter; format(".")'
git add src/Wire/constants.jl src/Wire/Wire.jl test/wire/test_constants.jl test/runtests.jl
git commit -m "feat(wire): kXR protocol constants"
```

---

### Task 4: Frame codecs — handshake, request header, response header

**Files:**
- Create: `src/Wire/frames.jl`
- Modify: `src/Wire/Wire.jl` (add `include("frames.jl")` after constants)
- Create: `test/wire/test_frames.jl`
- Modify: `test/runtests.jl` (add include)

**Interfaces:**
- Consumes: primitives (Task 2), constants (Task 3).
- Produces:
  - `const HANDSHAKE::Vector{UInt8}` (the 20-byte client hello),
  - `abstract type Request end` with the extension points
    `requestid(::Request)::UInt16`, `body!(frame, ::Request)`,
    `payload(::Request)::AbstractVector{UInt8}` (defaults: no-op body, empty
    payload),
  - `encode(req::Request, streamid::UInt16)::Vector{UInt8}`,
  - `struct ResponseHeader; streamid::UInt16; status::UInt16; dlen::UInt32; end`,
  - `decode_header(bytes)::ResponseHeader`,
  - `const REQUEST_HDRLEN = 24`, `const RESPONSE_HDRLEN = 8`.
  Plan 02's Session writes `encode(...)` output to the socket and feeds the
  first 8 read bytes to `decode_header`.

- [x] **Step 1: Write the failing test — `test/wire/test_frames.jl`**

```julia
using XRootD.Wire
using XRootD.Wire:
    HANDSHAKE, Request, ResponseHeader, decode_header, encode,
    REQUEST_HDRLEN, RESPONSE_HDRLEN, requestid, body!, payload

# A minimal fake request to exercise the generic encoder without depending
# on the real request structs (Task 6).
struct FakeRequest <: Wire.Request end
Wire.requestid(::FakeRequest) = UInt16(3011)           # kXR_ping

struct FakePayloadRequest <: Wire.Request end
Wire.requestid(::FakePayloadRequest) = UInt16(3017)    # kXR_stat
Wire.payload(::FakePayloadRequest) = codeunits("/tmp")

@testset "Wire frames" begin
    @testset "client hello is byte-exact" begin
        # ClientInitHandShake (wire_core_requests.h): three zero words,
        # fourth = 4, fifth = ROOTD_PQ (2012 = 0x07dc).
        @test HANDSHAKE == UInt8[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x04, 0, 0, 0x07, 0xdc,
        ]
        @test length(HANDSHAKE) == 20
    end

    @testset "request framing" begin
        frame = encode(FakeRequest(), UInt16(0x0003))
        @test length(frame) == REQUEST_HDRLEN
        @test frame == UInt8[
            0x00, 0x03, 0x0b, 0xc3,                    # streamid, kXR_ping
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # body
            0x00, 0x00, 0x00, 0x00,                    # dlen = 0
        ]

        frame = encode(FakePayloadRequest(), UInt16(0x0005))
        @test length(frame) == REQUEST_HDRLEN + 4
        @test frame[21:24] == UInt8[0x00, 0x00, 0x00, 0x04]   # dlen = 4
        @test frame[25:28] == codeunits("/tmp")               # no trailing NUL
    end

    @testset "response header decode" begin
        hdr = decode_header(UInt8[0x00, 0x07, 0x0f, 0xa4, 0x00, 0x00, 0x00, 0x10])
        @test hdr === ResponseHeader(0x0007, UInt16(4004), UInt32(16))  # kXR_redirect
        @test_throws ArgumentError decode_header(UInt8[0x00])
    end
end
```

- [x] **Step 2: Add the runtests include, run to verify it fails**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: FAIL with `UndefVarError: HANDSHAKE`.

- [x] **Step 3: Write `src/Wire/frames.jl`**

```julia
# Frame-level codecs: the 20-byte client hello, the 24-byte ClientRequestHdr,
# and the 8-byte ServerResponseHdr (nginx-xrootd wire_core_requests.h,
# frame_hdr.h).

"Length in bytes of the ClientRequestHdr that starts every request frame."
const REQUEST_HDRLEN = 24

"Length in bytes of the ServerResponseHdr that starts every response frame."
const RESPONSE_HDRLEN = 8

"""
    HANDSHAKE

The fixed 20-byte `ClientInitHandShake` sent immediately after TCP connect:
three zero words, then `4`, then `ROOTD_PQ` (2012), all big-endian. The
server validates these exact bytes before anything else happens.
"""
const HANDSHAKE = let hs = zeros(UInt8, 20)
    set_u32!(hs, 13, UInt32(4))
    set_u32!(hs, 17, ROOTD_PQ)
    hs
end

"""
    Request

Abstract supertype of every client request. A concrete request defines:

- `requestid(req)::UInt16` — its `kXR_*` opcode (required);
- `body!(frame, req)` — write its parameters into bytes 5:20 of the 24-byte
  header (optional; default leaves them zero);
- `payload(req)::AbstractVector{UInt8}` — the bytes following the header
  (optional; default empty). `dlen` is derived from its length.

[`encode`](@ref) turns any `Request` into wire bytes.
"""
abstract type Request end

"""
    requestid(req::Request) -> UInt16

The `kXR_*` opcode of `req`. Every concrete request must implement this.
"""
function requestid end

"""
    body!(frame::Vector{UInt8}, req::Request) -> frame

Write the request's 16 parameter bytes into `frame[5:20]`. The default
writes nothing (all-zero body, e.g. `kXR_ping`).
"""
body!(frame::Vector{UInt8}, ::Request) = frame

"""
    payload(req::Request) -> AbstractVector{UInt8}

The payload bytes that follow the 24-byte header (default: none).
"""
payload(::Request) = UInt8[]

"""
    encode(req::Request, streamid::UInt16) -> Vector{UInt8}

Serialize `req` as a complete wire frame: 24-byte `ClientRequestHdr`
(streamid, opcode, 16 parameter bytes, dlen) followed by the payload.
`streamid` is owned by the Session layer, which stamps each in-flight
request with a distinct id and matches responses back by it.
"""
function encode(req::Request, streamid::UInt16)
    pl = payload(req)
    frame = zeros(UInt8, REQUEST_HDRLEN + length(pl))
    set_u16!(frame, 1, streamid)
    set_u16!(frame, 3, requestid(req))
    body!(frame, req)
    set_u32!(frame, 21, UInt32(length(pl)))
    isempty(pl) || set_bytes!(frame, REQUEST_HDRLEN + 1, pl)
    return frame
end

encode(req::Request, streamid::Integer) = encode(req, UInt16(streamid))

"""
    ResponseHeader

Decoded `ServerResponseHdr`: `streamid` echoes the request's id, `status` is
`kXR_ok` / `kXR_error` / `kXR_oksofar` / ..., and `dlen` bytes of body follow
on the wire.
"""
struct ResponseHeader
    streamid::UInt16
    status::UInt16
    dlen::UInt32
end

"""
    decode_header(bytes::AbstractVector{UInt8}) -> ResponseHeader

Decode the leading 8-byte `ServerResponseHdr` of a response frame.
"""
function decode_header(bytes::AbstractVector{UInt8})
    if length(bytes) < RESPONSE_HDRLEN
        throw(ArgumentError("response header needs 8 bytes, got $(length(bytes))"))
    end
    return ResponseHeader(get_u16(bytes, 1), get_u16(bytes, 3), get_u32(bytes, 5))
end
```

- [x] **Step 4: Add the Wire.jl include, run tests to verify they pass**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS.

- [x] **Step 5: Format and commit**

```bash
julia -e 'using Pkg; Pkg.activate(; temp=true); Pkg.add("JuliaFormatter"); using JuliaFormatter; format(".")'
git add src/Wire/frames.jl src/Wire/Wire.jl test/wire/test_frames.jl test/runtests.jl
git commit -m "feat(wire): handshake and request/response frame codecs"
```

---

### Task 5: Bootstrap request codecs — protocol, login, auth, ping

**Files:**
- Create: `src/Wire/requests.jl`
- Modify: `src/Wire/Wire.jl` (add `include("requests.jl")` after frames)
- Create: `test/wire/test_requests.jl`
- Modify: `test/runtests.jl` (add include)

**Interfaces:**
- Consumes: `Request`/`encode`/`body!`/`payload` (Task 4), constants (Task 3),
  primitives (Task 2).
- Produces (Plan 02's connection bring-up sends exactly these):
  - `ProtocolRequest(; flags::UInt8 = kXR_secreqs | kXR_ableTLS)`
  - `LoginRequest(username; pid::Integer = getpid(), capver::UInt8 = kXR_ver005 | kXR_asyncap)`
  - `AuthRequest(credtype::String, cred::Vector{UInt8})`
  - `PingRequest()`

- [x] **Step 1: Write the failing test — `test/wire/test_requests.jl`**

```julia
using XRootD.Wire
using XRootD.Wire: ProtocolRequest, LoginRequest, AuthRequest, PingRequest, encode

@testset "Wire bootstrap requests" begin
    @testset "kXR_protocol golden frame" begin
        # streamid=1, pv=0x520, flags=secreqs|ableTLS, expect=ExpLogin
        frame = encode(ProtocolRequest(), UInt16(1))
        @test frame == UInt8[
            0x00, 0x01, 0x0b, 0xbe,          # streamid, kXR_protocol (3006)
            0x00, 0x00, 0x05, 0x20,          # clientpv = 0x00000520
            0x03, 0x03,                      # flags, expect
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    # reserved[10]
            0x00, 0x00, 0x00, 0x00,          # dlen = 0
        ]
    end

    @testset "kXR_login golden frame" begin
        frame = encode(LoginRequest("julia"; pid = 1234), UInt16(2))
        @test frame == UInt8[
            0x00, 0x02, 0x0b, 0xbf,                       # streamid, kXR_login (3007)
            0x00, 0x00, 0x04, 0xd2,                       # pid = 1234
            0x6a, 0x75, 0x6c, 0x69, 0x61, 0, 0, 0,        # "julia" NUL-padded to 8
            0x00, 0x00, 0x85, 0x00,                       # ability2, ability, capver, rsvd
            0x00, 0x00, 0x00, 0x00,                       # dlen = 0 (anonymous)
        ]
        # username longer than the 8-byte wire field is truncated, not an error
        long = encode(LoginRequest("verylonguser"; pid = 0), UInt16(2))
        @test long[9:16] == codeunits("verylong")
    end

    @testset "kXR_auth golden frame" begin
        frame = encode(AuthRequest("ztn", Vector{UInt8}(codeunits("TOKEN"))), UInt16(4))
        @test frame == vcat(
            UInt8[0x00, 0x04, 0x0b, 0xb8],               # streamid, kXR_auth (3000)
            zeros(UInt8, 12),                            # reserved[12]
            UInt8[0x7a, 0x74, 0x6e, 0x00],               # credtype "ztn\0"
            UInt8[0x00, 0x00, 0x00, 0x05],               # dlen = 5
            Vector{UInt8}(codeunits("TOKEN")),
        )
        @test_throws ArgumentError AuthRequest("toolong", UInt8[])  # credtype > 4 bytes
    end

    @testset "kXR_ping golden frame" begin
        frame = encode(PingRequest(), UInt16(3))
        @test frame == vcat(UInt8[0x00, 0x03, 0x0b, 0xc3], zeros(UInt8, 20))
    end
end
```

- [x] **Step 2: Add the runtests include, run to verify it fails**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: FAIL with `UndefVarError: ProtocolRequest`.

- [x] **Step 3: Write `src/Wire/requests.jl`**

```julia
# Concrete request codecs. Field layouts: nginx-xrootd wire_core_requests.h;
# default flag/capability values: bootstrap_pack.h (the exact bytes libxrdc
# sends during connection bring-up).

"""
    ProtocolRequest(; flags::UInt8 = kXR_secreqs | kXR_ableTLS)

`kXR_protocol` — the first request after the handshake. Announces the client
protocol version (`kXR_PROTOCOLVERSION`), capability `flags` (pass
`kXR_secreqs | kXR_ableTLS | kXR_wantTLS` to require TLS), and that a login
follows (`kXR_ExpLogin`).
"""
struct ProtocolRequest <: Request
    clientpv::UInt32
    flags::UInt8
    expect::UInt8
end

function ProtocolRequest(; flags::UInt8=kXR_secreqs | kXR_ableTLS)
    return ProtocolRequest(kXR_PROTOCOLVERSION, flags, kXR_ExpLogin)
end

requestid(::ProtocolRequest) = kXR_protocol

function body!(frame::Vector{UInt8}, r::ProtocolRequest)
    set_u32!(frame, 5, r.clientpv)
    frame[9] = r.flags
    frame[10] = r.expect
    return frame
end

"""
    LoginRequest(username::AbstractString;
                 pid::Integer = getpid(),
                 capver::UInt8 = kXR_ver005 | kXR_asyncap)

`kXR_login` — starts the session. `username` is NUL-padded/truncated into the
8-byte wire field; `pid` is informational; `capver` advertises a v5,
async-capable client. `dlen = 0` (anonymous — credentials go in a subsequent
`kXR_auth`).
"""
struct LoginRequest <: Request
    username::String
    pid::Int32
    capver::UInt8
end

function LoginRequest(
    username::AbstractString; pid::Integer=getpid(), capver::UInt8=kXR_ver005 | kXR_asyncap
)
    return LoginRequest(String(username), Int32(pid), capver)
end

requestid(::LoginRequest) = kXR_login

function body!(frame::Vector{UInt8}, r::LoginRequest)
    set_u32!(frame, 5, reinterpret(UInt32, r.pid))
    set_padded_string!(frame, 9, 8, r.username)
    frame[19] = r.capver   # bytes 17 (ability2), 18 (ability), 20 (rsvd) stay 0
    return frame
end

"""
    AuthRequest(credtype::AbstractString, cred::Vector{UInt8})

`kXR_auth` — answers a `kXR_authmore`/security requirement with a credential.
`credtype` is the 4-byte protocol tag (`"unix"`, `"ztn"`, `"sss"`); `cred` is
the raw credential payload (e.g. the JWT bytes for ztn).
"""
struct AuthRequest <: Request
    credtype::String
    cred::Vector{UInt8}

    function AuthRequest(credtype::AbstractString, cred::Vector{UInt8})
        if ncodeunits(credtype) > 4
            throw(ArgumentError("credtype must be ≤ 4 bytes, got $(repr(credtype))"))
        end
        return new(String(credtype), cred)
    end
end

requestid(::AuthRequest) = kXR_auth

function body!(frame::Vector{UInt8}, r::AuthRequest)
    set_padded_string!(frame, 17, 4, r.credtype)   # bytes 5:16 reserved
    return frame
end

payload(r::AuthRequest) = r.cred

"""
    PingRequest()

`kXR_ping` — liveness probe; empty body, empty payload.
"""
struct PingRequest <: Request end

requestid(::PingRequest) = kXR_ping
```

- [x] **Step 4: Add the Wire.jl include, run tests to verify they pass**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS.

- [x] **Step 5: Format and commit**

```bash
julia -e 'using Pkg; Pkg.activate(; temp=true); Pkg.add("JuliaFormatter"); using JuliaFormatter; format(".")'
git add src/Wire/requests.jl src/Wire/Wire.jl test/wire/test_requests.jl test/runtests.jl
git commit -m "feat(wire): protocol/login/auth/ping request codecs"
```

---

### Task 6: Stat & dirlist request codecs

**Files:**
- Modify: `src/Wire/requests.jl` (append)
- Modify: `test/wire/test_requests.jl` (append testsets)

**Interfaces:**
- Consumes: `Request` machinery (Task 4), constants (Task 3).
- Produces (Plan 02's FS ops):
  - `StatRequest(path; options::UInt8 = 0x00, fhandle::NTuple{4,UInt8} = (0,0,0,0))`
    — pass `options = kXR_vfs` for statvfs, or a real `fhandle` with empty
    path for open-file stat;
  - `DirlistRequest(path; options::UInt8 = kXR_dstat)`.

- [x] **Step 1: Append failing tests to `test/wire/test_requests.jl`**

```julia
using XRootD.Wire: StatRequest, DirlistRequest, kXR_dstat, kXR_vfs

@testset "Wire fs requests" begin
    @testset "kXR_stat golden frame" begin
        frame = encode(StatRequest("/tmp"), UInt16(5))
        @test frame == vcat(
            UInt8[0x00, 0x05, 0x0b, 0xc9],       # streamid, kXR_stat (3017)
            zeros(UInt8, 16),                    # options=0, reserved, fhandle=0
            UInt8[0x00, 0x00, 0x00, 0x04],       # dlen = 4
            Vector{UInt8}(codeunits("/tmp")),    # path, no trailing NUL
        )
        vfs = encode(StatRequest("/data"; options = kXR_vfs), UInt16(5))
        @test vfs[5] == 0x01
        byhandle = encode(
            StatRequest(""; fhandle = (0x01, 0x02, 0x03, 0x04)), UInt16(5)
        )
        @test byhandle[17:20] == UInt8[0x01, 0x02, 0x03, 0x04]
        @test byhandle[21:24] == zeros(UInt8, 4)   # dlen = 0 when path empty
    end

    @testset "kXR_dirlist golden frame" begin
        frame = encode(DirlistRequest("/data"), UInt16(6))
        @test frame == vcat(
            UInt8[0x00, 0x06, 0x0b, 0xbc],       # streamid, kXR_dirlist (3004)
            zeros(UInt8, 15),                    # reserved[15]
            UInt8[kXR_dstat],                    # options at body byte 16
            UInt8[0x00, 0x00, 0x00, 0x05],       # dlen = 5
            Vector{UInt8}(codeunits("/data")),
        )
        plain = encode(DirlistRequest("/data"; options = 0x00), UInt16(6))
        @test plain[20] == 0x00
    end
end
```

- [x] **Step 2: Run to verify the new testsets fail**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: FAIL with `UndefVarError: StatRequest` (earlier testsets still pass).

- [x] **Step 3: Append to `src/Wire/requests.jl`**

```julia
"""
    StatRequest(path::AbstractString;
                options::UInt8 = 0x00,
                fhandle::NTuple{4,UInt8} = (0x00, 0x00, 0x00, 0x00))

`kXR_stat` — stat a path (the usual case) or an open file handle (empty
`path` + real `fhandle`). `options = kXR_vfs` requests virtual-filesystem
(statvfs) information instead. The response body is the ASCII stat line
`"<id> <size> <flags> <mtime>"` (see [`parse_stat_line`](@ref)).
"""
struct StatRequest <: Request
    path::String
    options::UInt8
    fhandle::NTuple{4,UInt8}
end

function StatRequest(
    path::AbstractString;
    options::UInt8=0x00,
    fhandle::NTuple{4,UInt8}=(0x00, 0x00, 0x00, 0x00),
)
    return StatRequest(String(path), options, fhandle)
end

requestid(::StatRequest) = kXR_stat

function body!(frame::Vector{UInt8}, r::StatRequest)
    frame[5] = r.options                       # bytes 6:16 reserved (zero)
    set_bytes!(frame, 17, collect(r.fhandle))
    return frame
end

payload(r::StatRequest) = codeunits(r.path)

"""
    DirlistRequest(path::AbstractString; options::UInt8 = kXR_dstat)

`kXR_dirlist` — list a directory. The default `kXR_dstat` asks for per-entry
stat lines (the server then prepends the `".\\n0 0 0 0\\n"` sentinel — see
[`parse_dirlist`](@ref)). Large listings arrive chunked via `kXR_oksofar`;
accumulating chunks is the Session layer's job.
"""
struct DirlistRequest <: Request
    path::String
    options::UInt8
end

function DirlistRequest(path::AbstractString; options::UInt8=kXR_dstat)
    return DirlistRequest(String(path), options)
end

requestid(::DirlistRequest) = kXR_dirlist

function body!(frame::Vector{UInt8}, r::DirlistRequest)
    frame[20] = r.options   # body bytes 1:15 reserved; options is byte 16
    return frame
end

payload(r::DirlistRequest) = codeunits(r.path)
```

- [x] **Step 4: Run tests to verify they pass**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS.

- [x] **Step 5: Format and commit**

```bash
julia -e 'using Pkg; Pkg.activate(; temp=true); Pkg.add("JuliaFormatter"); using JuliaFormatter; format(".")'
git add src/Wire/requests.jl test/wire/test_requests.jl
git commit -m "feat(wire): stat and dirlist request codecs"
```

---

### Task 7: Response body decoders

**Files:**
- Create: `src/Wire/responses.jl`
- Modify: `src/Wire/Wire.jl` (add `include("responses.jl")` after requests)
- Create: `test/wire/test_responses.jl`
- Modify: `test/runtests.jl` (add include)

**Interfaces:**
- Consumes: primitives (Task 2), constants (Task 3).
- Produces (Plan 02 dispatches on `ResponseHeader.status` and calls):
  - `decode_error(body) -> (; errnum::Int32, message::String)`
  - `wait_seconds(body; fallback::UInt32 = UInt32(5), cap::UInt32 = UInt32(600)) -> UInt32`
  - `decode_redirect(body) -> (; port::Int32, host::String, cgi::String)`
  - `decode_protocol(body) -> (; pval::UInt32, flags::UInt32)`
  - `decode_login(body) -> (; sessid::Vector{UInt8}, sec::String)`
  - `parse_stat_line(line) -> (; id::String, size::Int64, flags::UInt32, mtime::Int64)`
  - `parse_dirlist(body) -> (; entries::Vector{String}, stats::Union{Nothing,Vector})`

- [x] **Step 1: Write the failing test — `test/wire/test_responses.jl`**

```julia
using XRootD.Wire:
    decode_error, wait_seconds, decode_redirect, decode_protocol,
    decode_login, parse_stat_line, parse_dirlist

@testset "Wire response bodies" begin
    @testset "kXR_error body" begin
        body = vcat(UInt8[0x00, 0x00, 0x0b, 0xc3], Vector{UInt8}(codeunits("No such file")))
        err = decode_error(body)
        @test err.errnum == Int32(3011)
        @test err.message == "No such file"
        # tolerate a trailing NUL some servers append
        @test decode_error(vcat(body, UInt8[0x00])).message == "No such file"
        @test_throws ArgumentError decode_error(UInt8[0x00, 0x00])
    end

    @testset "kXR_wait body" begin
        @test wait_seconds(UInt8[0x00, 0x00, 0x00, 0x05]) == 5
        @test wait_seconds(UInt8[]) == 5                       # fallback
        @test wait_seconds(UInt8[0x00, 0x00, 0x00, 0x00]) == 1 # clamp low
        @test wait_seconds(UInt8[0x00, 0x01, 0x00, 0x00]; cap = UInt32(600)) == 600
    end

    @testset "kXR_redirect body" begin
        body = vcat(UInt8[0x00, 0x00, 0x04, 0x46], Vector{UInt8}(codeunits("eos.cern.ch")))
        r = decode_redirect(body)
        @test r.port == Int32(1094)
        @test r.host == "eos.cern.ch"
        @test r.cgi == ""
        r = decode_redirect(
            vcat(UInt8[0x00, 0x00, 0x04, 0x46], Vector{UInt8}(codeunits("eos.cern.ch?xrd.spr=tls")))
        )
        @test r.host == "eos.cern.ch"
        @test r.cgi == "xrd.spr=tls"
    end

    @testset "kXR_protocol + kXR_login bodies" begin
        p = decode_protocol(UInt8[0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x01])
        @test p.pval == 0x00000520
        @test p.flags == 0x00000001

        sessid = UInt8.(1:16)
        l = decode_login(sessid)
        @test l.sessid == sessid
        @test l.sec == ""
        l = decode_login(vcat(sessid, Vector{UInt8}(codeunits("&P=ztn"))))
        @test l.sec == "&P=ztn"
        @test_throws ArgumentError decode_login(UInt8[0x01])
    end

    @testset "stat line" begin
        s = parse_stat_line("1234567 16 65536 1700000000")
        @test s == (; id = "1234567", size = 16, flags = UInt32(65536), mtime = 1700000000)
        @test parse_stat_line("9 0 0 0\0").size == 0     # tolerate trailing NUL
        @test_throws ArgumentError parse_stat_line("only two")
    end

    @testset "dirlist bodies" begin
        plain = parse_dirlist(Vector{UInt8}(codeunits("a.root\nb.root\nsub\0")))
        @test plain.entries == ["a.root", "b.root", "sub"]
        @test plain.stats === nothing

        dstat_text = ".\n0 0 0 0\nf1\n10 100 0 1700000000\ndir1\n11 0 19 1700000001\0"
        ds = parse_dirlist(Vector{UInt8}(codeunits(dstat_text)))
        @test ds.entries == ["f1", "dir1"]
        @test ds.stats[1] == (; id = "10", size = 100, flags = UInt32(0), mtime = 1700000000)
        @test ds.stats[2].flags == UInt32(19)

        empty = parse_dirlist(UInt8[])
        @test empty.entries == String[] && empty.stats === nothing
    end
end
```

- [x] **Step 2: Add the runtests include, run to verify it fails**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: FAIL with `UndefVarError: decode_error`.

- [x] **Step 3: Write `src/Wire/responses.jl`**

```julia
# Response body decoders (nginx-xrootd frame_hdr.h and the per-request
# response documentation in wire_core_requests.h / dirlist_fmt.h). These
# take the ALREADY-ACCUMULATED body — reassembling kXR_oksofar chunks is the
# Session layer's job.

"""
    decode_error(body) -> (; errnum::Int32, message::String)

Decode a `kXR_error` body: `errnum[4]` + message bytes. The message is NOT
guaranteed NUL-terminated on the wire; it is read bounded and any trailing
NUL is dropped.
"""
function decode_error(body::AbstractVector{UInt8})
    if length(body) < 4
        throw(ArgumentError("kXR_error body needs ≥ 4 bytes, got $(length(body))"))
    end
    errnum = reinterpret(Int32, get_u32(body, 1))
    message = get_bounded_string(body, 5, length(body) - 4)
    return (; errnum, message)
end

"""
    wait_seconds(body; fallback::UInt32 = UInt32(5), cap::UInt32 = UInt32(600)) -> UInt32

Decode a `kXR_wait`/`kXR_waitresp` retry-after body (`int32` seconds),
clamped to `[1, cap]`; `fallback` is used when the body is too short.
Mirrors `xrd_wait_secs_parse` in frame_hdr.h.
"""
function wait_seconds(
    body::AbstractVector{UInt8}; fallback::UInt32=UInt32(5), cap::UInt32=UInt32(600)
)
    s = length(body) >= 4 ? get_u32(body, 1) : fallback
    return clamp(s, UInt32(1), cap)
end

"""
    decode_redirect(body) -> (; port::Int32, host::String, cgi::String)

Decode a `kXR_redirect` body: `port[4]` + `host[?cgi]`. Any CGI opaque
after `?` is split off into `cgi` (empty when absent).
"""
function decode_redirect(body::AbstractVector{UInt8})
    if length(body) < 4
        throw(ArgumentError("kXR_redirect body needs ≥ 4 bytes, got $(length(body))"))
    end
    port = reinterpret(Int32, get_u32(body, 1))
    target = get_bounded_string(body, 5, length(body) - 4)
    host, cgi = let i = findfirst('?', target)
        i === nothing ? (target, "") : (target[1:prevind(target, i)], target[nextind(target, i):end])
    end
    return (; port, host=String(host), cgi=String(cgi))
end

"""
    decode_protocol(body) -> (; pval::UInt32, flags::UInt32)

Decode a `kXR_protocol` response body (`ServerProtocolBody`): the server's
protocol version and its type/TLS-requirement flags.
"""
function decode_protocol(body::AbstractVector{UInt8})
    if length(body) < 8
        throw(ArgumentError("kXR_protocol body needs ≥ 8 bytes, got $(length(body))"))
    end
    return (; pval=get_u32(body, 1), flags=get_u32(body, 5))
end

"""
    decode_login(body) -> (; sessid::Vector{UInt8}, sec::String)

Decode a `kXR_login` response body: the 16-byte opaque session id (echoed by
`kXR_bind`/`kXR_endsess`) plus the optional security-requirements trailer
(e.g. `"&P=ztn,..."`) that follows when the server demands authentication.
"""
function decode_login(body::AbstractVector{UInt8})
    if length(body) < SESSION_ID_LEN
        throw(ArgumentError("kXR_login body needs ≥ $(SESSION_ID_LEN) bytes, got $(length(body))"))
    end
    sessid = Vector{UInt8}(body[1:SESSION_ID_LEN])
    sec = get_bounded_string(body, SESSION_ID_LEN + 1, length(body) - SESSION_ID_LEN)
    return (; sessid, sec)
end

"""
    parse_stat_line(line::AbstractString) -> (; id::String, size::Int64, flags::UInt32, mtime::Int64)

Parse the ASCII stat line `"<id> <size> <flags> <mtime>"` returned by
`kXR_stat` (and per entry by dstat dirlists). Extra fields (extended stat)
are ignored.
"""
function parse_stat_line(line::AbstractString)
    parts = split(rstrip(line, '\0'))
    if length(parts) < 4
        throw(ArgumentError("malformed stat line: $(repr(line))"))
    end
    return (;
        id=String(parts[1]),
        size=parse(Int64, parts[2]),
        flags=parse(UInt32, parts[3]),
        mtime=parse(Int64, parts[4]),
    )
end

# 9-byte prefix the reference client checks to detect dstat mode
# (DirectoryList::dStatPrefix; see dirlist_fmt.h).
const _DSTAT_SENTINEL = ".\n0 0 0 0"

"""
    parse_dirlist(body) -> (; entries::Vector{String}, stats)

Parse an accumulated `kXR_dirlist` response body. Plain listings are
newline-separated names (`stats === nothing`). When the request set
`kXR_dstat`, the body starts with the `".\\n0 0 0 0\\n"` sentinel and carries
`name\\nstatline` pairs; `stats[i]` is then [`parse_stat_line`](@ref) of
entry `i`'s line.
"""
function parse_dirlist(body::AbstractVector{UInt8})
    text = rstrip(String(copy(body)), '\0')
    isempty(text) && return (; entries=String[], stats=nothing)
    lines = split(text, '\n'; keepempty=false)
    if startswith(text, _DSTAT_SENTINEL)
        rest = lines[3:end]   # drop the two sentinel lines
        if isodd(length(rest))
            throw(ArgumentError("dstat dirlist has an unpaired name/stat line"))
        end
        entries = [String(rest[i]) for i in 1:2:length(rest)]
        stats = [parse_stat_line(rest[i + 1]) for i in 1:2:length(rest)]
        return (; entries, stats)
    end
    return (; entries=String.(lines), stats=nothing)
end
```

- [x] **Step 4: Add the Wire.jl include, run tests to verify they pass**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS.

- [x] **Step 5: Format and commit**

```bash
julia -e 'using Pkg; Pkg.activate(; temp=true); Pkg.add("JuliaFormatter"); using JuliaFormatter; format(".")'
git add src/Wire/responses.jl src/Wire/Wire.jl test/wire/test_responses.jl test/runtests.jl
git commit -m "feat(wire): response body decoders"
```

---

### Task 8: Quality gates — Aqua, JET, CI, docs stub

**Files:**
- Create: `test/test_quality.jl`
- Modify: `test/runtests.jl` (add include)
- Modify: `.github/workflows/ci.yml` (full replacement)
- Modify: `docs/make.jl` (full replacement)
- Modify: `docs/src/index.md` (full replacement)

**Interfaces:**
- Consumes: the whole package.
- Produces: CI that fails on unformatted code, Aqua/JET regressions, or test
  failures; a transitional docs build that stays green.

- [x] **Step 1: Write `test/test_quality.jl`**

```julia
using Aqua
using JET

@testset "quality" begin
    @testset "Aqua" begin
        Aqua.test_all(XRootD)
    end
    @testset "JET" begin
        JET.test_package(XRootD; target_defined_modules = true)
    end
end
```

- [x] **Step 2: Add `include("test_quality.jl")` to `test/runtests.jl`, run**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS. If Aqua or JET report real findings (ambiguities, unstable
public calls), fix the flagged code — do not loosen the test.

- [x] **Step 3: Replace `.github/workflows/ci.yml`**

```yaml
name: CI
on:
  pull_request:
    branches:
      - main
  push:
    branches:
      - main
    tags: '*'
jobs:
  format:
    name: Format check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: julia-actions/setup-julia@v2
        with:
          version: '1'
      - run: |
          julia -e '
            using Pkg; Pkg.add("JuliaFormatter"); using JuliaFormatter
            format(".", verbose=true) || error("Run JuliaFormatter before pushing")'
  test:
    name: Julia ${{ matrix.version }} - ${{ matrix.os }} - ${{ matrix.arch }}
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        version:
          - '1.10'
          - '1'
        os:
          - ubuntu-latest
        arch:
          - x64
    steps:
      - uses: actions/checkout@v4
      - uses: julia-actions/setup-julia@v2
        with:
          version: ${{ matrix.version }}
          arch: ${{ matrix.arch }}
      - uses: julia-actions/cache@v2
      - uses: julia-actions/julia-buildpkg@v1
      - uses: julia-actions/julia-runtest@v1
        env:
          JULIA_NUM_THREADS: "3"
      - uses: julia-actions/julia-processcoverage@v1
      - name: Upload coverage reports to Codecov
        uses: codecov/codecov-action@v4
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
          slug: JuliaHEP/XRootD.jl
  docs:
    name: Documentation
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: julia-actions/setup-julia@v2
        with:
          version: '1'
      - run: |
          julia --project=docs -e '
            using Pkg
            Pkg.develop(PackageSpec(path=pwd()))
            Pkg.instantiate()'
      - run: julia --project=docs docs/make.jl
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          DOCUMENTER_KEY: ${{ secrets.DOCUMENTER_KEY }}
```

- [x] **Step 4: Replace `docs/make.jl`**

```julia
using Documenter
using XRootD

makedocs(;
    sitename = "XRootD.jl",
    modules = [XRootD],
    pages = ["Home" => "index.md", "Release Notes" => "release_notes.md"],
    # Transitional while the 0.3 pure-Julia rewrite is in progress; the docs
    # get their full treatment in plan 08 (parity & release).
    warnonly = true,
)

deploydocs(; repo = "github.com/JuliaHEP/XRootD.jl.git", push_preview = true)
```

- [x] **Step 5: Replace `docs/src/index.md`**

````markdown
# XRootD.jl

Pure-Julia client for the [XRootD](https://xrootd.slac.stanford.edu)
high-performance data-access protocol.

!!! warning "0.3 rewrite in progress"
    XRootD.jl is being rewritten as a native Julia implementation of the
    XRootD protocol, replacing the previous CxxWrap binding to the XrdCl C++
    library. The 0.2.x `File`/`FileSystem` API will return unchanged as the
    rewrite lands. For the 0.2.x documentation, select the `v0.2.4` version
    of these docs.

## Architecture

The client is built in layers; only `Wire` exists so far:

- `XRootD.Wire` — pure codecs for the wire protocol (no I/O).
- `Session`, `File`/`FileSystem`, web backends, and `xrdcp`/`xrdfs` tool
  equivalents follow — see the roadmap in the repository under
  `docs/superpowers/plans/`.

## Attribution

The wire-format ground truth, client semantics, and architecture implemented
here were developed in the `libxrdc` pure-C client and protocol reference of
the nginx-xrootd project. This package is a Julia translation of that prior
work.

## Wire API

```@autodocs
Modules = [XRootD, XRootD.Wire]
```
````

- [x] **Step 6: Verify the docs build locally**

Run: `julia --project=docs -e 'using Pkg; Pkg.develop(PackageSpec(path=pwd())); Pkg.instantiate()' && julia --project=docs docs/make.jl`
Expected: build completes (warnings allowed, no errors). `deploydocs` is a
no-op locally.

- [x] **Step 7: Full test run, format, commit**

Run: `julia --project=. -e 'using Pkg; Pkg.test()'`
Expected: PASS (all wire + quality testsets).

```bash
julia -e 'using Pkg; Pkg.activate(; temp=true); Pkg.add("JuliaFormatter"); using JuliaFormatter; format(".")'
git add -A
git commit -m "ci: format/Aqua/JET gates, transitional docs for 0.3"
```

---

## Plan completion

After Task 8, `XRootD.Wire` fully covers the connection-bootstrap and
stat/dirlist vocabulary with byte-exact tests, and every quality gate from
the spec's "Code quality" section is enforced. Plan 02 (Session + FS-op
parity) starts by consuming `Wire.HANDSHAKE`, `Wire.encode`,
`Wire.decode_header`, and the codecs above, and extends `requests.jl` /
`responses.jl` with the remaining FS opcodes (mkdir/rm/rmdir/mv/chmod/
truncate/locate/query) following the exact patterns Tasks 5–7 established.
