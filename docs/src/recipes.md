# Recipes

Thirty-three short programs covering the three things almost every job does — read a
file over `root://`, list what is on a remote server, reach data with a token
over WebDAV — and then what to do when the network between you and the storage
cannot be trusted.

These are the layers underneath the everyday API — the ones to reach for when
you need the protocol's own vocabulary. If you just want your data, start at
[Getting started](@ref): most of what follows has a one-line form there.

Every call in the `XrdCl` layer answers `(status, result)`. `isOK(st)` /
`isError(st)` decide and `st.message` says why: a dead server, a missing file
and a refused permission all arrive as a status, not as an exception. The
`Storage` layer answers with a `Symbol` (`:ok`, `:truncated`, `:error`) and
the copy engine with `(ok::Bool, message::String)`. The one exception is the
stream layer of examples 28–30: an `IO` has nowhere to put a status code, so
those raise `StorageError`.

## Files over `root://`

### 1. Open a file and read a byte range

```julia
using XRootD.XrdCl

f = File()
st, _ = open(f, "root://xrootd.example.org//store/data/run3/AOD.root", OpenFlags.Read)
isOK(st) || error(st.message)

st, info = stat(f)                        # size, mtime, flags of the open handle
st, head = read(f, 1024, 0)               # 1 KiB from offset 0
st, tail = read(f, 4096, info.size - 4096)
close(f)
```

`read(f, size, offset)` positions the cursor and does *not* advance it, so
every read states where it reads from. `File(url, OpenFlags.Read)` is the
one-line form of the open above, and returns `nothing` if it failed.

### 2. Read a file line by line

```julia
f = File("root://xrootd.example.org//store/user/me/run.log", OpenFlags.Read)
while true
    st, line = readline(f)                # cursor advances; "" at EOF
    isOK(st) && !isempty(line) || break
    print(line)
end
close(f)
```

`readlines(f)` returns the whole thing at once when the file is small enough
to hold.

### 3. Stream a whole file to local disk, with bounded memory

```julia
using XRootD.Storage: storage_for, storage_read

open("/scratch/AOD.root", "w") do sink
    code = storage_read(storage_for("root://xrootd.example.org//store/data/run3/AOD.root"), sink)
    code == :ok || error("download failed: $code")
end
```

The transfer moves in 1 MiB chunks (`$XRD_CPCHUNKSIZE`), so a 100 GB file
costs 1 MiB of RSS. From the shell this is
`bin/xrdcp.jl root://xrootd.example.org//store/… /scratch/`.

### 4. Read many scattered pieces in one round trip

```julia
st, segs = readv(f, [(0, 512), (1 << 20, 512), (2 << 20, 512)])
# segs :: Vector{Vector{UInt8}}, in the order asked for
```

This is the request that matters on a high-latency link: a ROOT file's baskets
cost one round trip instead of `n`. A reply missing a segment is an error, not
a short read.

### 5. Read with per-page checksums

```julia
st, page = pgread(f, 64 * 1024, 0)        # CRC32c per 4 KiB, checked here
isError(st) && @error "corrupt page from the server" st.message
```

`kXR_pgread` is the one read that can tell you the bytes were mangled in
flight rather than at rest. Its counterpart `pgwrite(f, data, offset)` sends
the digests along with the data.

### 6. Write a file, all-or-nothing

```julia
f = File()
st, _ = open(f, "root://xrootd.example.org//store/user/me/out.bin",
             OpenFlags.New | OpenFlags.Write, Access.UR | Access.UW)
isOK(st) || error(st.message)

payload = rand(UInt8, 1 << 20)
st, _ = write(f, payload, length(payload), 0)
st, _ = sync(f)
st, _ = close(f; fsize=length(payload))   # wrong length ⇒ error, and the file is removed
```

`fsize=` is what makes an interrupted write leave nothing behind instead of a
plausible-looking short file. Add `OpenFlags.POSC` and the *server* deletes it
if the connection dies before the close.

### 7. Write scattered pieces as one operation

```julia
st, _ = writev(f, [(0, header), (1 << 20, block_a), (2 << 20, block_b)]; do_sync=true)
```

All of it or none of it, in one request.

### 8. Update a file under a checkpoint

```julia
st, result = checkpoint(f) do
    checkpoint_write(f, patch, 4096)
    checkpoint_truncate(f, 1 << 20)
end
isOK(st) || @error "update rolled back" st.message
```

The `do` block commits when it returns and rolls back when it throws, so a
failed in-place update leaves the file as it was. The explicit form is
`checkpoint_begin` / `checkpoint_commit` / `checkpoint_rollback` /
`checkpoint_query`.

### 9. Move bulk data off the control connection

```julia
st, pathid = bind_data_path!(f)           # a second TCP connection to the same server
isOK(st) || @warn "server would not bind a data path" st.message
st, buf = read(f, 64 << 20, 0)            # rides the data path from here on
```

Worth doing when a multi-gigabyte read shares a session with work that has to
stay responsive. A single read on an idle session gains nothing — the same
bytes cross the same network.

### 10. Recover a handle whose connection died

```julia
if isError(st) && recoverable(f)
    isOK(reopen!(f)) && ((st, buf) = read(f, 1024, offset))
end
```

The client already does this for you on a read-only handle — see *What the
client already does*, below — and the explicit call is for when you want to
decide yourself. A handle opened for writing is not `recoverable`: reopening
would discard what the writer had put there.

## Listing a remote namespace

### 11. List a directory

```julia
using XRootD.XrdCl

fs = FileSystem("root://xrootd.example.org")       # roots:// for TLS
st, entries = readdir(fs, "/store/data"; sort=true)
isOK(st) || error(st.message)
foreach(println, entries)
```

`join=true` returns full paths instead of names.

### 12. List with metadata in one round trip

```julia
st, names, stats = dirlist_stat(fs, "/store/data")
for (name, info) in zip(names, stats)
    println(isdir(info) ? "d " : "- ", lpad(info.size, 12), "  ", name)
end
```

One request when the server honours `kXR_dstat`, and a stat per entry when it
does not — the difference between one round trip and a thousand on a
transatlantic link.

### 13. Walk a whole tree

```julia
for (dir, subdirs, files) in walkdir(fs, "/store/data")
    for name in files
        println(joinpath(dir, name))
    end
end
```

Same shape as `Base.walkdir`. `topdown=false` visits children first.

### 14. Ask about one path

```julia
ispath(fs, "/store/data/run3")            # Bool — a plain answer, like Base
isdir(fs, "/store/data/run3")
isfile(fs, "/store/data/run3/AOD.root")
filesize(fs, "/store/data/run3/AOD.root")  # Int64, -1 when it cannot be stat'd
st, info = stat(fs, "/store/data/run3/AOD.root")
isreadable(info), isOffline(info)         # Base predicates and the two XRootD ones
```

The predicates answer plainly and throw only when the server gave no answer
about existence at all — unreachable, unauthorized. `isOffline` is the one to
check before a long read: the file exists, but it is on tape and the first
byte will take minutes (`prepare(fs, paths; stage=true)` starts the recall).

### 15. Classify a thousand paths in one request

```julia
paths = ["/store/data/run3/$i.root" for i in 1:1000]
st, flags = statx(fs, paths)              # one StatFlags per path, in order
readable = paths[map(isreadable, flags)]
dirs = paths[map(isdir, flags)]
```

`kXR_statx` answers with type and access bits only — which is exactly what
makes it one exchange rather than a thousand.

### 16. List with a checksum per entry

```julia
st, names, stats, cksums = dirlist_checksum(fs, "/store/data"; algorithm="adler32")
for (name, cks) in zip(names, something(cksums, fill(nothing, length(names))))
    println(name, "  ", cks === nothing ? "-" : cks.value)
end
```

`cksums === nothing` means the server ignored the option; the client reports
that rather than quietly issuing one checksum query per entry behind your
back.

### 17. Create, move and remove

```julia
st, _ = mkpath(fs, "/store/user/me/2026/08")      # one request, parents included
st, _ = touch(fs, "/store/user/me/2026/08/.keep")
st, _ = mv(fs, "/store/user/me/old", "/store/user/me/2026/07")
st, _ = chmod(fs, "/store/user/me/2026", 0o750)
st, _ = rm(fs, "/store/user/me/scratch"; recursive=true)
```

A recursive removal is depth-first and stops at the first failure, reporting
it — there is no wire operation that would undo what it already deleted.

### 18. Ask the server about itself

```julia
st, info = protocol(fs)
ismanager(info) && println("this is a redirector")
supports_pgio(info) && println("kXR_pgread available")

st, cfg = query_config(fs, "version", "role", "sitename")
st, vfs = statvfs(fs, "/store")                   # nodes, free_kb, utilization
```

### 19. Find the servers actually holding a file

```julia
st, locs = deep_locate(fs, "/store/data/run3/AOD.root", OpenFlags.Refresh)
for l in locs
    println(l.address, "  ", l.access)
end
```

A plain `locate` against a redirector names the redirector. `deep_locate`
resolves managers down to the data servers behind them, skipping a node it
cannot reach rather than failing the whole call — a federation with one
machine down still knows where the other replicas are.

### 20. The same listing over any other protocol

```julia
using XRootD.Storage: storage_for, storage_list

for url in ("root://xrootd.example.org//store/data/",
            "davs://webdav.example.org/data/",
            "s3://bucket/prefix/",
            "/scratch/data/")
    for (name, info) in storage_list(storage_for(url))
        println(info.isdir ? "d " : "- ", lpad(info.size, 12), "  ", name)
    end
end
```

`Storage` dispatches on the scheme, so a tool that takes a URL from its
caller does not care which kind it got. From the shell:
`bin/xrdfs.jl xrootd.example.org ls /store/data`, or with no command for an
interactive shell.

## Tokens and WebDAV

### 21. Read with a token the job already has

```julia
using XRootD.Storage: storage_for, storage_stat, storage_read

b = storage_for("davs://webdav.example.org/store/user/me/out.root")
code, info = storage_stat(b)              # :ok, StorageInfo(size, mtime, isdir)
open("/scratch/out.root", "w") do sink
    storage_read(b, sink)                 # Authorization: Bearer …, added for you
end
```

The client looks before it asks: `$BEARER_TOKEN`, `$BEARER_TOKEN_FILE`,
`$XDG_RUNTIME_DIR/bt_u<uid>`, `/tmp/bt_u<uid>`. A job that has already had
`htgettoken` or `wlcg-token` run for it says nothing at all.

### 22. Pass a token explicitly

```julia
b = storage_for("davs://webdav.example.org/store/user/me/";
                token=read("/run/secrets/scope-write.jwt", String))
storage_list(b)                           # PROPFIND Depth: 1
```

Use this when the job holds several tokens and the discovery order is not the
one you want. Tokens never appear in `show`, `repr` or any log line the client
writes.

### 23. Read a byte range, and know that you got it

```julia
buf = IOBuffer()
code = storage_read(b, buf; offset=4096, length=1024)
code == :truncated && @warn "endpoint ignored the range or stopped early"
```

An endpoint that answers a ranged `GET` with a plain `200` has sent you the
wrong bytes while looking successful. The client compares what arrived against
what it asked for and says `:truncated` rather than handing the buffer over.

### 24. Write, create a collection, move, delete

```julia
using XRootD.Storage: storage_write, storage_mkdir, storage_move, storage_remove

storage_mkdir(storage_for("davs://webdav.example.org/store/user/me/2026/"))
open("/scratch/out.root") do src
    storage_write(storage_for("davs://webdav.example.org/store/user/me/2026/out.root"), src)
end
storage_move(storage_for("davs://webdav.example.org/store/user/me/2026/out.root"),
             "davs://webdav.example.org/store/user/me/2026/final.root")
storage_remove(storage_for("davs://webdav.example.org/store/user/me/2026/tmp.root"))
```

`PUT`, `PROPFIND` and `MKCOL` are replayed after a transport failure;
`DELETE`, `MOVE` and `COPY` are not, because the retry of one that already
landed reports a failure that did not happen.

### 25. The same credential over `root://`

```julia
f = File("roots://xrootd.example.org//store/user/me/out.root", OpenFlags.Read;
         token=read("/run/secrets/read.jwt", String))

fs = FileSystem("roots://xrootd.example.org";
                cert="/tmp/x509up_u1000", key="/tmp/x509up_u1000")
```

A bearer token goes out as `ztn` during login instead of as a header, so the
credential keywords (`token`, `cert`/`key`, `cafile`, `keytab`,
`insecure_tls`) are the same whichever scheme a URL turns out to have.

### 26. Copy between two token-protected endpoints

```julia
using XRootD.Tools: copyfile

ok, msg = copyfile(
    "davs://in.example.org/store/data/AOD.root",
    "davs://out.example.org/store/user/me/AOD.root";
    src_opts=(; token=read("/run/secrets/read.jwt", String)),
    dst_opts=(; token=read("/run/secrets/write.jwt", String)),
    verify=true, tpc=:first,
)
ok || @error "copy failed" msg
```

`tpc=:first` asks the two endpoints to move the bytes between themselves (a
WLCG HTTP-TPC `COPY` carrying `TransferHeaderAuthorization:`) and streams
through this client if they will not; `:only` fails instead of falling back.
`copytree` does the same for a whole directory. On the command line:
`bin/xrdcp.jl --token /run/secrets/read.jwt --verify davs://… /scratch/`.

One rule here is enforced rather than configured: a token is never sent over
cleartext `http://`. A *discovered* one is dropped with a warning, an
*explicit* one raises unless `allow_cleartext_token=true` says the risk is
understood. Use `davs://` / `https://`.

### 27. Supply a missing credential from somewhere other than a terminal

```julia
using XRootD.Session: prompt_credentials!

prompt_credentials!() do req
    # req.kind ∈ (:token, :x509, :x509key, :passphrase, :keytab)
    # req.host, req.port, req.reason, req.searched, req.secret
    req.kind === :token || return nothing          # nothing ⇒ carry on without one
    @info "fetching a token" req.host req.reason req.searched
    return read(`vault read -field=token secret/wlcg/$(req.host)`, String)
end
```

Without a prompter installed the client asks on a terminal (to stderr, echo
off for anything secret) and gives up silently when there is no terminal —
a batch job fails with a status instead of blocking forever on a read from a
closed stdin. Answers are cached per `(kind, scope)` for the process and
dropped again by `forget_credential!` when the server rejects them.

## Any object as a Julia stream

### 28. Read a remote object with the functions you already use

```julia
using XRootD.Storage: storage_open

storage_open("root://xrootd.example.org//store/data/run3/AOD.root") do io
    magic = read(io, 4)
    seek(io, 1 << 30)                     # a gigabyte in, without reading the first
    block = read(io, 4096)
    position(io), eof(io)
end
```

`storage_open` hands back a `StorageReader <: IO`, so `read`, `read!`,
`readbytes!`, `readavailable`, `seek`, `skip`, `position` and `eof` are Base's
own and code that takes an `IO` takes a remote object without being told. Every
scheme `storage_for` knows works here — `root(s)://`, `dav(s)://`,
`http(s)://`, `s3(s)://` and a local path.

Refills are `$XRD_CPCHUNKSIZE` at a time, so a seek-and-read over a
hundred-gigabyte file costs one chunk of memory. The xroot lane holds a single
open handle for the whole stream and addresses it by offset; the HTTP and S3
lanes refill with a ranged `GET`. An endpoint that will not say how large the
object is can still be read to the end — but not `seekend`, which raises rather
than guess.

### 29. Write an object larger than memory

```julia
storage_open("davs://webdav.example.org/store/user/me/out.root", "w";
             length=filesize("/scratch/out.root")) do io
    open("/scratch/out.root") do src
        buf = Vector{UInt8}(undef, 1 << 20)
        while !eof(src)
            n = readbytes!(src, buf)
            write(io, @view buf[1:n])
        end
    end
end
```

Say `length=` when you know it. It is not a hint:

- Over HTTP the upload is then framed with `Content-Length` and streamed from
  the caller as it is written, which is what the reference clients send and
  what the endpoints that reject `Transfer-Encoding: chunked` accept. Without
  it the client buffers 8 MiB to find out whether the object is small, sends a
  small one as one `PUT`, and falls back to chunked for the rest.
- On S3 the part size is chosen from it, so a 200 MB object costs 5 MiB of
  memory rather than 64 MiB, and the 10 000-part ceiling lands at S3's own
  5 TB object limit instead of at 640 GB.
- A stream that ends short of what it declared fails the upload instead of
  storing a plausible-looking truncated object.

The verdict arrives at `close`, which is where the `do` block ends: an upload
the endpoint refused raises `StorageError` there rather than returning quietly.
A streamed body cannot be replayed, so a large upload gives up two things a
buffered one keeps — the retry on a transport failure, and the `401`-then-
authorize handshake. Both are reported rather than retried.

### 30. Move an object between two endpoints through a fixed buffer

```julia
using XRootD.Storage: storage_for, storage_stat, storage_open

src = "root://xrootd.example.org//store/data/run3/AOD.root"
dst = "davs://webdav.example.org/store/user/me/AOD.root"

code, info = storage_stat(storage_for(src))
code == :ok || error("cannot stat the source: $code")

storage_open(src) do input
    storage_open(dst, "w"; length=info.size) do output
        buf = Vector{UInt8}(undef, 1 << 20)
        while !eof(input)
            n = readbytes!(input, buf)
            write(output, @view buf[1:n])
        end
    end
end
```

`copyfile` (example 26) does this and more — checksums, the short-read check,
third-party copy, retry — so reach for the streams when the point is to *touch*
the bytes on the way through: decode a container, filter events, index as you
go.

## When the network is the problem

### What the client already does

Everything in this list is on by default; the knobs in example 31 exist for
tuning, not for switching the behaviour on.

- **A lost connection is reconnected and the request replayed** — but only
  when replaying it cannot cause a second effect. Reads, stats and listings
  qualify. A write, an `rm`, a `mv` does not: a request that may already have
  been executed is reported as lost rather than repeated. A `File` opened
  read-only reopens itself and replays; one opened for writing does not,
  because reopening would discard what the writer had put there.
- **Retries are bounded twice over** — by a wall-clock window
  (`XRDC_MAX_STALL_MS`, 30 s) *and* by an attempt count (`XRDC_MAX_RETRIES`,
  4). A peer that refuses in a millisecond would otherwise fit hundreds of
  attempts inside the window, all of them landing on a server that is already
  in trouble.
- **The wait between attempts is exponential with full jitter** — drawn
  uniformly from `[0, min(cap, base·2ⁿ⁻¹)]` rather than being that value. When
  a server disappears it takes every one of its clients with it, and a fleet
  that all waited the same 200 ms comes back as a single burst.
- **Idle connections are probed at two levels.** `XRD_STREAMTIMEOUT` sends an
  application-level `kXR_ping`, which detects a server that is up but no
  longer answering; `SO_KEEPALIVE` (`XRDC_TCP_KEEPALIVE_S`, 60 s) asks the
  kernel to probe the socket, which is what turns a black-holed connection —
  a NAT that dropped the mapping, a firewall that ate the FIN — into an error
  instead of a hang. Without it a read on such a socket waits for the TCP
  retransmission timeout, which is measured in minutes.
- **Every wait has a ceiling.** A TCP connect gives up at
  `XRD_CONNECTIONWINDOW` (30 s) and so does every step of the session bring-up
  after it — a peer that completes the TCP handshake and then stops talking is
  not a connection this client waits on. An HTTP response that stops arriving
  mid-body gives up at `XRDC_HTTP_IDLE_TIMEOUT_S` (120 s), and a server that
  parks an operation with `kXR_wait` may do so for a total of
  `XRD_REQUESTTIMEOUT` (1800 s).
- **No request outlives the request timeout, however slowly it fails.** An
  idle timeout is not a deadline: a peer that dribbles one byte per timeout
  window keeps a read alive forever without ever being idle. So one whole
  operation is bounded absolutely — `XRDC_STALL_DEADLINE_MS` on the `root://`
  lane, `XRDC_HTTP_REQUEST_TIMEOUT_S` on the HTTP one, both defaulting to
  `XRD_REQUESTTIMEOUT`. An in-band `kXR_wait` restarts the budget, so a server
  that says it is staging from tape is not punished for saying so. The same
  deadline bounds the sending side: a peer that stops reading fills both socket
  buffers and blocks the caller inside `write`, before it has sent the request
  whose reply any other deadline would be timing.
- **HTTP and WebDAV retry too**, on `408`, `425`, `429` and `5xx`, honouring
  `Retry-After`. `GET`, `HEAD`, `PUT`, `PROPFIND` and `MKCOL` are replayed;
  `DELETE`, `COPY` and `MOVE` are not.
- **A reply that is bigger than it should be is refused before it is
  allocated**, and a `readv` missing a segment is a failure rather than a
  short read. A hostile or broken server cannot make the client allocate what
  it does not have.
- **A copy that ended early fails**, which no checksum can tell you on its
  own — example 32.

### 31. Tune the retry budget for the link you have

| Variable | Default | What it is for |
|---|---|---|
| `XRDC_MAX_RETRIES` | 4 | How many times one operation may be retried. `0` disables retrying. |
| `XRDC_RETRY_BASE_MS` | 200 | First backoff window; each attempt doubles it. |
| `XRDC_RETRY_CAP_MS` | 5000 | Ceiling on that window. |
| `XRDC_MAX_STALL_MS` | 30000 | Wall-clock budget for one operation's reconnect-and-replay. |
| `XRDC_TCP_KEEPALIVE_S` | 60 | Idle seconds before the kernel probes the socket. `0` leaves the system default. |
| `XRDC_HTTP_IDLE_TIMEOUT_S` | 120 | Seconds an HTTP response body may stall before the read is abandoned. |
| `XRDC_STALL_DEADLINE_MS` | `$XRD_REQUESTTIMEOUT` | Absolute ceiling on one `root://` operation, whatever the server is doing. `0` disables it. |
| `XRDC_HTTP_REQUEST_TIMEOUT_S` | `$XRD_REQUESTTIMEOUT` | The same ceiling on one HTTP request, headers and body. `0` disables it. |
| `XRD_CONNECTIONWINDOW` | 30 | Seconds a TCP connect may take — and each step of the bring-up after it. |
| `XRD_STREAMTIMEOUT` | 0 | Idle seconds before an application-level `kXR_ping`. Off by default. |
| `XRD_REQUESTTIMEOUT` | 1800 | Cumulative `kXR_wait` parking allowed for one operation. |
| `XRD_REDIRECTLIMIT` | 8 | Redirect hops followed. A redirect is not a retry — it spends its own budget. |

A long-haul transfer over a link that keeps flapping — be patient, and probe
the socket often enough to notice a dead path before the transfer stalls on
it:

```bash
export XRDC_MAX_RETRIES=8
export XRDC_RETRY_CAP_MS=15000
export XRDC_MAX_STALL_MS=120000
export XRDC_TCP_KEEPALIVE_S=30
export XRD_STREAMTIMEOUT=60
```

An interactive tool, where an answer in five seconds beats a better answer in
two minutes:

```bash
export XRDC_MAX_RETRIES=1
export XRDC_MAX_STALL_MS=5000
export XRD_CONNECTIONWINDOW=5
export XRDC_STALL_DEADLINE_MS=10000
export XRDC_HTTP_REQUEST_TIMEOUT_S=10
```

The same per call, without touching the environment of the whole process:

```julia
withenv("XRDC_MAX_RETRIES" => "8", "XRDC_MAX_STALL_MS" => "120000") do
    copyfile(src, dst; verify=true)
end
```

A typo in a site profile reaches every job at once, so a value that does not
parse, or one that is negative, leaves the default standing rather than
failing the job.

### 32. Catch the transfer that stopped halfway

```julia
ok, msg = copyfile(src, dst; verify=true)
ok || @error "copy failed" msg
# short read: 4194304 of 8388608 bytes from davs://…
# checksum mismatch after copy
# [ERROR] connection lost
```

This is the failure a bad network actually produces and the one a checksum
cannot catch on its own: the source stops sending halfway, the destination
stores a valid short object, and both ends agree on its checksum — so
`verify=true` passes. `copyfile` also compares what arrived against the size
the source declared, which costs one extra metadata request per copy and is
the only independent evidence there is. (An endpoint that will not declare a
size cannot be held to one; a copy from it still works, and still verifies.)

To check afterwards, or against a third party:

```julia
using XRootD.Tools: checksum_file

local_digest = checksum_file("/scratch/AOD.root", :adler32)
st, remote = checksum(fs, "/store/data/run3/AOD.root"; algorithm="adler32")
endswith(remote, local_digest) || @error "the copy is not the file" remote local_digest
```

### 33. Retry the whole operation, not just the request

```julia
function with_retries(op; attempts=5, base=1.0, cap=30.0)
    local ok, msg
    for n in 1:attempts
        ok, msg = op()
        ok && return true, msg
        n == attempts && break
        sleep(rand() * min(cap, base * 2.0^(n - 1)))   # full jitter, as the client does
        @warn "attempt $n failed, retrying" msg
    end
    return false, msg
end

with_retries() do
    copyfile(src, dst; verify=true, force=true)
end
```

The client retries a *request* — one round trip that it knows is safe to
repeat. Only the caller can retry a *transfer*, because only the caller knows
that the half-written destination is theirs to overwrite; that is what
`force=true` is doing here. A job that runs for hours across a link that drops
twice a day wants both.

Nothing here turns a broken endpoint into a working one, and the client is
deliberate about not pretending otherwise. What you get back is a status with
a message, every time.
