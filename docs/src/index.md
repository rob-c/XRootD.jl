# XRootD.jl

Pure-Julia client for the [XRootD](https://xrootd.slac.stanford.edu)
high-performance, scalable, fault-tolerant data-access protocol.

As of 0.3, XRootD.jl implements the XRootD protocol natively in Julia — there
is no longer a CxxWrap binding to the XrdCl C++ library, and the package has
no compiled binary dependencies beyond standard Julia packages.

## Installation

```julia
using Pkg
Pkg.add("XRootD")
```

## Quick start

A URL is all you need. Failures raise, sizes and times come back as numbers,
and the verbs are the ones you already use on local files.

```julia
using XRootD

XRootD.ls("root://eospublic.cern.ch//eos/opendata/cms")
file = XRootD.download("root://eospublic.cern.ch//eos/opendata/cms/data.root")
header = XRootD.read("root://eospublic.cern.ch//eos/opendata/cms/data.root"; length=1024)
```

The same operations on a [`StoragePath`](@ref) need no prefix, because the
type is ours to dispatch on:

```julia
f = xrd"root://eospublic.cern.ch//eos/opendata/cms/data.root"

filesize(f)
isfile(f)
cp(f, "data.root")
open(f) do io
    read(io, 1024)
end
```

One implementation, two front doors: `XRootD.read(url)` and `read(path)` run
the same code. [Getting started](@ref) walks through reading, browsing,
copying and writing in the order a job does them.

Underneath, the `XRootD.XrdCl` module provides the two protocol-level types —
`FileSystem` for namespace operations and `File` for I/O — with a
`(status, result)` return convention instead of exceptions.

```julia
using XRootD.XrdCl

fs = FileSystem("root://localhost:1094")     # or roots:// for TLS

st, _ = ping(fs)
isError(st) && error(st)

st, statinfo = stat(fs, "/tmp")
if isOK(st) && isdir(statinfo)
    st, entries = readdir(fs, "/tmp")
    foreach(println, entries)
end

# File I/O
f = File()
st, _ = open(f, "root://localhost:1094//tmp/testfile.txt", OpenFlags.New | OpenFlags.Write)
write(f, "Hello\nWorld\n")
close(f)

st, _ = open(f, "root://localhost:1094//tmp/testfile.txt", OpenFlags.Read)
st, lines = readlines(f)
close(f)
```

[Recipes](@ref) works through the three things most jobs do — reading over
`root://`, listing a remote server, reaching data with a token over WebDAV —
and what to set when the network in between is unreliable.

## Architecture

The client is built in layers, each depending only on the one below:

- `XRootD.Wire` — pure wire-format codecs (no I/O).
- `XRootD.Session` — connections, TLS, authentication (unix / bearer token /
  sss / X.509 client certificates), request multiplexing, resilience.
- `XRootD.XrdCl` — the public `File` / `FileSystem` API.
- `XRootD.Storage` — backend-agnostic storage dispatching on URL scheme
  (`root(s)://`, `http(s)://`/`dav(s)://`, `s3(s)://`, local paths).
- `XRootD.Tools` — the copy engine and `xrdcp` / `xrdfs` / checksum CLI
  equivalents (`bin/*.jl`).

## Credentials

Every storage backend takes the same bag of credential keywords, and
`storage_for` hands each one only the options its scheme understands — so a
single set of flags can be applied to a copy whose two endpoints speak
different protocols. `xrdcp` exposes the same set on the command line.

| Keyword | Schemes | Meaning |
|---|---|---|
| `token` | `root(s)`, `http(s)`, `dav(s)` | WLCG bearer token: `ztn` on xroot, `Authorization: Bearer` over HTTP. Discovered from `$BEARER_TOKEN`, `$BEARER_TOKEN_FILE`, `$XDG_RUNTIME_DIR/bt_u<uid>`, `/tmp/bt_u<uid>` when not given. |
| `use_token` | `http(s)`, `dav(s)` | Set `false` to suppress discovery for this endpoint. |
| `allow_cleartext_token` | `http(s)`, `dav(s)` | Permit sending a token over an unencrypted `http://` connection. |
| `cert`, `key` | `roots`, `https`, `davs` | X.509 client certificate and private key. A proxy PEM holds both, so `key` may be omitted. Discovered from `$X509_USER_PROXY`, `/tmp/x509up_u<uid>`, `$X509_USER_CERT`/`$X509_USER_KEY`, then `~/.globus/usercert.pem` + `userkey.pem`. |
| `cafile` | `roots`, `https`, `davs` | Extra CA bundle to trust, for a site CA outside the system store. `$X509_CERT_DIR` is picked up automatically for `roots://`. |
| `x509` | `root(s)` | Set `false` to skip X.509 discovery entirely. |
| `keytab` | `root(s)` | `sss` shared-secret keytab. |
| `insecure_tls` | `roots`, `https`, `davs` | Skip peer verification. For debugging only. |
| `headers` | `http(s)`, `dav(s)` | Extra request headers. |
| `creds`, `endpoint` | `s3(s)` | S3 credentials and endpoint override. |

### When a credential is missing

Discovery is what a batch job relies on, so nothing here changes when a
credential is found. When one is *not* found and the server has said it wants
it, the client asks — on the terminal, if there is one:

```
$ xrdfs root://xrootd.example.org ls /store
xrootd: root://xrootd.example.org:1094 asks for a bearer token (ztn) and none was found
        looked in: $BEARER_TOKEN, $BEARER_TOKEN_FILE, /run/user/1000/bt_u1000, /tmp/bt_u1000
        give a path to a token file, or paste the token itself
        press Enter alone to continue without one
        token:
```

The rules are deliberately narrow, because a prompt that fires when it should
not is worse than no prompt at all:

- Only when both stdin and stderr are a terminal. A pipeline stage, a batch
  job or a notebook cell fails with the message above instead of blocking on
  a read nobody will answer. `XRDC_NO_PROMPT=1` also turns it off for a
  script that does run under a terminal.
- Only when the credential would otherwise be missed: a bearer token when the
  alternative is an anonymous `unix` login that an authorizing server will
  refuse operation by operation, an `sss` keytab when the server offers
  nothing else, an X.509 credential when the peer has refused the TLS
  handshake for want of one, a passphrase for an encrypted private key, and a
  bearer token when an `https://` or `davs://` endpoint has answered `401`.
  The request that met the `401` is retried with the answer, and the rest of
  the transfer carries it.
- Once per process. A redirect chain re-authenticates at every hop, and so
  does a copy that opens both endpoints; the answer — including "no, carry on
  without one" — is remembered for all of them. A credential the server then
  *rejects* is forgotten, so the next attempt asks again.

An answer to the token prompt may be a path to a token file or the token
itself; the two are told apart by whether it looks like a path, so a mistyped
filename is reported rather than sent to the server as a credential.

`Session.prompt_credentials!` replaces the terminal prompter with anything
else — a GUI dialog, a secret manager, a notebook widget, a fixed answer in a
test:

```julia
using XRootD.Session: prompt_credentials!

prompt_credentials!(req -> req.kind === :token ? read(`vault-read`, String) : nothing)
```

The function is called with a `Session.CredentialRequest` naming what is
wanted (`:token`, `:x509`, `:x509key`, `:passphrase`, `:keytab`), which
endpoint wants it, and every location already searched. Returning `nothing`
means "proceed without one", which is exactly what the client does when no
terminal is attached. `prompt_credentials!(nothing)` restores the default.

A token is a bearer credential: anyone who sees it can use it. A token that
was *discovered* is therefore dropped rather than sent over cleartext
`http://` (with a warning), and one passed *explicitly* raises an
`ArgumentError` unless `allow_cleartext_token=true` says the risk is
understood. The same rule holds for `ztn` on the xroot side: the token
travels only inside TLS, so on a cleartext `root://` connection the
mechanism is skipped in favour of whatever else both ends speak — reconnect
with `roots://`, or set `XRDC_ZTN_CLEARTEXT=1` to say the risk is
understood. Legacy GSI (the pre-TLS X.509 handshake on the xroot control
stream) is not implemented; X.509 credentials authenticate through TLS, which
is what current servers expect.

## Environment

A process configured for the C++ client is configured for this one. The
`XRD_*` variables XrdCl reads are honoured under their own names, so a grid
job, a site login script or a container image built for `xrdcp` needs no
second configuration.

| Variable | Effect |
|---|---|
| `XRD_USERNAME` | Login account asserted at `kXR_login`, ahead of `$USER` and `$LOGNAME`. |
| `XRD_REQUIRETLS` | Upgrade every connection to TLS, as though every URL were `roots://`. |
| `XRD_TLSNOCERTVERIFY` | Skip peer-certificate verification. Debugging only. |
| `XRD_CONNECTIONWINDOW` | Seconds a TCP connect may take before it is abandoned, and the ceiling on each step of the bring-up that follows it (default 30; `0` waits as long as the kernel does). |
| `XRD_STREAMTIMEOUT` | Seconds a session may sit idle before a `kXR_ping` keeps it alive (default 0, no keepalive). |
| `XRD_REQUESTTIMEOUT` | Ceiling in seconds on one operation: the cumulative `kXR_wait` parking it may be asked to do, and the absolute deadline it must finish inside either way (default 1800). |
| `XRD_REDIRECTLIMIT` | Redirect hops followed before giving up (default 8). |
| `XRD_CPCHUNKSIZE` | Bytes moved per read or write (default 1 MiB). |
| `XrdSecPROTOCOL` | Authentication mechanisms to try, best first, comma- or space-separated. Both orders and *restricts*: a mechanism left out is not tried even when the server offers it. |
| `X509_CERT_FILE`, `SSL_CERT_FILE` | CA bundle to trust, on top of the system store. |
| `X509_USER_PROXY`, `X509_USER_CERT`, `X509_USER_KEY`, `X509_CERT_DIR` | X.509 credential and hashed CA directory, as in the table above. |
| `BEARER_TOKEN`, `BEARER_TOKEN_FILE` | WLCG bearer token, as in the table above. |
| `XRDC_ZTN_CLEARTEXT=1` | Offer a `ztn` bearer token over a cleartext `root://` connection. By default the token is held back there and presented only inside TLS. |
| `XRD_PROMPT=0` | Never ask for a missing credential, even under a terminal (`XRDC_NO_PROMPT=1` does the same). |

The client's own knobs govern what it does when the network between you and
the storage misbehaves; [Recipes](@ref) explains what each one protects
against.

| Variable | Effect |
|---|---|
| `XRDC_MAX_RETRIES` | Times one operation may be retried after a transport loss (default 4; `0` disables retrying). |
| `XRDC_RETRY_BASE_MS` | First backoff window, doubled per attempt (default 200). |
| `XRDC_RETRY_CAP_MS` | Ceiling on that window (default 5000). |
| `XRDC_MAX_STALL_MS` | Wall-clock budget for one operation's reconnect-and-replay (default 30000). |
| `XRDC_MAX_WAIT_MS` | Cumulative `kXR_wait` parking allowed for one operation (default 1800000); overrides `$XRD_REQUESTTIMEOUT`. |
| `XRDC_TCP_KEEPALIVE_S` | Idle seconds before `SO_KEEPALIVE` probes the socket (default 60; `0` leaves the system default). |
| `XRDC_HTTP_IDLE_TIMEOUT_S` | Seconds an HTTP response body may stall before the read is abandoned (default 120; `0` disables). |
| `XRDC_STALL_DEADLINE_MS` | Absolute ceiling on one `root://` operation, whatever the server is doing with the time (default `$XRD_REQUESTTIMEOUT`; `0` disables). |
| `XRDC_HTTP_REQUEST_TIMEOUT_S` | The same ceiling on one HTTP request, headers and body (default `$XRD_REQUESTTIMEOUT`; `0` disables). |

An explicit keyword always wins over the environment, and so does this
client's own `XRDC_*` knob where it has one — `XRDC_MAX_WAIT_MS` overrides
`$XRD_REQUESTTIMEOUT`, being the more specific of the two. A value that does
not parse, or one that is negative, leaves the default standing: a typo in a
site profile reaches every job at once, and failing all of them is a worse
answer than ignoring the typo.

Credentials are kept out of anything the client prints. A `File`,
`FileSystem`, `Connection` or storage backend displays the endpoint it talks
to and the *kinds* of credential it holds, never their values, and a URL
carrying one in its query string (`?authz=`, a presigned `X-Amz-Signature`)
is redacted on the way out — a token printed once into a CI log is as
compromised as one posted in a chat window.

## Parallel data paths

A session multiplexes every request onto one socket, which is usually what
you want and occasionally the thing standing in your way: a multi-gigabyte
read has to be handed over in pieces, and everything else on that session
queues behind those pieces. `kXR_bind` is the protocol's answer — a second
connection joins the session and carries the bulk bytes, leaving the control
link free for the requests that must interleave with them.

```julia
st, pathid = bind_data_path!(f)     # f::File, already open
isOK(st) || @warn "no data path" st.message
st, buf = read(f, 64 * 1024 * 1024) # data arrives on the bound link
```

The bind presents the session id the login gave out rather than logging in
again, so no credential is re-sent; the new link inherits the control link's
encryption, because a second connection in the clear would carry the very
bytes the first one was encrypting.

Path ids belong to a session. A handle that loses its connection and reopens
([`reopen!`](@ref)) falls back to the control link on its own — the id the
old session issued means nothing to the new one — and can be bound again.
Losing the data path alone costs only the requests routed over it; the
session stays up.

A single sequential read on an otherwise idle session gains nothing from
this: the same bytes cross the same network. It pays when a transfer shares a
session with work that has to stay responsive.

## Objects as Julia streams

`storage_open` opens any storage URL as an ordinary Julia `IO`, so a remote
object can be handed to code that knows nothing about XRootD:

```julia
using XRootD.Storage: storage_open

storage_open("root://xrootd.example.org//store/data/run3/AOD.root") do io
    seek(io, 1 << 30)                     # a gigabyte in, without reading the first
    read(io, 4096)
end

storage_open("s3://bucket/out.root", "w"; length=nbytes) do io
    write(io, chunk)                      # …as many times as it takes
end
```

`"r"` gives a `StorageReader` and `"w"` a `StorageWriter`, both `<: IO`, with
`read`, `read!`, `readbytes!`, `readavailable`, `write`, `seek`, `skip`,
`position`, `eof` and `flush` meaning what they mean everywhere else. Reads are
buffered `$XRD_CPCHUNKSIZE` at a time, so a seek-and-read over a
hundred-gigabyte file costs one chunk of memory; the `root://` lane keeps one
open handle for the whole stream and addresses it by offset, while the HTTP and
S3 lanes refill with a ranged `GET`.

An `IO` has nowhere to put a status code, so this layer raises `StorageError`
where the rest of `Storage` returns `:ok` / `:error`. For a writer that includes
`close`, which is where the endpoint's verdict on the upload arrives — and where
a `do` block ends.

Pass `length=` to a writer whenever the size is known. Over HTTP it frames the
upload with `Content-Length` and streams the body as the caller writes it,
rather than buffering to discover the size and falling back to
`Transfer-Encoding: chunked`; on S3 it sizes the multipart parts, which bounds
memory and lifts the object ceiling from 640 GB to S3's own 5 TB. A stream that
ends short of what it declared fails the upload instead of storing a truncated
object. What a streamed body gives up is replay: a transport failure or a `401`
part-way through cannot be retried, and is reported rather than repeated.

## Copying and third-party copy

`copyfile` streams through a bounded pipe — the source backend fills it while
the destination drains it — so a copy costs a fixed amount of memory rather
than the size of the object, and `verify=true` re-reads the destination and
compares checksums.

```julia
using XRootD.Tools: copyfile

copyfile("root://src.example.org//data/in.root",
         "davs://dst.example.org/data/out.root";
         verify=true, tpc=:first)
```

With `tpc=:first` the endpoints are asked to move the bytes between
themselves and a streaming copy is the fallback; `tpc=:only` fails instead of
falling back. Both third-party protocols are implemented: WLCG HTTP-TPC
(`COPY` carrying `Source:` or `Destination:` plus
`TransferHeaderAuthorization:`) between two HTTP/WebDAV endpoints, and the
xroot rendezvous (`tpc.stage=placement` at the source, `tpc.stage=copy` at
the destination) between two xroot endpoints. Two S3 objects at one endpoint,
under one credential, take the same bargain by another name: the
`x-amz-copy-source` the endpoint executes for itself. A pair with no common
third-party path — anything involving a local path, one endpoint of each
protocol, or two S3 endpoints or accounts — reports `:unsupported`, which is
what `:first` falls back on. The xroot rendezvous is tested against the wire format, not
against a production TPC deployment.

`dav(s)://` endpoints support the WebDAV write verbs, so they can be a copy
destination: `storage_mkdir` issues `MKCOL` (an existing collection's `405`
counts as success), `storage_move` issues `MOVE` and `storage_copy` `COPY`,
both with an `Overwrite:` header.

`s3(s)://` objects have the same surface. `storage_list` walks one level of a
key prefix (`ListObjectsV2` with `/` as the delimiter, following the
continuation token), so `s3://bucket/data` answers with the objects directly
under `data/` and the prefixes below it as directories. `storage_copy` is
`x-amz-copy-source` — the endpoint moves the bytes, not this client — and
`storage_move` is that copy followed by a delete, since S3 has no rename;
both take a destination at the same endpoint. An upload larger than
`Storage.S3_PART_SIZE` becomes a multipart upload rather than one `PUT`,
which bounds the memory a copy holds (SigV4 signs a hash of the payload, so
a request cannot start before its last byte arrives) and lifts the 5 GB
single-`PUT` ceiling; a part that fails aborts the upload instead of leaving
its fragments behind.

## Migration from 0.2.x

The `File` / `FileSystem` API and the `(status, result)` convention are
unchanged, so most 0.2.x code runs as-is. Notable changes:

- `roots://` URLs now negotiate in-protocol TLS.
- New operations: `sync`, `readv`, `writev`, `pgread`, `pgwrite`,
  `getxattr` / `setxattr` / `listxattr` / `removexattr`, `statvfs`,
  `checksum`, `prepare`, `symlink` / `hardlink` / `readlink`.
- Path predicates and whole-tree operations that read like `Base`'s:
  `ispath`, `isfile`, `isdir`, `filesize`, `touch`, `mkpath`, and
  `rm(fs, path; recursive=true)`.
- `statx` answers about many paths in one request, `xattrs` reads every
  attribute of one path in one request, `dirlist_checksum` lists a directory
  with a digest per entry in one request, and `checkpoint` brackets a group
  of writes the server can roll back.
- `clone` copies byte ranges between two open files inside the server, and
  `open(f, url, flags; conn=other.conn)` puts the two handles it needs on
  one session. `gpfile` sends `kXR_gpfile`, which no server yet answers;
  `supports_gpfile` and its neighbours read the capability bits off a
  `protocol` reply.
- No `XRootD_jll` / CxxWrap dependency; the test-only server still comes from
  `XRootD_jll`.

## Attribution

The wire-format ground truth, client semantics, and architecture implemented
here were developed in the `libxrdc` pure-C client and protocol reference of
the nginx-xrootd project. This package is a Julia translation of that prior
work.

## API

```@contents
Pages = ["api/everyday.md", "api/client.md", "api/storage.md", "api/tools.md"]
Depth = 1
```
