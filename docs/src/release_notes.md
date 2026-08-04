
# Release Notes

## Unreleased
An everyday API in `XRootD` itself, for people whose subject is physics and
not this protocol:

- [`StoragePath`](@ref) — a URL you can hold, over `root(s)://`,
  `http(s)://`, `dav(s)://`, `s3(s)://` and local paths. `filesize`, `mtime`,
  `stat`, `isfile`, `isdir`, `ispath`, `open`, `read`, `readlines`,
  `eachline`, `write`, `readdir`, `walkdir`, `joinpath`, `basename`,
  `dirname`, `mkpath`, `mkdir`, `cp`, `mv` and `rm` all work on one, and mean
  what they mean locally. The `xrd"root://…"` literal builds one and
  interpolates.
- The same verbs qualified, taking the URL as a string, so that a beginner
  who types one is not met with a `MethodError`: `XRootD.ls`,
  `XRootD.read`, `XRootD.open`, `XRootD.write`, `XRootD.filesize`,
  `XRootD.exists`, `XRootD.isfile`, `XRootD.isdir`, `XRootD.mkdir`,
  `XRootD.rm`, `XRootD.mv`. One implementation, two front doors.
- `XRootD.download`, `XRootD.upload` and `XRootD.copy` between any two
  endpoints, verifying by default, resolving a directory destination to the
  source's own name, and overwriting rather than failing a re-run. Progress
  reports itself where someone is watching — a self-rewriting line at a
  terminal, and silence in a notebook or a batch log unless `progress=true`
  asks for a periodic line.
- Failures raise `StorageError` carrying the endpoint's own words, and a
  refused credential says what was wanted and everywhere that was searched.
  A `StoragePath` prints its credentials as `<redacted>`.
- A listing renders as something legible rather than as a vector of structs,
  and carries the sizes and times the server sent with it, so asking an entry
  how big it is costs no second round trip.

Mistakes that used to be answered badly:

- A copy onto itself is refused instead of performed. A copy opens its
  destination before it reads its source, so `cp(f, f)` — or a `download` into
  a directory that already holds a file of that name — truncated the object it
  was about to read and then reported a short read. Local paths are compared
  through the filesystem, so a symlink or hard link to the same inode counts.
- A URL whose scheme this client does not speak raises `ArgumentError` naming
  the schemes it does. `rooot://host//data` used to fall back to the local
  filesystem and report "no such file or directory" about a path nobody wrote.
- A transfer whose *destination* could not be written says so, with the
  endpoint's reason, instead of blaming a read of the source — closing the
  pipe under the reader made a broken destination look like a broken source.
- A negative `offset` or `length` is an `ArgumentError` rather than
  `invalid GenericMemory size: too large for system address width`.

Operations the reference clients (`libxrdc`, go-hep's `xrootd`, PyXRootD,
XrdRust) carry and 0.3.0 did not:

- Path predicates answered from a single `stat`: `ispath`, `isfile`, `isdir`,
  `filesize`. `ispath` distinguishes absence from failure — a server that
  refuses to answer raises rather than reporting "no".
- Whole-tree operations: `mkpath` (one `kXR_mkdir` with `kXR_mkdirpath`,
  not a walk), `touch`, and `rm(fs, path; recursive=true)`, which empties a
  directory before removing it.
- `statx` — one flags byte per path, so a whole directory can be classified
  in one request; the answers come back as [`StatFlags`](@ref).
- `xattrs` reads every extended attribute of a path in one `kXR_fattr` get,
  and the per-handle forms of `getxattr` / `setxattr` / `listxattr` /
  `removexattr` address an open `File` instead of a path.
- Checkpoints: `checkpoint_begin` / `commit` / `rollback` / `query`, the
  `checkpoint_write` and `checkpoint_truncate` forms that run inside one, and
  the `checkpoint(f) do ... end` block, which rolls back if the body throws.
- `File` recovery: a read-only handle whose connection died is reopened and
  the request replayed against the new handle (`reopen!`, `recoverable`).
  A handle opened for writing is not recoverable — reopening it would
  silently discard what the writer had already sent.
- `close(f; fsize=n)` — the all-or-nothing close, which makes the server
  reject and remove a file that came out the wrong length.
- `visa`, `compression`, per-handle `checksum`, `checksum_cancel`, `evict`,
  `query_config`, `set_property`, `appid`, `endsess`, `lstat`, `deep_locate`.
- `ProtocolInfo` now names the endpoint's role: `ismanager`, `isserver`,
  `ismeta`, `isproxy`, `issupervisor`. `ismanager` reads the same on a
  `protocol` reply and on a `locate` answer's `Location`.
- `xrdfs` reaches the new operations: `statx`, `locate`, `touch`, `chmod`,
  `truncate`, `checksum`, `prepare` (`-e` to evict), `xattr`, `mkdir -p` and
  `rm -r`.
- `error_name` renders a status's `code` as its protocol name, and the
  `ErrorCode` namespace gives the codes names to compare against.
  `XErrorCode` is a separate enumeration from the request opcodes despite
  sharing their numeric range.

- Parallel data paths (`kXR_bind`): `bind_data_path!(f)` gives an open `File`
  a second connection to its server, and its reads and writes then move their
  bulk bytes there while the control link stays free for everything else.
  The bind presents the session id rather than logging in again, so no
  credential is re-sent, and it inherits the control link's encryption. A
  path id belongs to a session: a handle reopened after a lost connection
  falls back to the control link instead of naming an id the new session
  never issued, and a data path that dies alone fails only the requests it
  was carrying.

- The S3 backend reaches the rest of its own protocol: `storage_list` pages a
  key prefix through `ListObjectsV2`, `storage_copy` is an `x-amz-copy-source`
  the endpoint executes for itself, `storage_move` is that copy plus a delete
  (S3 has no rename), and an upload past `Storage.S3_PART_SIZE` goes up as a
  multipart upload — bounded memory, no 5 GB single-`PUT` ceiling, and an
  aborted upload rather than abandoned parts when one fails.

- `XRootD.Tools.tpc_copy` takes that server-side copy as the S3 third-party
  path, so a copy between two keys at one endpoint under one credential no
  longer streams the object through this client; two endpoints or two
  accounts still report `:unsupported` and fall back.

- `storage_move` on an xroot backend now means what it does everywhere else:
  `kXR_mv` carries no "replace" flag, so an occupied destination is refused
  outright and cleared first when `overwrite=true`, rather than being left to
  whichever way the server happens to rule.

Streams — a storage object where a Julia `IO` is expected, in both directions:

- `storage_open(url)` and `storage_open(url, "w")` open any storage URL as an
  `IO`: `StorageReader` and `StorageWriter` implement `read`, `read!`,
  `readbytes!`, `readavailable`, `write`, `seek`, `seekstart`, `seekend`,
  `skip`, `position`, `eof`, `bytesavailable`, `flush` and `close`, so a remote
  object can be handed to code that knows nothing about this package. Reads are
  buffered `$XRD_CPCHUNKSIZE` at a time; the `root://` lane keeps one `kXR_open`
  handle for the whole stream and addresses it by offset, the HTTP and S3 lanes
  refill with a ranged `GET`, and a local path uses the file's own cursor rather
  than reopening per chunk. An `IO` has nowhere to put a status code, so this
  layer raises `StorageError` where the rest of `Storage` returns a `Symbol` —
  including from `close` on a writer, which is where the endpoint's verdict on
  the upload arrives.
- An endpoint that will not state a size is read to the end rather than treated
  as empty. `Content-Length: 0` on a `HEAD` used to be indistinguishable from an
  empty object; a stream now carries "size unknown" as its own state, finds the
  end by reading, and refuses `seekend` instead of guessing at it.
- `storage_write` over HTTP and WebDAV no longer holds the whole object in
  memory. An upload with a declared `length=` past 8 MiB is framed with
  `Content-Length` and streamed from the source as it arrives — which is what
  the reference clients send, and what the endpoints that reject
  `Transfer-Encoding: chunked` accept — and one without a declared length
  buffers 8 MiB to find out whether it is small before falling back to chunked.
  A source that ends short of what was declared fails the upload rather than
  storing a truncated object. What a streamed body gives up is replay: a
  transport failure or a `401` part-way through is reported on `b.lasterror`
  rather than retried, since the bytes are already gone. Small uploads keep both
  the retry and the `401`-then-authorize handshake.
- S3 part size is now chosen from the declared length rather than being a flat
  64 MiB, so a 200 MB object costs 5 MiB of memory instead of 64 MiB and the
  10 000-part ceiling lands at S3's own 5 TB object limit instead of at 640 GB.
  An explicit `part_size=` still wins.

Credentials:

- A credential the server asks for and discovery cannot find is now asked
  for, when — and only when — stdin and stderr are both a terminal:
  a bearer token when the alternative is an anonymous `unix` login, an `sss`
  keytab when the server offers nothing else, an X.509 credential when the
  peer refused the TLS handshake for want of one, and the passphrase for an
  encrypted private key, which was previously a hard error. An `https://` or
  `davs://` endpoint that answers `401` asks the same way, and the request is
  retried with what it is given. Everywhere else
  the client fails with the message it would have prompted with, so a batch
  job cannot block on a read nobody will answer. `XRDC_NO_PROMPT=1` turns it
  off.
- One prompt per process per credential, including a declined one: a redirect
  chain re-authenticates at every hop. A credential the server then rejects
  is forgotten, so the next attempt asks again.
- `Session.prompt_credentials!(f)` replaces the terminal prompter with a GUI,
  a secret manager or a test; `f` receives a `Session.CredentialRequest`
  naming what is wanted, which endpoint wants it, and everywhere already
  searched.
- A failed TLS handshake now says which side could not be verified —
  `Session.TLSHandshakeFailed` reports whether a client credential was
  presented, and points at `$X509_CERT_DIR` rather than at a client
  certificate when it was the server's chain that did not verify.
- Credentials are kept out of anything the client prints. `File`,
  `FileSystem`, `Connection`, `WebBackend`, `XRootDBackend` and
  `S3Credentials` display the endpoint and the *kinds* of credential they
  hold, and a URL carrying one in its query string (`?authz=`, a presigned
  `X-Amz-Signature`) is redacted. Previously a `@show` or an exception
  message would print a bearer token, an sss session key or an AWS secret key
  verbatim.

Bad networks — the failures a wide-area link produces between a job and the
storage it was given, rather than the ones a server reports:

- Retries are now bounded by an attempt count as well as by the stall window,
  and back off exponentially with full jitter (`XRDC_MAX_RETRIES`, default 4;
  `XRDC_RETRY_BASE_MS`, 200; `XRDC_RETRY_CAP_MS`, 5000). Previously every
  retry waited a fixed 200 ms, so a peer that refused instantly took ~150
  attempts inside the 30 s window — all of them landing on a server already in
  trouble — and a fleet that lost the same server came back to it in one
  burst. One policy now serves the `FileSystem` lane, the `File` reopen-and-
  replay lane and the HTTP/WebDAV lane. A redirect is still not a retry: it
  spends the hop budget.
- Sockets carry `SO_KEEPALIVE` (`XRDC_TCP_KEEPALIVE_S`, default 60 s). A
  black-holed connection — a NAT that dropped the mapping, a firewall that ate
  the FIN — is what a bad network actually produces, and without a kernel probe
  a read on one waits out the TCP retransmission budget, which runs to
  minutes. This is below `XRD_STREAMTIMEOUT`'s application-level `kXR_ping`,
  which detects a server that is up and no longer answering.
- HTTP and WebDAV requests retry on `408`, `425`, `429` and `5xx`, honour
  `Retry-After`, and have deadlines of their own: `XRD_CONNECTIONWINDOW` on
  the connect and `XRDC_HTTP_IDLE_TIMEOUT_S` (120 s) on a response body that
  stops arriving. `PROPFIND` and `MKCOL` are replayed alongside the methods
  HTTP.jl replays by default; `DELETE`, `COPY` and `MOVE` are withdrawn from
  it, for the same reason `rm` is not replayed over xroot — the repeat of one
  that already landed answers `404` and reports a removal that in fact
  happened as a failure. A transport failure is kept on the backend
  (`b.lasterror`)
  rather than being discarded, so "it did not work" can say why.
- A range answered with something other than a range is no longer taken as
  data. An endpoint that ignores `Range:` and answers `200` with the whole
  object had its body written to the caller's sink as though it were the
  window that was asked for — silent wrong bytes. The window is now taken out
  of a `200`, and a body shorter than the range reports `:truncated` instead
  of a short read that looks complete.
- A peer that accepts the connection and then stops talking no longer parks the
  caller. `XRD_CONNECTIONWINDOW` used to bound the TCP connect alone, and every
  step after it — handshake, `kXR_protocol`, the TLS upgrade, `kXR_login`, the
  `kXR_auth` round — read from the socket with no deadline at all, so a load
  balancer holding a connection open for a backend that never came up, or a
  middlebox that answers SYN and drops the rest, blocked the process forever.
  Each step is now guarded by that same window and reports which one the server
  never answered. The guard covers the exchange, not the prompt: a caller being
  asked for a token is entitled to take longer than a connection window to find
  it.
- One operation now has an absolute deadline by default, on both lanes:
  `XRDC_STALL_DEADLINE_MS` for `root://` and `XRDC_HTTP_REQUEST_TIMEOUT_S` for
  HTTP, each defaulting to `XRD_REQUESTTIMEOUT` (1800 s) and each disabled with
  `0`. The stall deadline existed but was off unless asked for, which left the
  slowest failure mode of all unbounded: a peer that dribbles one byte per
  idle-timeout window is never idle, never wrong, and never finished. An
  in-band `kXR_wait` or `kXR_waitresp` restarts the budget, so a server staging
  from tape is not cut off for saying so. S3 requests are bounded by the same
  three deadlines as WebDAV ones, having previously had none.
- Sends are bounded by that deadline too. A peer that stops *reading* — its
  receive window shut and never reopened, which is what a stalled server or a
  saturated path looks like from the sending end — filled both socket buffers
  and left the caller blocked inside `write`, where no reply deadline could
  reach it: it had not yet sent the request it would have been waiting for an
  answer to. A write that never drains now fails the operation and drops the
  connection, so the retry lane reconnects and replays. The teardown forces the
  socket closed rather than closing it politely, because a polite close asks
  the peer that stopped reading to read, and waits.
- `copyfile` compares what arrived against the size the source declared and
  fails with `short read: N of M bytes`. This is the failure `verify=true`
  cannot catch: a transfer that stops halfway leaves a valid short object
  whose checksum both ends agree on. An endpoint that will not declare a size
  is not held to one.

Environment:

- The `XRD_*` variables XrdCl reads are now honoured under their own names, so
  a process already configured for the C++ client needs no second
  configuration: `XRD_USERNAME`, `XRD_REQUIRETLS`, `XRD_TLSNOCERTVERIFY`,
  `XRD_CONNECTIONWINDOW`, `XRD_STREAMTIMEOUT`, `XRD_REQUESTTIMEOUT`,
  `XRD_REDIRECTLIMIT`, `XRD_CPCHUNKSIZE`, `XrdSecPROTOCOL`, `X509_CERT_FILE`
  and `SSL_CERT_FILE`. An explicit keyword wins over the environment, and this
  client's own `XRDC_*` knob wins where it has one. An unparseable or negative
  value leaves the default standing rather than failing the connection.
- `XrdSecPROTOCOL` both orders and restricts the authentication mechanisms
  tried: a mechanism it leaves out is not tried even when the server offers
  it, which is how a site pins its jobs to tokens. A failure caused by that
  narrowing names both lists, since "the server offered nothing usable" and
  "the environment excluded the one mechanism both sides had" otherwise look
  identical.
- `XRD_CONNECTIONWINDOW` gives TCP connects a deadline of their own (30 s by
  default). A host that has gone away without answering — a stale DNS entry, a
  dropped firewall rule — previously took the kernel's SYN retry budget,
  which runs to minutes.

The three opcodes no reference client sends, each answered on its own
evidence rather than as a set:

- `dirlist_checksum` lists a directory with a digest per entry (`kXR_dcksm`,
  dirlist option `0x04`) in one request, instead of a listing followed by a
  `kXR_query` checksum per file. The option implies `kXR_dstat` whether or
  not that bit is also set, so the stat lines come back too, and the
  algorithm is chosen with `algorithm=` the way `checksum` chooses one. An
  entry the server has no digest for — a directory, normally — says so
  rather than dropping the token and shifting every later answer onto the
  wrong name.
- `clone(dst, src, ranges)` copies byte ranges from one open file into
  another inside the server (`kXR_clone`), without them crossing this
  client. Both handles must be on one session, which is what
  `open(f, url, flags; conn=other.conn)` is now for: a `File` can be opened
  on a connection that is already up, and closing it leaves that connection
  to whoever dialed it. `kXR_clone` (3032) is an nginx-xrootd extension —
  the opcode sits one past `kXR_REQFENCE` in stock `XProtocol.hh` — so
  anything else answers `kXR_InvalidRequest`.
- `gpfile(fs, path)` sends `kXR_gpfile` and reports what comes back. Nothing
  answers it: upstream's own request struct carries the comment "This is all
  wrong; correct when implemented", and go-hep refuses to marshal the opcode
  at all. The request is encoded exactly as declared, the near-certain
  `kXR_Unsupported` is handed back unembellished, and the capability bits
  that qualify it are now readable off the `protocol` reply —
  `supports_gpfile`, `allows_anon_gpfile`, `supports_pgio`, `supports_posc` —
  so a caller can ask before sending. A server that said gpfile travels only
  over TLS (`kXR_tlsGPF`) is refused locally on a cleartext link rather than
  being sent to.

Deliberately not implemented, so that a reader comparing this client against
the reference ones knows the gaps are choices:

- `kXR_verifyw` (3026) is the pre-5.0 spelling of `kXR_pgwrite`, which is
  implemented; the old opcode is not sent.
- Legacy GSI authentication. Its replacement on a modern deployment is an
  X.509 client certificate over TLS or a bearer token, both of which are
  implemented, and reproducing GSI's own handshake would mean shipping a
  second, weaker credential path for servers that no longer require it.

## 0.3.0 (07-02-2026)
- **Pure-Julia rewrite.** The XRootD protocol is now implemented natively in
  Julia; the CxxWrap binding to the XrdCl C++ library and the `XRootD_jll` /
  `XRootD_cxxwrap_jll` runtime dependencies are removed (`XRootD_jll` remains
  a test-only dependency for the server). The `File` / `FileSystem` API and
  the `(status, result)` convention are unchanged.
- Layered architecture: `Wire` (codecs) → `Session` (connections, TLS, auth,
  multiplexing, resilience) → `XrdCl` (public API) → `Storage` (multi-backend
  dispatch) → `Tools` (copy engine + CLIs).
- In-protocol TLS via `roots://`, or on the server's demand (`kXR_gotoTLS`,
  `kXR_tlsLogin`, `kXR_tlsSess`); a demand the server cannot honour fails the
  session rather than falling back to cleartext.
- Authentication: unix, WLCG bearer tokens (ztn), sss shared-secret
  (pure-Julia Blowfish), and X.509 client certificates over TLS (grid proxy
  discovery, `roots://` and `https://`/`davs://`); `kXR_sigver` request
  signing for high-security servers.
- New operations: `sync`, `readv`, `writev`, `pgread`/`pgwrite` (per-page
  CRC32c), `getxattr`/`setxattr`/`listxattr`/`removexattr`, `statvfs`,
  `checksum`, `prepare`, `symlink`/`hardlink`/`readlink`.
- Resilience: redirect following (including a negative port, which names a
  TLS endpoint), reconnect-with-replay for idempotent operations, and idle
  keepalive.
- Web backends: `http(s)://`, `dav(s)://` (WebDAV), and `s3(s)://` (AWS
  Signature v4) through a `Storage` abstraction; an S3 `endpoint` may name its
  own scheme, so an S3-compatible service on a private network can be reached
  over plain HTTP.
- `Tools`: a backend-agnostic copy engine and Julia equivalents of `xrdcp`,
  `xrdfs`, `xrdadler32`, `xrdcrc32c`, `xrdcrc64`, and `xrdckverify`
  (`bin/*.jl`), verified byte-for-byte against the reference clients.
- Attribution: the protocol understanding and client semantics were
  developed in the `libxrdc` pure-C client of the nginx-xrootd project;
  this release is a Julia translation of that work.

## 0.2.4 (05-02-2026)
- Fix for #2
- Fix for #3
 
## 0.2.3 (03-09-2025)
- Upgraded to CxxWrap 0.17 to support Julia 1.12. It fixes [#1](https://github.com/JuliaHEP/XRootD.jl/issues/1)
- Removed from exports `url`, `length`, `Set` to avoid clashes with `Base`
- Invoke `wrapit` to generate wrappers in the script instead of CMake   

## 0.2.2 (11-12-2024)
- Added function walkdir to walk on a directory tree

## 0.2.1 (4-11-2024)
- Added some protection to avoid pre-compilation errors in case the XRootD binary artifacts do not exist (e.g. Windows platform)

## 0.2.0 (31-10-2024)
- Updated to XRootD 5.7.1, OpenSLL 3.0.15 and CxxWrap 0.16 (with libcxxwrap_julia_jll 0.13.2)

## 0.1.0 (31-05-2024)
- First release. It provides similar functionality as for the python bindings of the client library of XRootD
