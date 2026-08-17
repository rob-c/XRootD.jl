# Connection lifecycle: bring-up, streamid-multiplexed roundtrips, teardown.

"One response frame as delivered to a waiting request."
const Frame = Tuple{Wire.ResponseHeader,Vector{UInt8}}

"""
    DataPath

A second connection to the same server, attached to an existing session with
`kXR_bind` ([`bind_data_path!`](@ref)). Requests that name its `pathid` send
their write data, and receive their read replies, here instead of on the
control link — so a multi-gigabyte transfer stops standing between the
control link and the small requests that have to interleave with it.

It is a transport, not a session: its frames carry the *control* link's
streamids and are routed to the same `pending` table, so a caller never sees
which link answered.
"""
struct DataPath
    sock::IO
    pathid::UInt8
    wlock::ReentrantLock        # serializes writes of write-data
    reader::Base.RefValue{Union{Task,Nothing}}
end

"""
    Connection

A live `root://` session. Created by [`connect`](@ref). One reader Task
parses response frames off the socket and routes each to the Channel in
`pending` keyed by its streamid; operations run through [`roundtrip`](@ref).
"""
mutable struct Connection
    sock::IO                        # TCPSocket, or an OpenSSL.SSLStream after upgrade
    host::String
    port::Int
    username::String
    protover::UInt32
    flags::UInt32
    sessid::Vector{UInt8}
    pending::Dict{UInt16,Channel{Frame}}
    wlock::ReentrantLock            # serializes frame writes
    plock::ReentrantLock            # guards pending + nextsid
    nextsid::UInt16
    reader::Union{Task,Nothing}
    closed::Bool
    sec_level::Int                          # server security level (0 = no signing)
    sec_opts::UInt8                          # kXR_secOData/kXR_secOFrce from the trailer
    sec_overrides::Dict{UInt16,UInt8}        # secvec: opcode → sign requirement
    signing_key::Union{Vector{UInt8},Nothing}
    sig_seqno::UInt64
    last_activity::Float64                   # time() of the last frame sent
    keepalive::Union{Task,Nothing}
    stall_deadline_ms::Int                   # whole-operation cutoff (0 = disabled)
    datapaths::Dict{UInt8,DataPath}          # kXR_bind links, by path id
    routed::Dict{UInt16,UInt8}               # in-flight streamid → path id
    substreams_rw::Union{Bool,Nothing}       # paths carry whole frames (nothing = unprobed)
end

"""
    istls(c::Connection) -> Bool

`true` when this session's frames are encrypted — the socket was upgraded in
protocol, or the connection was made to a `roots://` endpoint. A request the
server said it will only take over TLS (`kXR_tlsGPF`, `kXR_tlsData`,
`kXR_tlsTPC`) asks this before it goes out.
"""
istls(c::Connection) = c.sock isa OpenSSL.SSLStream

"""
A connection prints its endpoint and state. The default field-by-field
display would print `signing_key` — the sss session key the server and this
process share — and a key that has been printed is a key that has to be
rotated.
"""
function Base.show(io::IO, c::Connection)
    print(io, "Connection(", c.username, "@", c.host, ":", c.port)
    print(io, c.closed ? ", closed" : ", open")
    istls(c) && print(io, ", tls")
    c.sec_level == 0 || print(io, ", signed(level $(c.sec_level))")
    return print(io, ")")
end

"""
The whole-operation deadline when nothing else says otherwise: the request
timeout ([`max_wait_ms`](@ref), i.e. `\$XRD_REQUESTTIMEOUT`, 30 minutes by
default). One request may not outlast the time XrdCl gives a request, however
the server manages to spend it.

A per-frame idle timeout would not do: a peer that dribbles one byte per
timeout window keeps a read alive forever, and a peer that simply stops
talking after the header keeps it alive with no bytes at all. Neither shows up
as a dead socket — the connection is open, the peer is running, nothing is
coming — so the cutoff has to be absolute over the whole logical operation.

`XRDC_STALL_DEADLINE_MS` tightens it (a few seconds is right for an
interactive tool), and `XRDC_STALL_DEADLINE_MS=0` turns it off for a caller
that would rather wait forever than lose a transfer. An in-band `kXR_wait` or
`kXR_waitresp` restarts the budget, so a server that says it is staging from
tape is not cut off for saying so — [`roundtrip`](@ref) bounds that parking
separately.
"""
stall_deadline_default_ms() = max_wait_ms()

"""
Resolve `XRDC_STALL_DEADLINE_MS` (milliseconds; unset or unparseable means
[`stall_deadline_default_ms`](@ref), an explicit `0` means no deadline).
"""
function stall_deadline_ms()
    v = get(ENV, "XRDC_STALL_DEADLINE_MS", "")
    isempty(v) && return stall_deadline_default_ms()
    n = tryparse(Int, v)
    return n === nothing || n < 0 ? stall_deadline_default_ms() : n
end

"""
Default ceiling on the *cumulative* `kXR_wait` parking of one operation: 30
minutes. A single wait is already clamped by [`Wire.wait_seconds`](@ref),
but a server that answers every re-send with another wait would otherwise
park a caller forever, so the advised delays are added up against this.
"""
const DEFAULT_MAX_WAIT_MS = 1_800_000

"""
Clamp on a single `kXR_waitresp` deferral, and the grace added to it before
the deferred reply is called overdue (libxrdc `frame.c`: 570 s + 30 s).
"""
const WAITRESP_CAP_S = UInt32(570)
const WAITRESP_GRACE_MS = 30_000

"""
Resolve `XRDC_MAX_WAIT_MS` (milliseconds), else `\$XRD_REQUESTTIMEOUT`
(seconds, XrdCl's spelling of the same ceiling), else the default. Zero or
unparseable means the default in both.
"""
function max_wait_ms()
    v = get(ENV, "XRDC_MAX_WAIT_MS", "")
    if !isempty(v)
        n = tryparse(Int, v)
        return n === nothing || n <= 0 ? DEFAULT_MAX_WAIT_MS : n
    end
    secs = env_number("XRD_REQUESTTIMEOUT", 0)
    return secs <= 0 ? DEFAULT_MAX_WAIT_MS : round(Int, secs * 1000)
end

"""
    TLSHandshakeFailed(host, port, had_client_cert, cause)

A TLS upgrade that did not complete. Wrapping the OpenSSL error this way
keeps the two questions a user actually has — was a client certificate
presented, and was the *server* the one we could not verify — attached to the
failure, instead of leaving them to be guessed from an alert number.
"""
struct TLSHandshakeFailed <: Exception
    host::String
    port::Int
    had_client_cert::Bool
    cause::Any
end

function TLSHandshakeFailed(host::AbstractString, port::Integer, had::Bool, cause)
    return TLSHandshakeFailed(String(host), Int(port), had, cause)
end

function Base.showerror(io::IO, e::TLSHandshakeFailed)
    print(io, "TLS handshake with $(e.host):$(e.port) failed: ")
    showerror(io, e.cause)
    if untrusted_server(e.cause)
        print(
            io,
            "\nthe server's certificate did not verify — add its CA with the " *
            "cafile= argument or \$X509_CERT_DIR (\$X509_CERT_DIR is where the " *
            "IGTF grid CAs live, and they are not in the default bundle)",
        )
    elseif !e.had_client_cert
        print(
            io,
            "\nno X.509 client credential was presented; if the server requires " *
            "one, create a proxy (voms-proxy-init) or pass cert=/key=",
        )
    end
    return nothing
end

"""
    TLSRequiredByServer(host, port)

A `kXR_login` the server refused with `kXR_TLSRequired`: it will only take
logins on an encrypted connection, and this one asked in the clear. Its own
exception type because — unlike every other login refusal — the client can
fix this one by itself: [`connect`](@ref) catches it and reconnects with TLS.
"""
struct TLSRequiredByServer <: Exception
    host::String
    port::Int
end

function Base.showerror(io::IO, e::TLSRequiredByServer)
    print(
        io,
        "$(e.host):$(e.port) refused the login: the server requires TLS " *
        "(kXR_TLSRequired)",
    )
    return nothing
end

"The OpenSSL wording for a peer that asked for a client certificate we did not have."
function wants_client_cert(cause)
    msg = sprint(showerror, cause)
    return occursin("certificate required", msg) ||
           occursin("peer did not return a certificate", msg) ||
           occursin("handshake failure", msg) ||
           occursin("bad certificate", msg)
end

"""
The OpenSSL wording for a *server* certificate we could not verify. Told
apart from [`wants_client_cert`](@ref) deliberately: offering to supply a
client credential when the problem is a CA we do not trust sends the user
looking in exactly the wrong place.
"""
function untrusted_server(cause)
    msg = sprint(showerror, cause)
    return occursin("certificate verify failed", msg) ||
           occursin("unable to get local issuer", msg) ||
           occursin("self signed certificate", msg) ||
           occursin("self-signed certificate", msg)
end

"""
    connect(host, port; username = ENV["USER"], want_tls = false,
            insecure_tls = false) -> Connection

Establish a session: TCP connect, then the 44-byte pipelined bring-up
segment (20-byte handshake + `kXR_protocol`, exactly as libxrdc `conn.c`
sends it); when the client requires TLS (`want_tls`, i.e. `roots://`) or
the server demands it ([`Wire.kXR_tlsDemands`](@ref) in the protocol reply),
the socket upgrades to TLS before `kXR_login` (libxrdc `tls.c`). The login
reply's security trailer then drives authentication
([`authenticate`](@ref)).

`insecure_tls` skips certificate-chain verification (test servers with
self-signed certificates only — never for production data).

`cert`/`key` name an X.509 client credential to present during the TLS
handshake; with neither given, [`discover_x509`](@ref) looks for a proxy in
the usual places. `x509 = false` suppresses that discovery. `cafile` adds a
CA bundle or hashed CA directory to the trusted roots, for a site CA that is
neither in the Mozilla bundle nor under `\$X509_CERT_DIR`.

Every keyword defaults from the environment XrdCl reads, so a process already
configured for the C++ client needs no second configuration: `\$XRD_USERNAME`,
`\$XRD_REQUIRETLS`, `\$XRD_TLSNOCERTVERIFY`, `\$X509_CERT_FILE`,
`\$XRD_CONNECTIONWINDOW` (`connect_timeout`) and `\$XRD_STREAMTIMEOUT`
(`keepalive_s`). An explicit keyword always wins.
"""
function connect(
    host::AbstractString,
    port::Integer;
    username::AbstractString=xrd_username(),
    want_tls::Bool=env_flag("XRD_REQUIRETLS"),
    insecure_tls::Bool=env_flag("XRD_TLSNOCERTVERIFY"),
    token::Union{AbstractString,Nothing}=nothing,
    keytab::Union{AbstractString,Nothing}=nothing,
    cert::Union{AbstractString,Nothing}=nothing,
    key::Union{AbstractString,Nothing}=nothing,
    cafile::Union{AbstractString,Nothing}=env_cafile(),
    x509::Bool=true,
    keepalive_s::Real=stream_timeout_s(),
    connect_timeout::Real=connection_window_s(),
)
    sock::IO = tcp_connect(String(host), Int(port), connect_timeout)
    try
        return bring_up(
            sock,
            String(host),
            Int(port);
            username,
            want_tls,
            insecure_tls,
            token,
            keytab,
            cert,
            key,
            cafile,
            x509,
            keepalive_s,
            connect_timeout,
        )
    catch err
        # A bring-up that fails owns the socket it opened. Leaving it to the
        # finalizer holds a half-open connection at the server — and a client
        # that walks a redirect chain fails bring-up repeatedly by design.
        try
            close(sock)
        catch
            # already gone, which is the state we wanted
        end
        # A login refused for arriving in the clear is fixed by arriving
        # encrypted. `want_tls` already true means the refusal survived a TLS
        # connection — something else is wrong, and retrying would recur.
        if err isa TLSRequiredByServer && !want_tls
            return connect(
                host,
                port;
                username,
                want_tls=true,
                insecure_tls,
                token,
                keytab,
                cert,
                key,
                cafile,
                x509,
                keepalive_s,
                connect_timeout,
            )
        end
        # A handshake the peer refused for want of a client certificate is the
        # one failure a user can still fix from here. `cert` being unset is
        # also what stops the retry from recurring: the second attempt carries
        # one, so it cannot ask again.
        offered = cert === nothing ? prompt_client_cert(err) : nothing
        offered === nothing && rethrow()
        return connect(
            host,
            port;
            username,
            want_tls,
            insecure_tls,
            token,
            keytab,
            cert=offered.cert,
            key=offered.key,
            cafile,
            x509,
            keepalive_s,
            connect_timeout,
        )
    end
end

"""
    tcp_connect(host, port, timeout_s) -> IO

Connect, giving up after `timeout_s` seconds (`\$XRD_CONNECTIONWINDOW`); zero
or negative waits as long as the operating system does. A host that has gone
away without answering — a stale DNS entry, a dropped firewall rule — is the
case this exists for: the kernel's own SYN retry budget runs to minutes, which
is longer than any interactive caller will wait.

The abandoned attempt is closed when it eventually completes rather than left
to a finalizer, so a timed-out connect cannot leave a socket open at a server
that was merely slow.
"""
function tcp_connect(host::String, port::Int, timeout_s::Real)
    timeout_s <= 0 && return keepalive!(Sockets.connect(host, port))
    attempt = Threads.@spawn Sockets.connect(host, port)
    if timedwait(() -> istaskdone(attempt), Float64(timeout_s); pollint=0.05) === :timed_out
        Threads.@spawn begin
            try
                close(fetch(attempt))
            catch
                # It failed on its own, which is the outcome we wanted anyway.
            end
        end
        error("connecting to $host:$port timed out after $(timeout_s)s")
    end
    try
        return keepalive!(fetch(attempt))
    catch err
        # The caller asked for a connection, not for a Task: a refused
        # connection must arrive as the IOError it would have been without the
        # timeout, or every `catch` upstream would have to learn a new type.
        err isa TaskFailedException ? throw(current_exceptions(attempt)[1][1]) : rethrow()
    end
end

"""
    keepalive!(sock, delay_s = tcp_keepalive_s()) -> sock

Ask the kernel to probe an idle connection (`SO_KEEPALIVE`, first probe after
`delay_s` seconds; see [`DEFAULT_TCP_KEEPALIVE_S`](@ref)), and return the
socket either way.

The probe interval and count remain the system's, so this bounds a
black-holed connection rather than detecting one quickly: the loss surfaces
after the idle delay plus the kernel's probe budget. Bounded is the whole
point — the alternative is a socket that never reports anything at all.

Failure is deliberately not an error. A platform that declines the option
leaves a working connection that is merely less well guarded, which is not a
reason to refuse to talk to the storage element.
"""
function keepalive!(sock::IO, delay_s::Real=tcp_keepalive_s())
    (delay_s > 0 && sock isa TCPSocket && isopen(sock)) || return sock
    # `sock.handle` is only stable under the IO lock, which is also how
    # `Sockets.nagle` reaches libuv for the neighbouring socket option.
    Base.iolock_begin()
    try
        handle = sock.handle
        handle == C_NULL || ccall(
            :uv_tcp_keepalive,
            Cint,
            (Ptr{Cvoid}, Cint, Cuint),
            handle,
            Cint(1),
            round(UInt32, max(delay_s, 1)),
        )
    catch
        # An option the platform will not take is not a reason to fail.
    finally
        Base.iolock_end()
    end
    return sock
end

"""
    BringUpTimeout(host, port, phase, timeout_s)

A bring-up step the peer never answered. Told apart from a connect timeout on
purpose: the connection was established and then went quiet, which is a
different fault — and a different thing to tell the user — from a host that
never accepted at all.
"""
struct BringUpTimeout <: Exception
    host::String
    port::Int
    phase::String
    timeout_s::Float64
end

function Base.showerror(io::IO, e::BringUpTimeout)
    print(
        io,
        "session bring-up to $(e.host):$(e.port) timed out after $(e.timeout_s)s " *
        "waiting for $(e.phase) (\$XRD_CONNECTIONWINDOW)",
    )
    return nothing
end

"""
    abort_socket!(sock)

Tear a socket down without waiting on the peer for anything.

`close` is the wrong tool for a watchdog: on a stream with a queued write it
asks libuv to shut the write side down *first*, which means waiting for the
peer that stopped reading to read. The queued write then never completes, and
the `close` call itself can block alongside it — the watchdog dies of the
condition it exists to break. Forcing the handle closed cancels the pending
request instead, so the blocked writer unblocks with an `IOError` and a
blocked reader with an `EOFError`.

A socket already closing is left alone: `uv_close` twice on one handle is a
libuv assertion failure, and the first call has already done the job.
"""
function abort_socket!(sock::IO)
    if !(sock isa Base.LibuvStream)
        close(sock)
        return nothing
    end
    Base.iolock_begin()
    try
        if sock.handle != C_NULL &&
            sock.status != Base.StatusClosing &&
            sock.status != Base.StatusClosed
            ccall(:jl_forceclose_uv, Cvoid, (Ptr{Cvoid},), sock.handle)
            sock.status = Base.StatusClosing
        end
    finally
        Base.iolock_end()
    end
    return nothing
end

"""
    guard_io(f, sock, timeout_s, mkerr) -> f()

Run one blocking socket operation under a watchdog that tears `sock` down
after `timeout_s` seconds (zero or negative for none), and report the failure
that follows as `mkerr()` rather than as the incidental `IOError` of a socket
somebody else closed.

Killing the socket is what ends the operation; nothing else interrupts a
blocking `unsafe_read` or `uv_write` ([`abort_socket!`](@ref)). A TLS stream is
torn down through the TCP socket underneath it, so the callback cannot itself
block on an SSL shutdown exchange with the peer that is already refusing to
talk.
"""
function guard_io(f::Function, sock::IO, timeout_s::Real, mkerr::Function)
    timeout_s <= 0 && return f()
    raw = sock isa OpenSSL.SSLStream ? sock.io : sock
    tripped = Threads.Atomic{Bool}(false)
    finished = Threads.Atomic{Bool}(false)
    watchdog = Timer(Float64(timeout_s)) do _
        finished[] && return nothing
        tripped[] = true
        try
            abort_socket!(raw)
        catch
            # already gone, which is the state we wanted
        end
    end
    try
        result = f()
        finished[] = true
        return result
    catch
        tripped[] || rethrow()
        throw(mkerr())
    finally
        close(watchdog)
    end
end

"""
    guard_bringup(f, sock, host, port, timeout_s, phase) -> f()

Run one synchronous bring-up step under a watchdog ([`guard_io`](@ref)) bounded
by `timeout_s` (`\$XRD_CONNECTIONWINDOW`), reporting a step the peer never
answered as a [`BringUpTimeout`](@ref).

Bring-up reads block: they run before the reader Task exists, so the stall
deadline that bounds an ordinary request ([`arm_stall`](@ref)) is not in play
yet, and [`tcp_connect`](@ref) bounds only the connect itself. A peer that
completes the TCP handshake and then says nothing — a load balancer holding
the connection open for a backend that never came up, a middlebox that answers
SYN and drops the rest — would otherwise park the caller for as long as it
cares to stay silent, with `SO_KEEPALIVE` no help because the peer is alive.
"""
function guard_bringup(
    f::Function,
    sock::IO,
    host::AbstractString,
    port::Integer,
    timeout_s::Real,
    phase::AbstractString,
)
    mkerr() = BringUpTimeout(String(host), Int(port), String(phase), Float64(timeout_s))
    return guard_io(f, sock, timeout_s, mkerr)
end

"""
Ask for the X.509 credential a refused handshake needs, or `nothing` when
`err` is some other failure, nobody is there to ask, or the answer was empty.
A proxy keeps its key in the same PEM as its chain, so the key is asked for
only when the certificate given does not carry one.
"""
function prompt_client_cert(err)
    err isa TLSHandshakeFailed || return nothing
    (err.had_client_cert || untrusted_server(err.cause)) && return nothing
    wants_client_cert(err.cause) || return nothing
    cert = ask_credential(
        CredentialRequest(
            :x509,
            err.host,
            err.port;
            reason="$(err.host):$(err.port) refused the TLS handshake and no X.509 client credential was presented",
            searched=vcat(
                x509_proxy_candidates(), "\$X509_USER_CERT", "~/.globus/usercert.pem"
            ),
        ),
    )
    cert === nothing && return nothing
    pem_has_key(cert) && return (cert=cert, key=cert)
    key = ask_credential(
        CredentialRequest(
            :x509key,
            err.host,
            err.port;
            reason="$cert holds no private key",
            searched=["\$X509_USER_KEY", "~/.globus/userkey.pem"],
        );
        scope=cert,
    )
    return key === nothing ? nothing : (cert=cert, key=key)
end

"""
The bring-up itself, on an already-connected `sock`: handshake,
`kXR_protocol`, the TLS decision, `kXR_login` and any authentication the
login reply calls for. Returns the live [`Connection`](@ref).
"""
function bring_up(
    sock::IO,
    host::String,
    port::Int;
    username::AbstractString,
    want_tls::Bool,
    insecure_tls::Bool,
    token::Union{AbstractString,Nothing},
    keytab::Union{AbstractString,Nothing},
    cert::Union{AbstractString,Nothing},
    key::Union{AbstractString,Nothing},
    cafile::Union{AbstractString,Nothing},
    x509::Bool,
    keepalive_s::Real,
    connect_timeout::Real=connection_window_s(),
)
    # Bring-up is synchronous: the reader Task starts only once the session
    # is authenticated, so plain blocking reads are safe here — as long as
    # something bounds them, which is what `guard_bringup` is for.
    flags = if want_tls
        (Wire.kXR_secreqs | Wire.kXR_ableTLS | Wire.kXR_wantTLS)
    else
        (Wire.kXR_secreqs | Wire.kXR_ableTLS)
    end
    proto = guard_bringup(sock, host, port, connect_timeout, "the protocol reply") do
        write(
            sock,
            vcat(Wire.HANDSHAKE, Wire.encode(Wire.ProtocolRequest(; flags), UInt16(1))),
        )
        hs_hdr, _ = read_frame(sock)
        hs_hdr.status == Wire.kXR_ok || bringup_error("handshake", hs_hdr)
        p_hdr, p_body = read_frame(sock)
        p_hdr.status == Wire.kXR_ok || bringup_error("kXR_protocol", p_hdr)
        return Wire.decode_protocol(p_body)
    end

    server_demands = (proto.flags & Wire.kXR_tlsDemands) != 0
    if want_tls || server_demands
        if (proto.flags & Wire.kXR_haveTLS) == 0
            error(
                "TLS required but the server at $host:$port does not offer it " *
                "(protocol flags 0x$(string(proto.flags; base=16)))",
            )
        end
        creds = x509 ? discover_x509(; cert, key) : nothing
        sock = try
            guard_bringup(sock, host, port, connect_timeout, "the TLS handshake") do
                return tls_upgrade(sock, String(host); insecure_tls, creds, cafile)
            end
        catch err
            # A handshake that timed out says nothing about the credentials, so
            # it must not be dressed up as a certificate problem: that is the
            # error that offers to go looking for a proxy.
            err isa BringUpTimeout && rethrow()
            throw(TLSHandshakeFailed(host, port, creds !== nothing, err))
        end
    end

    login = guard_bringup(sock, host, port, connect_timeout, "the login reply") do
        write(sock, Wire.encode(Wire.LoginRequest(username), UInt16(2)))
        l_hdr, l_body = read_frame(sock)
        if l_hdr.status == Wire.kXR_error && length(l_body) >= 4
            # kXR_TLSRequired is the one refusal with a remedy the client
            # holds: reconnect encrypted. `connect` catches this and does.
            errnum = Wire.decode_error(l_body).errnum
            (errnum & 0xffff) == Wire.kXR_TLSRequired &&
                throw(TLSRequiredByServer(String(host), Int(port)))
        end
        l_hdr.status == Wire.kXR_ok || bringup_error("kXR_login", l_hdr)
        return Wire.decode_login(l_body)
    end

    auth = if isempty(login.sec)
        nothing
    else
        authenticate(
            sock, username, login.sec; token, keytab, host, port, timeout_s=connect_timeout
        )
    end

    conn = Connection(
        sock,
        String(host),
        Int(port),
        String(username),
        proto.pval,
        proto.flags,
        login.sessid,
        Dict{UInt16,Channel{Frame}}(),
        ReentrantLock(),
        ReentrantLock(),
        UInt16(4),   # 1..3 were used during bring-up
        nothing,
        false,
        # The signing contract the kXR_protocol trailer advertised. It only
        # bites when the mechanism that won left a session key behind: a
        # server demanding signatures from a key-less session is refused per
        # request by the server, not guessed at here.
        Int(proto.seclvl),
        proto.secopt,
        Dict{UInt16,UInt8}(proto.secvec),
        auth === nothing ? nothing : auth.key,
        UInt64(0),   # sig_seqno
        time(),      # last_activity
        nothing,     # keepalive timer
        stall_deadline_ms(),
        Dict{UInt8,DataPath}(),
        Dict{UInt16,UInt8}(),
        nothing,     # substreams_rw: not yet probed
    )
    conn.reader = errormonitor(Threads.@spawn reader_loop(conn))
    keepalive_s > 0 && start_keepalive!(conn, Float64(keepalive_s))
    return conn
end

"""
Arm an idle keepalive: every `interval` seconds, if the connection has been
idle at least that long, send a `kXR_ping` so a long-lived handle survives
the server's idle timeout. The timer is cancelled on [`close`](@ref).
"""
function start_keepalive!(conn::Connection, interval::Float64)
    conn.keepalive = errormonitor(Threads.@spawn begin
        while !conn.closed
            sleep(interval)
            conn.closed && break
            if time() - conn.last_activity >= interval
                try
                    roundtrip(conn, Wire.PingRequest())
                catch
                    # a failed ping just means the reader task will tear down
                end
            end
        end
    end)
    return nothing
end

"""
    bind_data_path!(conn; insecure_tls, cert, key, cafile, x509, connect_timeout)
        -> UInt8

Open a second connection to the same server, attach it to `conn`'s session
with `kXR_bind`, and return the path id the server assigned. Requests built
with that id ([`Wire.ReadRequest`](@ref), [`Wire.WriteRequest`](@ref)) then
move their bulk bytes over it while their headers and replies stay in step on
the control link.

The data path is brought up as far as `kXR_bind` and no further: it presents
the *session's* id instead of logging in, so there is no second login and no
second authentication — which is also why the credential keywords here
configure only the TLS handshake. It inherits the control link's encryption:
a session that negotiated TLS binds over TLS, because a second link in the
clear would carry the file content the first one was encrypting.

Errors rather than returns on a path id of `0`: that is the id of the control
link, and a request naming it would send its data back down the link the bind
was meant to relieve.

Path ids belong to a session. A connection that was replaced — a redirect, a
reconnect after transport loss — has none of them, which is what
[`has_data_path`](@ref) is for.
"""
function bind_data_path!(
    conn::Connection;
    insecure_tls::Bool=env_flag("XRD_TLSNOCERTVERIFY"),
    cert::Union{AbstractString,Nothing}=nothing,
    key::Union{AbstractString,Nothing}=nothing,
    cafile::Union{AbstractString,Nothing}=env_cafile(),
    x509::Bool=true,
    connect_timeout::Real=connection_window_s(),
)
    isopen(conn) || error("cannot bind a data path to a closed connection")
    isempty(conn.sessid) &&
        error("$(conn.host):$(conn.port) issued no session id to bind to")

    want_tls = conn.sock isa OpenSSL.SSLStream
    sock::IO = tcp_connect(conn.host, conn.port, connect_timeout)
    pathid = try
        # The same bring-up as a session's, stopping before kXR_login: the
        # reads are blocking because no reader Task owns this socket yet.
        flags = if want_tls
            (Wire.kXR_secreqs | Wire.kXR_ableTLS | Wire.kXR_wantTLS)
        else
            (Wire.kXR_secreqs | Wire.kXR_ableTLS)
        end
        proto = guard_bringup(
            sock, conn.host, conn.port, connect_timeout, "the protocol reply"
        ) do
            write(
                sock,
                vcat(Wire.HANDSHAKE, Wire.encode(Wire.ProtocolRequest(; flags), UInt16(1))),
            )
            hs_hdr, _ = read_frame(sock)
            hs_hdr.status == Wire.kXR_ok || bringup_error("handshake", hs_hdr)
            p_hdr, p_body = read_frame(sock)
            p_hdr.status == Wire.kXR_ok || bringup_error("kXR_protocol", p_hdr)
            return Wire.decode_protocol(p_body)
        end
        if want_tls || (proto.flags & Wire.kXR_tlsDemands) != 0
            if (proto.flags & Wire.kXR_haveTLS) == 0
                error("the data path to $(conn.host):$(conn.port) cannot be encrypted")
            end
            creds = x509 ? discover_x509(; cert, key) : nothing
            sock = try
                guard_bringup(
                    sock, conn.host, conn.port, connect_timeout, "the TLS handshake"
                ) do
                    return tls_upgrade(sock, conn.host; insecure_tls, creds, cafile)
                end
            catch err
                err isa BringUpTimeout && rethrow()
                throw(TLSHandshakeFailed(conn.host, conn.port, creds !== nothing, err))
            end
        end

        guard_bringup(sock, conn.host, conn.port, connect_timeout, "the bind reply") do
            write(sock, Wire.encode(Wire.BindRequest(conn.sessid), UInt16(2)))
            b_hdr, b_body = read_frame(sock)
            b_hdr.status == Wire.kXR_ok || bringup_error("kXR_bind", b_hdr)
            return Wire.decode_bind(b_body)
        end
    catch
        try
            close(sock)
        catch
            # already gone, which is the state we wanted
        end
        rethrow()
    end

    path = DataPath(sock, pathid, ReentrantLock(), Ref{Union{Task,Nothing}}(nothing))
    lock(conn.plock) do
        haskey(conn.datapaths, pathid) &&
            error("the server reused path id $pathid, which is already bound")
        return conn.datapaths[pathid] = path
    end
    # Started only once the path is registered: a frame that arrives the
    # instant the socket is readable must find a table to be routed through.
    path.reader[] = errormonitor(Threads.@spawn data_path_loop(conn, path))
    probe_substreams!(conn)
    return pathid
end

"""
    probe_substreams!(conn)

Ask the server — once per session, after the first successful bind — whether
its bound paths speak whole request frames (`kXR_Qconfig brix.substreams`,
answered `…=rw` by a BriX server built that way). A stock server echoes an
unknown key back verbatim, which reads as "no", and any error reads as "no"
too: the split framing is the protocol default, so only an explicit yes moves
traffic off it. [`transmit`](@ref) consults the verdict on every routed
request.
"""
function probe_substreams!(conn::Connection)
    conn.substreams_rw === nothing || return nothing
    conn.substreams_rw = false
    try
        hdr, body = roundtrip(
            conn, Wire.QueryRequest(Wire.kXR_Qconfig, "brix.substreams")
        )
        if hdr.status == Wire.kXR_ok
            conn.substreams_rw = occursin("=rw", String(copy(body)))
        end
    catch
        # A probe that failed outright changes nothing: the default framing
        # was going to be used anyway, and the bind that preceded it stands.
    end
    return nothing
end

"The path ids bound to `conn`, in no particular order."
data_paths(conn::Connection) = lock(conn.plock) do
    return sort!(collect(keys(conn.datapaths)))
end

"""
    has_data_path(conn, pathid) -> Bool

Whether `pathid` names a data path this connection can route over. A caller
that remembers an id across a reconnect asks this before using it: the id
belonged to the session that is gone, and sending it to the new one would
name a path the server never bound.
"""
function has_data_path(conn::Connection, pathid::Integer)
    pathid == 0 && return false
    return lock(conn.plock) do
        return haskey(conn.datapaths, UInt8(pathid))
    end
end

"""
Read frames off a bound data path. They carry the control link's streamids
and go into the same `pending` table, so a `kXR_read` answered here is
indistinguishable to the caller from one answered on the control link.

A data path that dies takes only the requests routed over it: the control
link may be perfectly healthy, and failing an unrelated `kXR_stat` because a
transfer's second socket was reset would be inventing an error.
"""
function data_path_loop(conn::Connection, path::DataPath)
    try
        frame_loop(conn, path.sock)
    catch err
        fail_routed!(conn, path, err)
    end
    return nothing
end

"""
    connect(url::AbstractString; kwargs...) -> Connection

Convenience: parse `root://[user@]host[:port]` ([`parse_root_url`](@ref),
default port 1094) and connect; a `roots://` scheme forces TLS. A user named
in the URL logs in as that account unless a `username` keyword says otherwise.
"""
function connect(url::AbstractString; kwargs...)
    u = parse_root_url(url)
    opts = Dict{Symbol,Any}(kwargs)
    get!(opts, :want_tls, u.scheme == "roots")
    isempty(u.username) || get!(opts, :username, u.username)
    return connect(u.host, u.port; opts...)
end

function bringup_error(stage::String, hdr::Wire.ResponseHeader)
    return error("$stage failed with status $(hdr.status)")
end

"""
Read exactly `n` bytes (blocking; `EOFError` on a short read). Uses
`unsafe_read`, the one input primitive both `TCPSocket` and
`OpenSSL.SSLStream` implement natively.
"""
function readn(sock::IO, n::Int)
    buf = Vector{UInt8}(undef, n)
    n == 0 && return buf
    GC.@preserve buf unsafe_read(sock, pointer(buf), UInt(n))
    return buf
end

"""
Read one complete response frame (blocking). A `dlen` beyond
[`Wire.DLEN_MAX`](@ref) is refused rather than allocated: the header is
untrusted input, and no legitimate reply body is that large (chunked replies
arrive as several `kXR_oksofar` frames).
"""
function read_frame(sock::IO)
    hdr = Wire.decode_header(readn(sock, Wire.RESPONSE_HDRLEN))
    if hdr.dlen > Wire.DLEN_MAX
        error("response body of $(hdr.dlen) bytes exceeds the $(Wire.DLEN_MAX)-byte cap")
    end
    body = hdr.dlen > 0 ? readn(sock, Int(hdr.dlen)) : UInt8[]
    return hdr, body
end

"""
Upgrade a live socket to TLS (client mode) with SNI/hostname checking.
Chain verification is on unless `insecure_tls` (self-signed test servers).

`creds` presents an X.509 client certificate during the handshake — the
identity an XRootD 5 server maps to a user when it authenticates over TLS.
Presenting one is harmless when the server does not ask, so the default is
whatever [`discover_x509`](@ref) finds. `cafile` names an extra CA bundle or
hashed directory to trust.
"""
function tls_upgrade(
    sock::IO,
    host::String;
    insecure_tls::Bool=false,
    creds::Union{X509Credentials,Nothing}=nothing,
    cafile::Union{AbstractString,Nothing}=nothing,
)
    ctx = client_ssl_context(; insecure_tls, creds)
    cafile === nothing || OpenSSL.ca_chain!(ctx, String(cafile))
    ssl = OpenSSL.SSLStream(ctx, sock)
    OpenSSL.hostname!(ssl, host)
    OpenSSL.connect(ssl; require_ssl_verification=(!insecure_tls))
    return ssl
end

# (authentication mechanisms live in auth.jl / sss.jl; signing in sigver.jl)

# ---- reader task ----

function reader_loop(conn::Connection)
    try
        frame_loop(conn, conn.sock)
    catch err
        fail_pending!(conn, err)
    end
    return nothing
end

"""
Parse frames off `sock` and route each to the streamid that is waiting for it.
Shared by the control link and every bound data path ([`DataPath`](@ref)),
because a reply is the same frame whichever link carries it — only what a
*failure* of the link means differs, which is why the two callers own the
`catch` and this loop has none.
"""
function frame_loop(conn::Connection, sock::IO)
    while true
        hdr, body = read_frame(sock)
        if hdr.status == Wire.kXR_attn
            handle_attn(conn, body)
        elseif hdr.status == Wire.kXR_status
            # Paged-io frames carry page data BEYOND hdr.dlen: the 24-byte
            # status body announces pgdlen trailing bytes (ops_file_pg.c).
            if length(body) >= Wire.STATUS_BODY_LEN
                pgdlen = Wire.get_u32(body, 13)
                pgdlen > 0 && append!(body, readn(sock, Int(pgdlen)))
            end
            deliver(conn, hdr, body)
        else
            deliver(conn, hdr, body)
        end
    end
end

"""
Handle an unsolicited `kXR_attn` frame. `kXR_asynresp` carries a deferred
response — body layout `actnum[4] + reserved[4] + ServerResponseHdr[8] +
data` — which is re-routed to its original streamid. `kXR_asyncms` server
notices are logged.
"""
function handle_attn(conn::Connection, body::Vector{UInt8})
    length(body) < 4 && return nothing
    actnum = Wire.get_u32(body, 1)
    if actnum == Wire.kXR_asynresp && length(body) >= 16
        inner = Wire.decode_header(view(body, 9:16))
        deliver(conn, inner, body[17:end])
    elseif actnum == Wire.kXR_asyncms
        @debug "server notice" message = String(body[9:end])
    end
    return nothing
end

function deliver(conn::Connection, hdr::Wire.ResponseHeader, body::Vector{UInt8})
    ch = lock(conn.plock) do
        return get(conn.pending, hdr.streamid, nothing)
    end
    ch === nothing || put!(ch, (hdr, body))
    return nothing
end

"""
A `kXR_error` frame the client synthesizes locally (transport loss, a stall
cutoff, a refused reply) so callers see one failure shape whether the error
came from the server or from us.
"""
function synthetic_error(sid::UInt16, msg::AbstractString)
    body = vcat(zeros(UInt8, 4), Vector{UInt8}(codeunits(msg)))
    return (Wire.ResponseHeader(sid, Wire.kXR_error, UInt32(length(body))), body)
end

"Fail every in-flight request with a synthetic kXR_error frame."
function fail_pending!(conn::Connection, err)
    conn.closed = true
    msg = "connection to $(conn.host):$(conn.port) lost ($(typeof(err)))"
    lock(conn.plock) do
        for (sid, ch) in conn.pending
            put!(ch, synthetic_error(sid, msg))
        end
    end
    return nothing
end

"""
Retire a data path that died: drop it, and fail only the requests that were
routed over it. The session itself survives — the control link is a separate
socket, and everything not naming this path is still answerable on it.

A caller holding the path id learns of the loss from
[`has_data_path`](@ref) and can fall back to the control link, which is what
losing the *second* socket should cost.
"""
function fail_routed!(conn::Connection, path::DataPath, err)
    msg = "data path $(path.pathid) to $(conn.host):$(conn.port) lost ($(typeof(err)))"
    lock(conn.plock) do
        get(conn.datapaths, path.pathid, nothing) === path &&
            delete!(conn.datapaths, path.pathid)
        for (sid, pid) in conn.routed
            pid == path.pathid || continue
            ch = get(conn.pending, sid, nothing)
            ch === nothing || put!(ch, synthetic_error(sid, msg))
        end
    end
    try
        close(path.sock)
    catch
        # it is already gone; that is why we are here
    end
    return nothing
end

# ---- request multiplexing ----

function register!(conn::Connection)
    lock(conn.plock) do
        sid = conn.nextsid
        while sid == 0x0000 || haskey(conn.pending, sid)
            sid += UInt16(1)
        end
        conn.nextsid = sid + UInt16(1)
        ch = Channel{Frame}(Inf)
        conn.pending[sid] = ch
        return sid, ch
    end
end

function unregister!(conn::Connection, sid::UInt16)
    lock(conn.plock) do
        return delete!(conn.pending, sid)
    end
    return nothing
end

"""
    SendTimeout(host, port, timeout_ms)

A write that never drained. The peer is up and its window is shut: it stopped
reading, or the path to it stopped delivering, and once both socket buffers
fill the sending `write` blocks with nothing to time it out — the caller never
reaches the `take!` that [`arm_stall`](@ref) unblocks, because it never got the
request out. Thrown so the retry lanes see a transport loss and reconnect.
"""
struct SendTimeout <: Exception
    host::String
    port::Int
    timeout_ms::Int
end

function Base.showerror(io::IO, e::SendTimeout)
    print(io, "send to $(e.host):$(e.port) exceeded the $(e.timeout_ms) ms stall deadline")
    return nothing
end

"""
    guard_send(f, conn, sock) -> f()

Run one blocking write to `sock` under the session's stall deadline
([`stall_deadline_ms`](@ref)), reporting a write that never completed as a
[`SendTimeout`](@ref).

The guard covers taking the write lock as well as the write itself: a link
jammed by one stalled sender would otherwise park every other Task queued
behind it on a lock no deadline watches.
"""
function guard_send(f::Function, conn::Connection, sock::IO)
    ms = conn.stall_deadline_ms
    mkerr() = SendTimeout(conn.host, conn.port, ms)
    return guard_io(f, sock, ms / 1000, mkerr)
end

function send(conn::Connection, frame::Vector{UInt8})
    guard_send(conn, conn.sock) do
        return lock(conn.wlock) do
            return write(conn.sock, frame)
        end
    end
    conn.last_activity = time()
    return nothing
end

"""
Arm the whole-operation stall deadline for the request on `sid`: when the
cutoff elapses before the terminal frame arrives, a synthetic timeout error is
delivered to `ch` and the waiting caller unblocks. Returns the `Timer` (close
it when the operation ends) or `nothing` when the deadline is disabled.

The budget covers *every* frame of one logical operation, which is the point:
a server that splits a read into many small frames cannot stay under a
per-frame timeout indefinitely.
"""
function arm_stall(
    conn::Connection, sid::UInt16, ch::Channel{Frame}; ms::Integer=conn.stall_deadline_ms
)
    ms > 0 || return nothing
    return Timer(ms / 1000) do _
        return put!(
            ch, synthetic_error(sid, "operation exceeded the $(ms) ms stall deadline")
        )
    end
end

"""
    roundtrip(conn, req::Wire.Request; maxbytes = 0) -> (Wire.ResponseHeader, Vector{UInt8})

Send `req` and block for its terminal response. `kXR_oksofar` chunks are
accumulated into one body; `kXR_wait` sleeps the advised seconds and
re-sends. Redirect and error statuses are returned to the caller undecoded.
Safe for concurrent use from many Tasks — each call gets its own streamid.

`maxbytes` bounds the accumulated body (0 = unbounded); a reply that would
grow past it is refused with a synthetic error instead of being buffered, so
an over-answering server cannot drive the client's heap. Reads pass the
length they asked for — see [`Wire.readv_reply_cap`](@ref) and
[`Wire.pgread_reply_cap`](@ref) for the vector and paged forms.

When `conn.stall_deadline_ms` is set the whole call is bounded by that
absolute deadline ([`arm_stall`](@ref)); repeated `kXR_wait` answers are
bounded separately by [`max_wait_ms`](@ref).

A request naming a bound data path ([`bind_data_path!`](@ref)) puts its header
on the control link and its bulk bytes on that path; the reply arrives on
whichever link the server chooses and is matched by streamid either way. On a
session whose server answered the substreams probe ([`probe_substreams!`](@ref))
the whole frame — header included, `pathid` zeroed — goes down the path
instead, which spares the control link even the headers of a bulk transfer.
"""
function roundtrip(conn::Connection, req::Wire.Request; maxbytes::Integer=0)
    conn.closed && return synthetic_error(0x0000, "connection already closed")
    pid = Wire.pathid(req)
    path = pid == 0x00 ? nothing : lock(conn.plock) do
        return get(conn.datapaths, pid, nothing)
    end
    if pid != 0x00 && path === nothing
        # Not an assertion failure: a path is lost when its socket dies or the
        # session is replaced by a redirect, so a caller can hold a stale id
        # through no fault of its own.
        return synthetic_error(0x0000, "no data path $pid is bound to this session")
    end
    sid, ch = register!(conn)
    # Whole-frame mode re-encodes without the pathid: the request IS on the
    # path it named, and a pathid in a frame already riding that path would
    # ask the server to route the data a second time.
    whole = path !== nothing && conn.substreams_rw === true
    frame = Wire.encode(whole ? Wire.without_pathid(req) : req, sid)
    acc = UInt8[]
    cap = Int(maxbytes)
    stall = nothing
    waited_ms = max_wait_ms()
    wait_budget = waited_ms / 1000
    waited = 0.0
    path === nothing || lock(conn.plock) do
        return conn.routed[sid] = pid
    end
    try
        transmit(conn, frame, req, path; whole)
        stall = arm_stall(conn, sid, ch)
        while true
            hdr, body = take!(ch)
            if hdr.status == Wire.kXR_oksofar || hdr.status == Wire.kXR_status
                # kXR_status is paged I/O: accumulate whole (status body +
                # pages) frames until the Final one; the caller walks the
                # self-describing frames. kXR_oksofar chunks concatenate.
                over_cap(cap, length(acc), length(body)) &&
                    return synthetic_error(sid, overrun_message(req, cap))
                resptype = length(body) >= 8 ? body[8] : Wire.kXR_FinalResult
                append!(acc, body)
                hdr.status == Wire.kXR_status &&
                    resptype != Wire.kXR_PartialResult &&
                    return hdr, acc
            elseif hdr.status == Wire.kXR_wait
                # An explicit, in-band "retry in N seconds" is the server
                # declaring a delay, not dribbling: restart the budget so the
                # advised wait cannot itself trip the cutoff. The delays are
                # still summed — an endless stream of waits is a stall too.
                secs = Wire.wait_seconds(body)
                waited += secs
                waited > wait_budget && return synthetic_error(
                    sid,
                    "operation parked for more than the $(waited_ms) ms kXR_wait budget",
                )
                sleep(secs)
                transmit(conn, frame, req, path; whole)
                stall === nothing || close(stall)
                stall = arm_stall(conn, sid, ch)
            elseif hdr.status == Wire.kXR_waitresp
                # "The answer is coming later": the server has accepted the
                # request and will deliver the reply unsolicited, as a
                # kXR_attn(kXR_asynresp) on this same streamid (libxrdc
                # aio_io.c). Nothing is re-sent — a deferral is not a retry —
                # but the stall deadline is re-armed for the advised delay,
                # since otherwise the wait the server asked for would itself
                # look like a stall. A TPC rendezvous is deferred this way.
                secs = Wire.wait_seconds(body; cap=WAITRESP_CAP_S)
                waited += secs
                waited > wait_budget && return synthetic_error(
                    sid,
                    "deferred reply did not arrive within the $(waited_ms) ms " *
                    "kXR_wait budget",
                )
                stall === nothing || close(stall)
                deadline_ms = conn.stall_deadline_ms
                stall = if deadline_ms > 0
                    arm_stall(
                        conn,
                        sid,
                        ch;
                        ms=max(deadline_ms, round(Int, secs * 1000) + WAITRESP_GRACE_MS),
                    )
                else
                    nothing
                end
            elseif hdr.status == Wire.kXR_ok
                # The cap applies to data-bearing statuses only: an error
                # body is a message, and truncating one would hide the very
                # failure the caller needs to see.
                over_cap(cap, length(acc), length(body)) &&
                    return synthetic_error(sid, overrun_message(req, cap))
                isempty(acc) || (append!(acc, body); body=acc)
                return hdr, body
            else
                return hdr, body
            end
        end
    finally
        stall === nothing || close(stall)
        unregister!(conn, sid)
        path === nothing || lock(conn.plock) do
            return delete!(conn.routed, sid)
        end
    end
end

"""
Put one request on the wire: the signature prefix if the session signs, the
frame itself on the control link, and — for a request bound to a data path —
its [`Wire.path_data`](@ref) on that path's socket. With `whole` set (a
session whose server answered the substreams probe) the signature and frame
go down the path instead and the control link carries nothing at all.

The two writes take two different locks because they are two different links;
the path's own lock is what keeps concurrent writers on one path from
interleaving their data, which the server, reading `dlen` bytes in order,
would have no way to untangle.
"""
function transmit(
    conn::Connection, frame::Vector{UInt8}, req::Wire.Request, path; whole::Bool=false
)
    # High-security servers require a kXR_sigver prefix on mutating ops;
    # it must share the write lock so it stays adjacent to its request.
    sig = sign_frame(conn, frame)
    if whole
        guard_send(conn, path.sock) do
            return lock(path.wlock) do
                sig === nothing || write(path.sock, sig)
                return write(path.sock, frame)
            end
        end
        conn.last_activity = time()
        return nothing
    end
    if sig === nothing
        send(conn, frame)
    else
        guard_send(conn, conn.sock) do
            return lock(conn.wlock) do
                write(conn.sock, sig)
                return write(conn.sock, frame)
            end
        end
        conn.last_activity = time()
    end
    path === nothing && return nothing
    data = Wire.path_data(req)
    isempty(data) || guard_send(conn, path.sock) do
        return lock(path.wlock) do
            return write(path.sock, data)
        end
    end
    return nothing
end

"True when `n` more bytes would push `have` past `cap` (`cap ≤ 0` = no cap)."
over_cap(cap::Int, have::Int, n::Int) = cap > 0 && have + n > cap

function overrun_message(req::Wire.Request, cap::Int)
    return "$(Wire.request_name(Wire.requestid(req))) reply exceeds the " *
           "$(cap)-byte cap for this request"
end

function Base.close(conn::Connection)
    conn.closed = true   # signals the keepalive task's loop to exit
    # The bound paths go first: they belong to this session, and a socket left
    # open after the control link is gone is one the server holds until its own
    # idle timeout expires.
    paths = lock(conn.plock) do
        ps = collect(values(conn.datapaths))
        empty!(conn.datapaths)
        return ps
    end
    for p in paths
        try
            close(p.sock)
        catch
            # already gone, which is the state we wanted
        end
    end
    isopen(conn.sock) && close(conn.sock)
    return nothing
end

Base.isopen(conn::Connection) = !conn.closed && isopen(conn.sock)
