# Connection lifecycle: bring-up, streamid-multiplexed roundtrips, teardown.

"One response frame as delivered to a waiting request."
const Frame = Tuple{Wire.ResponseHeader,Vector{UInt8}}

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
    signing_key::Union{Vector{UInt8},Nothing}
    sig_seqno::UInt64
    last_activity::Float64                   # time() of the last frame sent
    keepalive::Union{Task,Nothing}
    stall_deadline_ms::Int                   # whole-operation cutoff (0 = disabled)
end

"""
Default slow-drip completion deadline: disabled, matching libxrdc
(`brix_tmo_stall_ms`). A per-frame idle timeout is not a deadline — a peer
that dribbles one byte per timeout window keeps a read alive forever — so
`XRDC_STALL_DEADLINE_MS` arms an absolute cutoff for the whole logical
operation instead.
"""
const DEFAULT_STALL_DEADLINE_MS = 0

"Resolve `XRDC_STALL_DEADLINE_MS` (milliseconds; 0 or unset = disabled)."
function stall_deadline_ms()
    v = get(ENV, "XRDC_STALL_DEADLINE_MS", "")
    isempty(v) && return DEFAULT_STALL_DEADLINE_MS
    n = tryparse(Int, v)
    return n === nothing || n < 0 ? DEFAULT_STALL_DEADLINE_MS : n
end

"""
    connect(host, port; username = ENV["USER"], want_tls = false,
            insecure_tls = false) -> Connection

Establish a session: TCP connect, then the 44-byte pipelined bring-up
segment (20-byte handshake + `kXR_protocol`, exactly as libxrdc `conn.c`
sends it); when the client requires TLS (`want_tls`, i.e. `roots://`) or
the server demands it (`kXR_gotoTLS`/`kXR_tlsLogin` in the protocol reply),
the socket upgrades to TLS before `kXR_login` (libxrdc `tls.c`). The login
reply's security trailer then drives authentication
([`authenticate`](@ref)).

`insecure_tls` skips certificate-chain verification (test servers with
self-signed certificates only — never for production data).
"""
function connect(
    host::AbstractString,
    port::Integer;
    username::AbstractString=get(ENV, "USER", "nobody"),
    want_tls::Bool=false,
    insecure_tls::Bool=false,
    token::Union{AbstractString,Nothing}=nothing,
    keytab::Union{AbstractString,Nothing}=nothing,
    keepalive_s::Real=0,
)
    sock::IO = Sockets.connect(String(host), port)

    # Bring-up is synchronous: the reader Task starts only once the session
    # is authenticated, so plain blocking reads are safe here.
    flags = if want_tls
        (Wire.kXR_secreqs | Wire.kXR_ableTLS | Wire.kXR_wantTLS)
    else
        (Wire.kXR_secreqs | Wire.kXR_ableTLS)
    end
    write(sock, vcat(Wire.HANDSHAKE, Wire.encode(Wire.ProtocolRequest(; flags), UInt16(1))))
    hs_hdr, _ = read_frame(sock)
    hs_hdr.status == Wire.kXR_ok || bringup_error("handshake", hs_hdr)
    p_hdr, p_body = read_frame(sock)
    p_hdr.status == Wire.kXR_ok || bringup_error("kXR_protocol", p_hdr)
    proto = Wire.decode_protocol(p_body)

    server_demands = (proto.flags & (Wire.kXR_gotoTLS | Wire.kXR_tlsLogin)) != 0
    if want_tls || server_demands
        if (proto.flags & Wire.kXR_haveTLS) == 0
            error(
                "TLS required but the server at $host:$port does not offer it " *
                "(protocol flags 0x$(string(proto.flags; base=16)))",
            )
        end
        sock = tls_upgrade(sock, String(host); insecure_tls)
    end

    write(sock, Wire.encode(Wire.LoginRequest(username), UInt16(2)))
    l_hdr, l_body = read_frame(sock)
    l_hdr.status == Wire.kXR_ok || bringup_error("kXR_login", l_hdr)
    login = Wire.decode_login(l_body)

    if !isempty(login.sec)
        authenticate(sock, username, login.sec; token, keytab)
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
        0,           # sec_level: no signing until negotiated
        nothing,     # signing_key
        UInt64(0),   # sig_seqno
        time(),      # last_activity
        nothing,     # keepalive timer
        stall_deadline_ms(),
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
    connect(url::AbstractString; kwargs...) -> Connection

Convenience: parse `root://host[:port]` (default port 1094) and connect;
a `roots://` scheme forces TLS.
"""
function connect(url::AbstractString; kwargs...)
    m = match(r"^(roots?)://([^/:@]+)(?::(\d+))?", url)
    m === nothing && throw(ArgumentError("not a root:// URL: $(repr(url))"))
    scheme = String(something(m.captures[1]))
    host = String(something(m.captures[2]))
    portstr = m.captures[3]
    port = portstr === nothing ? 1094 : parse(Int, portstr)
    return connect(host, port; want_tls=(scheme == "roots"), kwargs...)
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
"""
function tls_upgrade(sock::IO, host::String; insecure_tls::Bool=false)
    ssl = OpenSSL.SSLStream(sock)
    OpenSSL.hostname!(ssl, host)
    OpenSSL.connect(ssl; require_ssl_verification=(!insecure_tls))
    return ssl
end

# (authentication mechanisms live in auth.jl / sss.jl; signing in sigver.jl)

# ---- reader task ----

function reader_loop(conn::Connection)
    try
        while true
            hdr, body = read_frame(conn.sock)
            if hdr.status == Wire.kXR_attn
                handle_attn(conn, body)
            elseif hdr.status == Wire.kXR_status
                # Paged-io frames carry page data BEYOND hdr.dlen: the 24-byte
                # status body announces pgdlen trailing bytes (ops_file_pg.c).
                if length(body) >= Wire.STATUS_BODY_LEN
                    pgdlen = Wire.get_u32(body, 13)
                    pgdlen > 0 && append!(body, readn(conn.sock, Int(pgdlen)))
                end
                deliver(conn, hdr, body)
            else
                deliver(conn, hdr, body)
            end
        end
    catch err
        fail_pending!(conn, err)
    end
    return nothing
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

function send(conn::Connection, frame::Vector{UInt8})
    lock(conn.wlock) do
        return write(conn.sock, frame)
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
function arm_stall(conn::Connection, sid::UInt16, ch::Channel{Frame})
    ms = conn.stall_deadline_ms
    ms > 0 || return nothing
    return Timer(ms / 1000) do _
        put!(ch, synthetic_error(sid, "operation exceeded the $(ms) ms stall deadline"))
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
absolute deadline ([`arm_stall`](@ref)).
"""
function roundtrip(conn::Connection, req::Wire.Request; maxbytes::Integer=0)
    conn.closed && return synthetic_error(0x0000, "connection already closed")
    sid, ch = register!(conn)
    frame = Wire.encode(req, sid)
    acc = UInt8[]
    cap = Int(maxbytes)
    stall = nothing
    try
        # High-security servers require a kXR_sigver prefix on mutating ops;
        # it must share the write lock so it stays adjacent to its request.
        sig = sign_frame(conn, frame)
        if sig === nothing
            send(conn, frame)
        else
            lock(conn.wlock) do
                write(conn.sock, sig)
                return write(conn.sock, frame)
            end
        end
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
                # advised wait cannot itself trip the cutoff.
                sleep(Wire.wait_seconds(body))
                send(conn, frame)
                stall === nothing || close(stall)
                stall = arm_stall(conn, sid, ch)
            elseif hdr.status == Wire.kXR_ok
                # The cap applies to data-bearing statuses only: an error
                # body is a message, and truncating one would hide the very
                # failure the caller needs to see.
                over_cap(cap, length(acc), length(body)) &&
                    return synthetic_error(sid, overrun_message(req, cap))
                isempty(acc) || (append!(acc, body); body = acc)
                return hdr, body
            else
                return hdr, body
            end
        end
    finally
        stall === nothing || close(stall)
        unregister!(conn, sid)
    end
end

"True when `n` more bytes would push `have` past `cap` (`cap ≤ 0` = no cap)."
over_cap(cap::Int, have::Int, n::Int) = cap > 0 && have + n > cap

function overrun_message(req::Wire.Request, cap::Int)
    return "$(Wire.request_name(Wire.requestid(req))) reply exceeds the " *
           "$(cap)-byte cap for this request"
end

function Base.close(conn::Connection)
    conn.closed = true   # signals the keepalive task's loop to exit
    isopen(conn.sock) && close(conn.sock)
    return nothing
end

Base.isopen(conn::Connection) = !conn.closed && isopen(conn.sock)
