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
        authenticate(sock, username, login.sec)
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
    )
    conn.reader = errormonitor(Threads.@spawn reader_loop(conn))
    return conn
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

"Read one complete response frame (blocking)."
function read_frame(sock::IO)
    hdr = Wire.decode_header(readn(sock, Wire.RESPONSE_HDRLEN))
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

"""
One `kXR_auth` round for the `unix` protocol: credtype `"unix"`, payload
`"unix\\0" * username`. The server either accepts (`kXR_ok`) or the
mechanism is unavailable — multi-round mechanisms (ztn, sss) are plan 04.
"""
function authenticate(sock::IO, username::AbstractString, sec::String)
    occursin("unix", sec) || error(
        "server requires authentication ($(sec)); only unix is supported until plan 04"
    )
    cred = vcat(Vector{UInt8}(codeunits("unix\0")), Vector{UInt8}(codeunits(username)))
    write(sock, Wire.encode(Wire.AuthRequest("unix", cred), UInt16(3)))
    a_hdr, a_body = read_frame(sock)
    if a_hdr.status != Wire.kXR_ok
        msg = a_hdr.status == Wire.kXR_error ? Wire.decode_error(a_body).message : ""
        error("unix authentication failed (status $(a_hdr.status)): $msg")
    end
    return nothing
end

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

"Fail every in-flight request with a synthetic kXR_error frame."
function fail_pending!(conn::Connection, err)
    conn.closed = true
    msg = "connection to $(conn.host):$(conn.port) lost ($(typeof(err)))"
    body = vcat(zeros(UInt8, 4), Vector{UInt8}(codeunits(msg)))
    lock(conn.plock) do
        for (sid, ch) in conn.pending
            put!(ch, (Wire.ResponseHeader(sid, Wire.kXR_error, UInt32(length(body))), body))
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
    return nothing
end

"""
    roundtrip(conn, req::Wire.Request) -> (Wire.ResponseHeader, Vector{UInt8})

Send `req` and block for its terminal response. `kXR_oksofar` chunks are
accumulated into one body; `kXR_wait` sleeps the advised seconds and
re-sends. Redirect and error statuses are returned to the caller undecoded.
Safe for concurrent use from many Tasks — each call gets its own streamid.
"""
function roundtrip(conn::Connection, req::Wire.Request)
    if conn.closed
        body = vcat(zeros(UInt8, 4), Vector{UInt8}(codeunits("connection already closed")))
        return Wire.ResponseHeader(0x0000, Wire.kXR_error, UInt32(length(body))), body
    end
    sid, ch = register!(conn)
    frame = Wire.encode(req, sid)
    acc = UInt8[]
    try
        send(conn, frame)
        while true
            hdr, body = take!(ch)
            if hdr.status == Wire.kXR_oksofar
                append!(acc, body)
            elseif hdr.status == Wire.kXR_status
                # Paged-io: accumulate whole (status body + pages) frames until
                # the Final one; the caller walks the self-describing frames.
                resptype = length(body) >= 8 ? body[8] : Wire.kXR_FinalResult
                append!(acc, body)
                resptype == Wire.kXR_PartialResult || return hdr, acc
            elseif hdr.status == Wire.kXR_wait
                sleep(Wire.wait_seconds(body))
                send(conn, frame)
            else
                if hdr.status == Wire.kXR_ok && !isempty(acc)
                    append!(acc, body)
                    body = acc
                end
                return hdr, body
            end
        end
    finally
        unregister!(conn, sid)
    end
end

function Base.close(conn::Connection)
    conn.closed = true
    isopen(conn.sock) && close(conn.sock)
    return nothing
end

Base.isopen(conn::Connection) = !conn.closed && isopen(conn.sock)
