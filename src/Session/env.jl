# The environment the C++ client reads. A process already configured for
# XrdCl — a grid job, a site login script, a container image built for the
# reference client — should not need a second configuration for this one, so
# the `XRD_*` variables are honoured under their own names and with their own
# meanings. Where this client has a knob of its own (`XRDC_*`, inherited from
# libxrdc) that one wins: it is the more specific of the two, and a user who
# set it meant this client.

"The vocabulary of an environment switch that is on. Anything else is off."
const ENV_TRUE = ("1", "true", "yes", "on")

"""
    env_flag(name, default=false) -> Bool

Read a boolean setting. Unset or empty leaves `default` standing; anything
else is compared against [`ENV_TRUE`](@ref), so `XRD_REQUIRETLS=0` turns a
setting off as clearly as leaving it out.
"""
function env_flag(name::AbstractString, default::Bool=false)
    v = strip(get(ENV, name, ""))
    isempty(v) && return default
    return lowercase(v) in ENV_TRUE
end

"""
    env_number(name, default) -> Float64

Read a non-negative numeric setting. A value that does not parse, or that is
negative, leaves `default` standing: a typo in a site profile should not fail
every connection the job makes, and a client that silently uses the default is
the same client an unset variable would have produced.
"""
function env_number(name::AbstractString, default::Real)
    v = strip(get(ENV, name, ""))
    isempty(v) && return Float64(default)
    n = tryparse(Float64, v)
    return (n === nothing || n < 0) ? Float64(default) : n
end

"[`env_number`](@ref) for a count rather than a duration."
function env_int(name::AbstractString, default::Integer)
    v = strip(get(ENV, name, ""))
    isempty(v) && return Int(default)
    n = tryparse(Int, v)
    return (n === nothing || n < 0) ? Int(default) : n
end

"""
    xrd_username() -> String

The account asserted at `kXR_login`: `\$XRD_USERNAME`, else `\$USER`, else
`\$LOGNAME`, else `"nobody"`. Never empty — a container with no passwd entry
still has to log in as somebody, and an empty name is not a login the server
will accept.
"""
function xrd_username()
    for var in ("XRD_USERNAME", "USER", "LOGNAME")
        v = strip(get(ENV, var, ""))
        isempty(v) || return String(v)
    end
    return "nobody"
end

"""
    env_cafile() -> Union{String,Nothing}

The CA bundle named by `\$X509_CERT_FILE`, else `\$SSL_CERT_FILE`. This is the
*bundle*; `\$X509_CERT_DIR` names the hashed directory and is picked up
separately by [`x509_ca_path`](@ref). A path that does not exist is ignored rather
than passed to OpenSSL, which would fail the handshake over a stale profile.
"""
function env_cafile()
    for var in ("X509_CERT_FILE", "SSL_CERT_FILE")
        p = strip(get(ENV, var, ""))
        (isempty(p) || !isfile(p)) && continue
        return String(p)
    end
    return nothing
end

"""
How long a TCP connection may take, in seconds (`\$XRD_CONNECTIONWINDOW`).
XrdCl's default is 120; this client's is 30, because a connection that has not
been accepted in 30 seconds is a host that is down far more often than a host
that is slow, and the caller can raise it. Zero waits as long as the operating
system does.
"""
const DEFAULT_CONNECTION_WINDOW_S = 30

connection_window_s() = env_number("XRD_CONNECTIONWINDOW", DEFAULT_CONNECTION_WINDOW_S)

"""
Seconds a session may sit idle before a `kXR_ping` keeps it alive
(`\$XRD_STREAMTIMEOUT`). Zero — the default — means no keepalive at all,
which is what a short-lived client wants; a long-lived handle over a firewall
that drops idle NAT entries wants it set.
"""
stream_timeout_s() = env_number("XRD_STREAMTIMEOUT", 0)

"""
Seconds a socket may sit idle before the kernel starts probing the peer
(`\$XRDC_TCP_KEEPALIVE_S`, `0` leaves the socket at the system default).

This is the layer below [`stream_timeout_s`](@ref), and it answers a failure
the protocol keepalive cannot: a connection whose path has gone — an expired
NAT entry, a firewall rule changed under a long transfer, a route withdrawn —
is not closed, it is *silent*. Nothing arrives, nothing errors, and a read
waits forever. Kernel probes turn that silence into an error the reader Task
can act on.
"""
const DEFAULT_TCP_KEEPALIVE_S = 60

tcp_keepalive_s() = env_number("XRDC_TCP_KEEPALIVE_S", DEFAULT_TCP_KEEPALIVE_S)

"""
How many `kXR_redirect` hops to follow before giving up
(`\$XRD_REDIRECTLIMIT`). The limit is what tells a federation that is sending
a client round in a circle from one that is merely deep.
"""
const DEFAULT_REDIRECT_LIMIT = 8

redirect_limit() = env_int("XRD_REDIRECTLIMIT", DEFAULT_REDIRECT_LIMIT)

"""
How many EXTRA `kXR_bind` data sub-streams a file opens beside the control
link. One — the default — matches the Go (go-hep), Rust and Python clients: a
single data path carries the file's bulk reads and writes while the control
link stays free for headers and other requests. Zero keeps everything on the
one link, which is all a lone transfer on an idle session ever needed.
"""
const DEFAULT_DATA_STREAMS = 1

"""
    data_streams() -> Int

The number of extra data sub-streams a newly opened [`File`](@ref) binds by
default. `\$XRDC_DATA_STREAMS` — this client's own knob — counts the extra
links directly. Failing that, XrdCl's `\$XRD_SUBSTREAMSPERCHANNEL` is honoured
for a process already configured for the reference client; it counts the
control link, so its N is our N-1 (its `2` is one extra here, its `1` is none).
An unparseable or missing value leaves [`DEFAULT_DATA_STREAMS`](@ref) standing;
a negative one is clamped to zero, because a typo in a site profile should
degrade to the default, never to an error on every open.
"""
function data_streams()
    v = strip(get(ENV, "XRDC_DATA_STREAMS", ""))
    if !isempty(v)
        n = tryparse(Int, v)
        return (n === nothing) ? DEFAULT_DATA_STREAMS : max(0, n)
    end
    w = strip(get(ENV, "XRD_SUBSTREAMSPERCHANNEL", ""))
    if !isempty(w)
        n = tryparse(Int, w)
        return (n === nothing) ? DEFAULT_DATA_STREAMS : max(0, n - 1)
    end
    return DEFAULT_DATA_STREAMS
end

"""
The authentication mechanisms this client implements, best first. `ztn`
(bearer token) before `sss` (shared secret) before `unix` (an assertion the
server may or may not believe). With no explicit order in play this is a
*filter*, not an order: the server's own preference list decides which of
these is tried first ([`authenticate`](@ref)).
"""
const DEFAULT_AUTH_ORDER = ("ztn", "sss", "unix")

"""
    env_auth_order() -> Union{Vector{String},Nothing}

The mechanism order `\$XrdSecPROTOCOL` — XrdCl's own variable, comma- or
space-separated — imposes, or `nothing` when it is unset. When set it both
orders and restricts: a mechanism it leaves out is not tried at all, which is
how a site pins a job to tokens even though the server would have accepted an
anonymous `unix` login. Names it lists that this client does not implement
are kept, ignored on the way past, and reported if nothing else works.
"""
function env_auth_order()
    v = get(ENV, "XrdSecPROTOCOL", "")
    names = [lowercase(strip(s)) for s in split(v, r"[,\s]+") if !isempty(strip(s))]
    return isempty(names) ? nothing : names
end

"""
    auth_order() -> Vector{String}

[`env_auth_order`](@ref) when `\$XrdSecPROTOCOL` says something, else the
built-in [`DEFAULT_AUTH_ORDER`](@ref).
"""
auth_order() = something(env_auth_order(), collect(String, DEFAULT_AUTH_ORDER))
