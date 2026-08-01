# A server that brings a connection up correctly, records every request it is
# sent, and answers each one with a body the test chose. Where the namespace
# server (fs_server.jl) judges the client by what a real filesystem ends up
# holding, this one judges it by what it *decoded*: the reply bodies here are
# the shapes a stock XrdXrootd emits for the informational surfaces — locate
# token lists, query text, oss space reports, extended stat lines — including
# the ones our own server never produces.
#
# It records the request frame and payload verbatim, so a test can also assert
# the other direction: the infotype, flag word and argument text the client put
# on the wire for the call it was asked to make.

using Sockets
using XRootD: Wire

"""
A scripted-reply server. `body` and `status` are what the *next* request is
answered with, whatever it asks; `frames`, `args` and `ops` record what
arrived, in order, so a test can read back the bytes the client sent.
"""
Base.@kwdef mutable struct InfoServer
    body::Vector{UInt8} = UInt8[]
    status::UInt16 = Wire.kXR_ok
    "Wrap the reply in a `kXR_attn`/`kXR_asynresp` frame (a deferred response)."
    async::Bool = false
    "Send an unsolicited `kXR_asyncms` notice ahead of the reply."
    notice::String = ""
    "Send a `kXR_attn` frame too short to act on, ahead of the reply."
    short_attn::Bool = false
    "Send a deferred reply addressed to a stream nobody is waiting on."
    stray_attn::Bool = false
    "Answer with `kXR_waitresp` for this many seconds before the real reply."
    waitresp_secs::Int = 0
    "Answer with the bytes this builds from the streamid (nothing = compose one)."
    scripted::Union{Nothing,Function} = nothing
    "Write replies in pieces this many bytes long (0 = one write), as a slow link would."
    fragment::Int = 0
    violations::Vector{String} = String[]
    logins::Vector{String} = String[]
    ops::Vector{UInt16} = UInt16[]
    frames::Vector{Vector{UInt8}} = Vector{UInt8}[]
    args::Vector{String} = String[]
end

flag!(s::InfoServer, msg::AbstractString) = push!(s.violations, String(msg))

"""
Forget the recorded history and put the envelope knobs back to plain replies;
the reply *body* is set per call by the tests.
"""
function info_reset!(s::InfoServer)
    s.async = false
    s.notice = ""
    s.short_attn = false
    s.stray_attn = false
    s.waitresp_secs = 0
    s.scripted = nothing
    s.fragment = 0
    empty!(s.violations)
    empty!(s.logins)
    empty!(s.ops)
    empty!(s.frames)
    empty!(s.args)
    return s
end

"Point the server at `text` (NUL-terminated, as a stock server sends it)."
function info_reply!(s::InfoServer, text::AbstractString; nul::Bool=true)
    s.status = Wire.kXR_ok
    s.body =
        nul ? vcat(Vector{UInt8}(codeunits(text)), 0x00) : Vector{UInt8}(codeunits(text))
    return s
end

"""
Point the server at a `kXR_error` reply: `errnum[4]` then the message. Servers
differ on the trailing NUL, so it is optional here too.
"""
function info_error!(
    s::InfoServer, errnum::Integer, message::AbstractString; nul::Bool=false
)
    s.status = Wire.kXR_error
    s.body = vcat(
        cs_be32(reinterpret(UInt32, Int32(errnum))),
        Vector{UInt8}(codeunits(message)),
        nul ? UInt8[0x00] : UInt8[],
    )
    return s
end

"The `u16` at byte `at` of the request recorded at index `i` (the last by default)."
info_u16(s::InfoServer, at::Int, i::Int=length(s.frames)) = Wire.get_u16(s.frames[i], at)

"""
Put `bytes` on the wire the way `s.fragment` says: in one write, or in pieces
that stop wherever the knob says — mid-header and mid-body included. TCP is
free to deliver a frame in as many reads as it likes, so a client that assumes
one read per frame passes every whole-frame test and fails on a slow link.
"""
function info_emit(s::InfoServer, sock, bytes::AbstractVector{UInt8})
    n = s.fragment
    if n <= 0
        write(sock, bytes)
        return nothing
    end
    for lo in 1:n:length(bytes)
        write(sock, bytes[lo:min(lo + n - 1, length(bytes))])
        flush(sock)
        yield()
    end
    return nothing
end

"""
The scripted reply, in whichever of the wire's envelopes the test asked for:
plain, or wrapped in the `kXR_attn`/`kXR_asynresp` frame a server uses to
deliver a reply it deferred (`actnum[4] + reserved[4] + ServerResponseHdr[8] +
data`, on the *original* streamid).
"""
function info_write_reply(s::InfoServer, sock, sid::UInt16)
    if isempty(s.notice)
        nothing
    else
        # kXR_asyncms: a server notice, addressed to nobody's request.
        notice = vcat(
            cs_be32(Wire.kXR_asyncms), zeros(UInt8, 4), Vector{UInt8}(codeunits(s.notice))
        )
        info_emit(s, sock, vcat(cs_hdr(0x0000, Wire.kXR_attn, length(notice)), notice))
    end
    if s.short_attn
        stub = cs_be32(Wire.kXR_asynresp)[1:3]   # too short even to name an action
        info_emit(s, sock, vcat(cs_hdr(0x0000, Wire.kXR_attn, length(stub)), stub))
    end
    if s.stray_attn
        # A deferred reply for a stream that was never opened (or has already
        # been answered): there is no caller to give it to.
        stray = vcat(
            cs_be32(Wire.kXR_asynresp),
            zeros(UInt8, 4),
            cs_hdr(0xffff, Wire.kXR_ok, 4),
            Vector{UInt8}(codeunits("late")),
        )
        info_emit(s, sock, vcat(cs_hdr(0x0000, Wire.kXR_attn, length(stray)), stray))
    end
    if s.scripted !== nothing
        # A frame the test spells out byte for byte — the shapes the composed
        # forms below cannot express (a kXR_status frame and its page trailer,
        # which lives outside `dlen`). `invokelatest` because the serving task
        # predates the closure the test just defined.
        info_emit(s, sock, Base.invokelatest(s.scripted, sid))
    elseif s.async
        inner = vcat(
            cs_be32(Wire.kXR_asynresp),
            zeros(UInt8, 4),
            cs_hdr(sid, s.status, length(s.body)),
            s.body,
        )
        info_emit(s, sock, vcat(cs_hdr(0x0000, Wire.kXR_attn, length(inner)), inner))
    else
        info_emit(s, sock, vcat(cs_hdr(sid, s.status, length(s.body)), s.body))
    end
    return nothing
end

"""
The bytes a request carries *beyond* its `dlen`. Only `kXR_writev` has any:
`dlen` frames the `N×16` descriptor block alone and `sum(wlen)` bytes of data
follow the frame (ops_file_vec.c). Taking them off the wire is not optional —
the next request would otherwise be read from a desynchronised stream.
"""
function info_take_trailer(sock, rid::UInt16, payload::Vector{UInt8})
    rid == Wire.kXR_writev || return UInt8[]
    nseg = length(payload) ÷ 16
    total = sum((cs_i32(payload, 16 * (i - 1) + 5) for i in 1:nseg); init=0)
    total > 0 || return UInt8[]
    trailer = read(sock, total)
    length(trailer) == total || throw(EOFError())
    return trailer
end

function info_serve_conn(s::InfoServer, sock)
    try
        serve_bringup(s, sock)
        while isopen(sock)
            frame, payload = cs_take(sock)
            sid = Wire.get_u16(frame, 1)
            rid = Wire.get_u16(frame, 3)
            append!(payload, info_take_trailer(sock, rid, payload))
            push!(s.ops, rid)
            push!(s.frames, copy(frame))
            push!(s.args, String(copy(payload)))
            if s.waitresp_secs > 0
                # "Later" — then the reply itself, unsolicited, on this stream.
                body = cs_be32(s.waitresp_secs)
                info_emit(s, sock, vcat(cs_hdr(sid, Wire.kXR_waitresp, length(body)), body))
                sleep(0.05)
            end
            info_write_reply(s, sock, sid)
        end
    catch
        # the client hung up, which is the only way this loop ends
    finally
        isopen(sock) && close(sock)
    end
    return nothing
end

"Start a scripted-reply server; returns (srv, port)."
function start_info_server(; kwargs...)
    s = InfoServer(; kwargs...)
    listener = listen(ip"127.0.0.1", 0)
    _, port = getsockname(listener)
    @async while isopen(listener)
        local sock
        try
            sock = accept(listener)
        catch
            break
        end
        @async info_serve_conn(s, sock)
    end
    return s, Int(port)
end

"A FileSystem on the scripted-reply server, with the stall deadline armed."
function info_fs(port::Int; stall_ms=CONF_STALL_MS)
    fs = XRootD.XrdCl.FileSystem("root://127.0.0.1:$port")
    XRootD.XrdCl.connection!(fs).stall_deadline_ms = stall_ms
    return fs
end
