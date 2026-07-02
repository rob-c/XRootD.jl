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
        if i === nothing
            (target, "")
        else
            (target[1:prevind(target, i)], target[nextind(target, i):end])
        end
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
        throw(
            ArgumentError(
                "kXR_login body needs ≥ $(SESSION_ID_LEN) bytes, got $(length(body))"
            ),
        )
    end
    sessid = Vector{UInt8}(body[1:SESSION_ID_LEN])
    sec = get_bounded_string(body, SESSION_ID_LEN + 1, length(body) - SESSION_ID_LEN)
    return (; sessid, sec)
end

"""
    parse_stat_line(line) -> (; id, size, flags, mtime, ctime, atime, mode, owner, group, has_ext)

Parse the ASCII stat line `"<id> <size> <flags> <mtime>"` returned by
`kXR_stat` (and per entry by dstat dirlists), including the optional
extended tail `" <ctime> <atime> <mode-octal> <owner> <group>"` some servers
append (stat_line.h). Without the tail, `has_ext` is `false` and the
extended fields are zero/empty.
"""
function parse_stat_line(line::AbstractString)
    parts = split(rstrip(line, '\0'))
    if length(parts) < 4
        throw(ArgumentError("malformed stat line: $(repr(line))"))
    end
    has_ext = length(parts) >= 9
    return (;
        id=String(parts[1]),
        size=parse(Int64, parts[2]),
        flags=parse(UInt32, parts[3]),
        mtime=parse(Int64, parts[4]),
        ctime=has_ext ? parse(Int64, parts[5]) : Int64(0),
        atime=has_ext ? parse(Int64, parts[6]) : Int64(0),
        mode=has_ext ? String(parts[7]) : "",
        owner=has_ext ? String(parts[8]) : "",
        group=has_ext ? String(parts[9]) : "",
        has_ext=has_ext,
    )
end

"""
    decode_open(body) -> (; fhandle::NTuple{4,UInt8}, cpsize::Int32, stat)

Decode a `kXR_open` response body: the 4-byte file handle, the compression
page size (0 when the 12-byte form is absent), and — when the open carried
`kXR_retstat` — the trailing ASCII stat line parsed via
[`parse_stat_line`](@ref) (`nothing` otherwise).
"""
function decode_open(body::AbstractVector{UInt8})
    if length(body) < 4
        throw(ArgumentError("kXR_open body needs ≥ 4 bytes, got $(length(body))"))
    end
    fhandle = (body[1], body[2], body[3], body[4])
    cpsize = length(body) >= 8 ? reinterpret(Int32, get_u32(body, 5)) : Int32(0)
    stat = if length(body) > 12
        line = get_bounded_string(body, 13, length(body) - 12)
        isempty(strip(line)) ? nothing : parse_stat_line(line)
    else
        nothing
    end
    return (; fhandle, cpsize, stat)
end

"""
    parse_locate(body) -> Vector{@NamedTuple{node::Char, access::Char, address::String}}

Parse a `kXR_locate` response: space-separated `XY<host:port>` tokens where
`X` is the node type (`S`/`M` online server/manager, `s`/`m` pending) and
`Y` the access mode (`r`/`w`).
"""
function parse_locate(body::AbstractVector{UInt8})
    text = rstrip(String(copy(body)), '\0')
    out = @NamedTuple{node::Char, access::Char, address::String}[]
    for token in split(text; keepempty=false)
        if length(token) < 3
            throw(ArgumentError("malformed locate token: $(repr(token))"))
        end
        push!(out, (; node=token[1], access=token[2], address=String(token[3:end])))
    end
    return out
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
