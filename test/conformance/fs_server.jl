# A strict, spec-checking XRootD server for the NAMESPACE surface: the
# requests that name a path rather than move file data — dirlist, open, stat,
# mkdir, mv, chmod, rm, rmdir, truncate, fattr, query, locate, prepare,
# symlink/link/readlink, setattr and ping.
#
# Same contract as conformance/server.jl, whose byte helpers (cs_hdr, cs_ok,
# cs_error, cs_take, cs_be32, ...) this file reuses: every framing rule the
# protocol states is checked and any breach lands in `fs.violations`, and the
# replies are hand-built from the primitives rather than through the codecs
# under test, so the tests cannot pass by agreeing with an encoder's bugs.
#
# The namespace is real — a `Dict` of paths to nodes with data, mode and
# extended attributes — so an operation is judged by what the server ends up
# holding, not by the status it chose to return.

using Sockets
using XRootD: Wire

# XErrorCode values (XProtocol.hh). Wire carries no error-code table, and a
# conformance server has to answer with the code a stock server would.
const FSC_ArgInvalid = 3000
const FSC_InvalidRequest = 3006
const FSC_NotFound = 3011
const FSC_Unsupported = 3013
const FSC_NotFile = 3015
const FSC_isDirectory = 3016
const FSC_IOError = 3007
const FSC_AttrNotFound = 3027
const FSC_FileNotOpen = 3004

"Every stat line this namespace emits carries this mtime."
const FSC_MTIME = 1_700_000_000

"kXR_faMaxVars — the attributes one kXR_fattr request may name."
const FSC_FATTR_MAX = 16

"The `kXR_open` option bits a v5 client may set."
const FSC_OPEN_KNOWN =
    Wire.kXR_compress | Wire.kXR_delete | Wire.kXR_force | Wire.kXR_new |
    Wire.kXR_open_read | Wire.kXR_open_updt | Wire.kXR_refresh | Wire.kXR_mkpath |
    Wire.kXR_open_apnd | Wire.kXR_retstat | Wire.kXR_open_wrto

"The `kXR_open` bits that request write access."
const FSC_OPEN_WRITE =
    Wire.kXR_delete | Wire.kXR_new | Wire.kXR_open_updt | Wire.kXR_open_apnd |
    Wire.kXR_open_wrto

"One namespace entry: a file's bytes or a directory, plus mode and xattrs."
mutable struct ConfNode
    data::Vector{UInt8}
    dir::Bool
    mode::UInt16
    xattr::Dict{String,Vector{UInt8}}
    link::String                       # symlink target; "" for everything else
end

function ConfNode(; data=UInt8[], dir::Bool=false, mode::Integer=0o644, link="")
    return ConfNode(
        Vector{UInt8}(data), dir, UInt16(mode), Dict{String,Vector{UInt8}}(), String(link)
    )
end

"""
A namespace conformance server. `violations` collects every protocol breach
seen from the client; `ops` and `paths` record the requestid and the path of
each request served, in order, so a test can assert on the *sequence* a
client emitted (the bottom-up order of a `walkdir`, a per-entry `kXR_stat`
fallback after a listing without stat info).

The shaping knobs are one-shot and keyed by requestid: they make the next
request of that kind wait, fail, or answer with a body of the test's choosing.
"""
Base.@kwdef mutable struct ConfFS
    nodes::Dict{String,ConfNode} = Dict{String,ConfNode}(
        "/" => ConfNode(; dir=true, mode=0o755)
    )
    handles::Dict{NTuple{4,UInt8},String} = Dict{NTuple{4,UInt8},String}()
    next_handle::UInt32 = 0x00000001
    violations::Vector{String} = String[]
    ops::Vector{UInt16} = UInt16[]
    paths::Vector{String} = String[]
    opaque::Vector{String} = String[]   # the CGI on each path, "" when there is none
    logins::Vector{String} = String[]   # the username each connection logged in as
    # response shaping
    fail_next::UInt16 = 0x0000        # fail the next request of this kind once
    fail_code::Int = FSC_IOError      # ... with this error code
    wait_next::UInt16 = 0x0000        # answer it with kXR_wait once
    cut_next::UInt16 = 0x0000         # announce more body than is sent, then hang up
    body_for::UInt16 = 0x0000         # substitute `body_next` for this reply
    body_next::Vector{UInt8} = UInt8[]
    junk::Bool = false                # precede the next reply with a frame for no one
    no_stat::Bool = false             # ignore kXR_dstat on a listing
    chunk_dirlist::Int = 0            # >0: split listings into kXR_oksofar chunks
end

"Record a protocol breach; the tests fail on a non-empty violation list."
flag!(fs::ConfFS, msg::AbstractString) = push!(fs.violations, String(msg))

"Reset the shaping knobs and the recorded history, keeping the namespace."
function fsc_reset!(fs::ConfFS)
    empty!(fs.violations)
    empty!(fs.ops)
    empty!(fs.paths)
    empty!(fs.opaque)
    empty!(fs.logins)
    fs.fail_next = 0x0000
    fs.fail_code = FSC_IOError
    fs.wait_next = 0x0000
    fs.cut_next = 0x0000
    fs.body_for = 0x0000
    fs.body_next = UInt8[]
    fs.junk = false
    fs.no_stat = false
    fs.chunk_dirlist = 0
    return fs
end

# ---- namespace ----

"Normalize a wire path the way a namespace does: one separator between names, none trailing."
function fsc_norm(path::AbstractString)
    parts = filter(!isempty, split(String(path), '/'))
    return isempty(parts) ? "/" : "/" * join(parts, "/")
end

function fsc_name(path::AbstractString)
    return path == "/" ? "/" : String(path[(findlast('/', path) + 1):end])
end

function fsc_parent(path::AbstractString)
    path == "/" && return "/"
    i = findlast('/', path)
    return i == 1 ? "/" : String(path[1:(i - 1)])
end

"Take the path a request named, checking it is the absolute form the protocol requires."
function fsc_wantpath(fs::ConfFS, what::AbstractString, raw::AbstractString)
    isempty(raw) && flag!(fs, "$what: empty path")
    (isempty(raw) || startswith(raw, "/")) || flag!(fs, "$what: relative path $(repr(raw))")
    # Everything past the first '?' is CGI, the way stock XrdXrootd splits an
    # incoming path. It is recorded per path so a test can assert what the
    # client attached — that is how tokens reach the server.
    q = findfirst('?', raw)
    push!(fs.opaque, q === nothing ? "" : String(raw[(nextind(raw, q)):end]))
    q === nothing || (raw = raw[1:prevind(raw, q)])
    path = fsc_norm(raw)
    push!(fs.paths, path)
    return path
end

"The immediate children of `dir`, sorted; the namespace itself is a flat path map."
function fsc_children(fs::ConfFS, dir::AbstractString)
    return sort!([fsc_name(p) for p in keys(fs.nodes) if p != "/" && fsc_parent(p) == dir])
end

function fsc_mkpath!(fs::ConfFS, dir::AbstractString)
    dir == "/" && return nothing
    haskey(fs.nodes, dir) && return nothing
    fsc_mkpath!(fs, fsc_parent(dir))
    fs.nodes[dir] = ConfNode(; dir=true, mode=0o755)
    return nothing
end

function fsc_flags(n::ConfNode)
    f = n.dir ? Wire.kXR_isDir : UInt32(0)
    (n.mode & 0o400) != 0 && (f |= Wire.kXR_readable)
    (n.mode & 0o200) != 0 && (f |= Wire.kXR_writable)
    (n.mode & 0o100) != 0 && (f |= Wire.kXR_xset)
    return f
end

"The four-field ASCII stat line: `\"<id> <size> <flags> <mtime>\"`."
function fsc_stat_line(fs::ConfFS, path::AbstractString)
    n = fs.nodes[path]
    return "$(length(fsc_name(path))) $(length(n.data)) $(fsc_flags(n)) $FSC_MTIME"
end

"Allocate a file handle for `path`; handles are 4-byte big-endian counters."
function fsc_handle!(fs::ConfFS, path::AbstractString)
    h = fs.next_handle
    fs.next_handle += 0x00000001
    fh = (
        UInt8((h >> 24) & 0xff),
        UInt8((h >> 16) & 0xff),
        UInt8((h >> 8) & 0xff),
        UInt8(h & 0xff),
    )
    fs.handles[fh] = String(path)
    return fh
end

fsc_fhandle(frame, at::Int) = (frame[at], frame[at + 1], frame[at + 2], frame[at + 3])

"Check that the reserved bytes a request must leave alone are zero."
function fsc_zeroed(fs::ConfFS, frame, range::UnitRange{Int}, what::AbstractString)
    all(==(0x00), view(frame, range)) ||
        flag!(fs, "$what: reserved frame bytes $range are not zero")
    return nothing
end

# ---- reply shaping ----

"""
Apply the knobs that answer a request instead of serving it: `junk` prepends
a frame addressed to no one, `wait_next` answers `kXR_wait` once and
`fail_next` fails once. Returns `true` when the request has been answered and
must not be served.
"""
function fsc_shape(fs::ConfFS, sock, sid::UInt16, rid::UInt16)
    if fs.junk
        fs.junk = false
        write(sock, vcat(cs_hdr(0xffff, Wire.kXR_ok, 3), UInt8[0x6e, 0x6f, 0x21]))
    end
    if fs.wait_next == rid
        fs.wait_next = 0x0000
        write(sock, vcat(cs_hdr(sid, Wire.kXR_wait, 4), cs_be32(0)))
        return true
    end
    if fs.fail_next == rid
        fs.fail_next = 0x0000
        cs_error(sock, sid, fs.fail_code, "conformance: refused $(Wire.request_name(rid))")
        return true
    end
    return false
end

"""
Send the terminal reply for `rid`, applying the shaping knobs that rewrite it:
`body_next` substitutes a hand-built body, and `cut_next` announces a body it
then declines to send in full before hanging up.
"""
function fsc_reply(
    fs::ConfFS, sock, sid::UInt16, rid::UInt16, body::AbstractVector{UInt8}=UInt8[]
)
    out = Vector{UInt8}(body)
    if fs.body_for == rid
        fs.body_for = 0x0000
        out = fs.body_next
    end
    if fs.cut_next == rid
        fs.cut_next = 0x0000
        write(sock, cs_hdr(sid, Wire.kXR_ok, length(out) + 8))
        write(sock, out)
        throw(EOFError())                        # hang up behind the short body
    end
    return cs_ok(sock, sid, out)
end

# ---- per-request handlers ----

function fsc_serve_dirlist(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:19, "kXR_dirlist")
    options = frame[20]
    (options & ~(Wire.kXR_online | Wire.kXR_dstat | Wire.kXR_dcksm)) == 0 ||
        flag!(fs, "kXR_dirlist: unknown option bits $(string(options; base=16))")
    path = fsc_wantpath(fs, "kXR_dirlist", String(copy(payload)))
    node = get(fs.nodes, path, nothing)
    node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such directory $path")
    node.dir || return cs_error(sock, sid, FSC_NotFile, "$path is not a directory")

    dstat = (options & Wire.kXR_dstat) != 0 && !fs.no_stat
    io = IOBuffer()
    # The dstat form opens with the ".\n0 0 0 0\n" sentinel and then alternates
    # name and stat lines; the plain form is bare names. Both are NUL-terminated.
    dstat && print(io, ".\n0 0 0 0\n")
    for name in fsc_children(fs, path)
        print(io, name, "\n")
        dstat && print(io, fsc_stat_line(fs, path == "/" ? "/$name" : "$path/$name"), "\n")
    end
    write(io, 0x00)
    body = take!(io)

    if fs.chunk_dirlist > 0 && length(body) > fs.chunk_dirlist
        # A long listing arrives as kXR_oksofar chunks; accumulating them is
        # the Session layer's job, and the split lands mid-line on purpose.
        pos = 1
        while length(body) - pos + 1 > fs.chunk_dirlist
            chunk = body[pos:(pos + fs.chunk_dirlist - 1)]
            write(sock, vcat(cs_hdr(sid, Wire.kXR_oksofar, length(chunk)), chunk))
            pos += fs.chunk_dirlist
        end
        return fsc_reply(fs, sock, sid, Wire.kXR_dirlist, body[pos:end])
    end
    return fsc_reply(fs, sock, sid, Wire.kXR_dirlist, body)
end

function fsc_serve_open(fs::ConfFS, sock, sid, frame, payload)
    mode = Wire.get_u16(frame, 5)
    options = Wire.get_u16(frame, 7)
    fsc_zeroed(fs, frame, 9:20, "kXR_open")
    (options & ~FSC_OPEN_KNOWN) == 0 ||
        flag!(fs, "kXR_open: unknown option bits $(string(options; base=16))")
    (options & (FSC_OPEN_WRITE | Wire.kXR_open_read)) == 0 &&
        flag!(fs, "kXR_open: no access mode requested")
    path = fsc_wantpath(fs, "kXR_open", String(copy(payload)))

    node = get(fs.nodes, path, nothing)
    if node !== nothing
        node.dir && return cs_error(sock, sid, FSC_isDirectory, "$path is a directory")
        (options & Wire.kXR_new) != 0 &&
            return cs_error(sock, sid, FSC_InvalidRequest, "$path already exists")
        (options & Wire.kXR_delete) != 0 && empty!(node.data)
    else
        (options & FSC_OPEN_WRITE) == 0 &&
            return cs_error(sock, sid, FSC_NotFound, "no such file $path")
        parent = fsc_parent(path)
        if !haskey(fs.nodes, parent)
            (options & Wire.kXR_mkpath) == 0 &&
                return cs_error(sock, sid, FSC_NotFound, "no such directory $parent")
            fsc_mkpath!(fs, parent)
        end
        node = ConfNode(; mode=(mode == 0 ? 0o644 : mode))
        fs.nodes[path] = node
    end

    body = collect(fsc_handle!(fs, path))
    if (options & Wire.kXR_retstat) != 0
        # handle[4], then the compression descriptor stock servers send
        # (page size[4] + type[4]), then the stat line.
        body = vcat(
            body, cs_be32(0), cs_be32(0), Vector{UInt8}(codeunits(fsc_stat_line(fs, path)))
        )
    end
    return fsc_reply(fs, sock, sid, Wire.kXR_open, body)
end

"Resolve the handle a file request carries, flagging one the server never issued."
function fsc_open_path(fs::ConfFS, frame, what::AbstractString; at::Int=5)
    fh = fsc_fhandle(frame, at)
    path = get(fs.handles, fh, nothing)
    path === nothing && flag!(fs, "$what: unknown fhandle $fh")
    return path
end

function fsc_serve_stat(fs::ConfFS, sock, sid, frame, payload)
    options = frame[5]
    fsc_zeroed(fs, frame, 6:16, "kXR_stat")
    (options & ~Wire.kXR_vfs) == 0 ||
        flag!(fs, "kXR_stat: unknown option bits $(string(options; base=16))")

    if isempty(payload)
        # The handle form names no path; the path form carries no handle.
        path = fsc_open_path(fs, frame, "kXR_stat"; at=17)
        path === nothing && return cs_error(sock, sid, FSC_FileNotOpen, "file not open")
        (options & Wire.kXR_vfs) != 0 && flag!(fs, "kXR_stat: kXR_vfs on the handle form")
        return fsc_reply(
            fs, sock, sid, Wire.kXR_stat, Vector{UInt8}(codeunits(fsc_stat_line(fs, path)))
        )
    end
    fsc_fhandle(frame, 17) == (0x00, 0x00, 0x00, 0x00) ||
        flag!(fs, "kXR_stat: the path form carries a file handle")
    path = fsc_wantpath(fs, "kXR_stat", String(copy(payload)))
    haskey(fs.nodes, path) ||
        return cs_error(sock, sid, FSC_NotFound, "no such file or directory $path")
    if (options & Wire.kXR_vfs) != 0
        # oss space report: nodes, free KB, utilization, then the same three
        # for the staging area.
        return fsc_reply(
            fs, sock, sid, Wire.kXR_stat, Vector{UInt8}(codeunits("2 1024 50 1 2048 25"))
        )
    end
    return fsc_reply(
        fs, sock, sid, Wire.kXR_stat, Vector{UInt8}(codeunits(fsc_stat_line(fs, path)))
    )
end

function fsc_serve_mkdir(fs::ConfFS, sock, sid, frame, payload)
    options = frame[5]
    fsc_zeroed(fs, frame, 6:18, "kXR_mkdir")
    mode = Wire.get_u16(frame, 19)
    (options & ~Wire.kXR_mkdirpath) == 0 ||
        flag!(fs, "kXR_mkdir: unknown option bits $(string(options; base=16))")
    path = fsc_wantpath(fs, "kXR_mkdir", String(copy(payload)))
    haskey(fs.nodes, path) &&
        return cs_error(sock, sid, FSC_InvalidRequest, "$path already exists")
    parent = fsc_parent(path)
    if !haskey(fs.nodes, parent)
        (options & Wire.kXR_mkdirpath) == 0 &&
            return cs_error(sock, sid, FSC_NotFound, "no such directory $parent")
        fsc_mkpath!(fs, parent)
    end
    fs.nodes[path] = ConfNode(; dir=true, mode=(mode == 0 ? 0o755 : mode))
    return fsc_reply(fs, sock, sid, Wire.kXR_mkdir)
end

"Split a two-path payload at `arg1len`, checking the single-space separator."
function fsc_two_paths(fs::ConfFS, frame, payload, what::AbstractString)
    arg1len = Int(Wire.get_u16(frame, 19))
    if arg1len <= 0 || arg1len >= length(payload)
        flag!(
            fs, "$what: arg1len $arg1len does not split a $(length(payload))-byte payload"
        )
        return nothing, nothing
    end
    payload[arg1len + 1] == UInt8(' ') ||
        flag!(fs, "$what: the paths are not separated by a space")
    first = String(copy(payload[1:arg1len]))
    second = String(copy(payload[(arg1len + 2):end]))
    return fsc_wantpath(fs, what, first), fsc_wantpath(fs, what, second)
end

function fsc_serve_mv(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:18, "kXR_mv")
    src, dst = fsc_two_paths(fs, frame, payload, "kXR_mv")
    src === nothing && return cs_error(sock, sid, FSC_ArgInvalid, "bad kXR_mv payload")
    haskey(fs.nodes, src) || return cs_error(sock, sid, FSC_NotFound, "no such file $src")
    haskey(fs.nodes, dst) &&
        return cs_error(sock, sid, FSC_InvalidRequest, "$dst already exists")
    haskey(fs.nodes, fsc_parent(dst)) ||
        return cs_error(sock, sid, FSC_NotFound, "no such directory $(fsc_parent(dst))")
    # Renaming a directory renames everything under it; the namespace is a flat
    # map, so the subtree's keys move with it.
    for path in collect(keys(fs.nodes))
        if path == src
            fs.nodes[dst] = pop!(fs.nodes, path)
        elseif startswith(path, src * "/")
            fs.nodes[dst * path[(length(src) + 1):end]] = pop!(fs.nodes, path)
        end
    end
    return fsc_reply(fs, sock, sid, Wire.kXR_mv)
end

function fsc_serve_chmod(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:18, "kXR_chmod")
    mode = Wire.get_u16(frame, 19)
    mode > 0o777 && flag!(fs, "kXR_chmod: mode $(string(mode; base=8)) is not nine bits")
    path = fsc_wantpath(fs, "kXR_chmod", String(copy(payload)))
    node = get(fs.nodes, path, nothing)
    node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such file $path")
    node.mode = mode
    return fsc_reply(fs, sock, sid, Wire.kXR_chmod)
end

function fsc_serve_rm(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:20, "kXR_rm")
    path = fsc_wantpath(fs, "kXR_rm", String(copy(payload)))
    node = get(fs.nodes, path, nothing)
    node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such file $path")
    node.dir && return cs_error(sock, sid, FSC_isDirectory, "$path is a directory")
    delete!(fs.nodes, path)
    return fsc_reply(fs, sock, sid, Wire.kXR_rm)
end

function fsc_serve_rmdir(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:20, "kXR_rmdir")
    path = fsc_wantpath(fs, "kXR_rmdir", String(copy(payload)))
    node = get(fs.nodes, path, nothing)
    node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such directory $path")
    node.dir || return cs_error(sock, sid, FSC_NotFile, "$path is not a directory")
    isempty(fsc_children(fs, path)) ||
        return cs_error(sock, sid, FSC_InvalidRequest, "$path is not empty")
    path == "/" && return cs_error(sock, sid, FSC_InvalidRequest, "cannot remove the root")
    delete!(fs.nodes, path)
    return fsc_reply(fs, sock, sid, Wire.kXR_rmdir)
end

function fsc_serve_truncate(fs::ConfFS, sock, sid, frame, payload)
    size = cs_i64(frame, 9)
    fsc_zeroed(fs, frame, 17:20, "kXR_truncate")
    size < 0 && flag!(fs, "kXR_truncate: negative size $size")
    path = if isempty(payload)
        p = fsc_open_path(fs, frame, "kXR_truncate")
        p === nothing && return cs_error(sock, sid, FSC_FileNotOpen, "file not open")
        p
    else
        fsc_fhandle(frame, 5) == (0x00, 0x00, 0x00, 0x00) ||
            flag!(fs, "kXR_truncate: the path form carries a file handle")
        fsc_wantpath(fs, "kXR_truncate", String(copy(payload)))
    end
    node = get(fs.nodes, path, nothing)
    node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such file $path")
    node.dir && return cs_error(sock, sid, FSC_isDirectory, "$path is a directory")
    if size <= length(node.data)
        resize!(node.data, size)
    else
        append!(node.data, zeros(UInt8, size - length(node.data)))
    end
    return fsc_reply(fs, sock, sid, Wire.kXR_truncate)
end

"""
Adler-32, recomputed here rather than taken from the client's checksum code so
that a `kXR_Qcksum` reply is independent of what the client would have derived.
"""
function fsc_adler32(data::AbstractVector{UInt8})
    a, b = UInt32(1), UInt32(0)
    for byte in data
        a = (a + byte) % 0xfff1
        b = (b + a) % 0xfff1
    end
    return (b << 16) | a
end

const FSC_CONFIG = Dict(
    "version" => "5.2.0", "role" => "server", "sitename" => "conformance"
)

function fsc_serve_query(fs::ConfFS, sock, sid, frame, payload)
    infotype = Wire.get_u16(frame, 5)
    fsc_zeroed(fs, frame, 7:20, "kXR_query")
    args = String(copy(payload))
    if infotype == Wire.kXR_Qcksum
        path = fsc_wantpath(fs, "kXR_query", args)
        node = get(fs.nodes, path, nothing)
        node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such file $path")
        text = "adler32 " * string(fsc_adler32(node.data); base=16, pad=8)
        return fsc_reply(
            fs, sock, sid, Wire.kXR_query, vcat(Vector{UInt8}(codeunits(text)), 0x00)
        )
    elseif infotype == Wire.kXR_Qconfig
        # One line per requested keyword, in the order asked.
        lines = [get(FSC_CONFIG, String(k), "0") for k in split(args; keepempty=false)]
        text = join(lines, "\n") * "\n"
        return fsc_reply(
            fs, sock, sid, Wire.kXR_query, vcat(Vector{UInt8}(codeunits(text)), 0x00)
        )
    elseif infotype == Wire.kXR_Qspace
        return fsc_reply(
            fs,
            sock,
            sid,
            Wire.kXR_query,
            Vector{UInt8}(codeunits("oss.space=1024&oss.free=512\0")),
        )
    end
    return cs_error(sock, sid, FSC_Unsupported, "query $infotype is not supported")
end

"""
`kXR_fattr` the way stock XrdXrootd parses it: the body is `\"<path>\\0\"`, then
an nvec of `[rc u16][name\\0]` per named attribute, then — for Set only — a vvec
of `[vlen i32][value]`. Get/Set/Del answer
`[errcount u8][numattr u8][rc u16][name\\0]` (Get appending `[vlen][value]`);
List answers a NUL-separated name list.
"""
function fsc_serve_fattr(fs::ConfFS, sock, sid, frame, payload)
    fsc_fhandle(frame, 5) == (0x00, 0x00, 0x00, 0x00) ||
        flag!(fs, "kXR_fattr: a path-based request carries a file handle")
    subcode, numattr, options = frame[9], frame[10], frame[11]
    fsc_zeroed(fs, frame, 12:20, "kXR_fattr")
    numattr > FSC_FATTR_MAX &&
        flag!(fs, "kXR_fattr: $numattr attributes exceeds the maximum of $FSC_FATTR_MAX")

    z = findfirst(==(0x00), payload)
    if z === nothing
        flag!(fs, "kXR_fattr: the body has no NUL-terminated path")
        return cs_error(sock, sid, FSC_ArgInvalid, "bad fattr body")
    end
    path = fsc_wantpath(fs, "kXR_fattr", String(copy(payload[1:(z - 1)])))
    rest = payload[(z + 1):end]
    node = get(fs.nodes, path, nothing)
    node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such file $path")

    if subcode == Wire.kXR_fattrList
        numattr == 0 || flag!(fs, "kXR_fattr list: numattr is $numattr, want 0")
        isempty(rest) ||
            flag!(fs, "kXR_fattr list: $(length(rest)) bytes of attribute vector")
        (options & Wire.kXR_fa_aData) == 0 ||
            flag!(fs, "kXR_fattr list: values requested, which this server does not serve")
        names = sort!(collect(keys(node.xattr)))
        isempty(names) && return fsc_reply(fs, sock, sid, Wire.kXR_fattr)
        body = vcat(Vector{UInt8}(codeunits(join(names, "\0"))), 0x00)
        return fsc_reply(fs, sock, sid, Wire.kXR_fattr, body)
    end

    if subcode ∉ (Wire.kXR_fattrGet, Wire.kXR_fattrSet, Wire.kXR_fattrDel)
        flag!(fs, "kXR_fattr: unknown subcode $subcode")
        return cs_error(sock, sid, FSC_ArgInvalid, "bad subcode")
    end
    numattr == 1 || flag!(fs, "kXR_fattr: numattr is $numattr, want 1")
    if length(rest) < 3
        flag!(fs, "kXR_fattr: the attribute vector is $(length(rest)) bytes")
        return cs_error(sock, sid, FSC_ArgInvalid, "bad fattr body")
    end
    Wire.get_u16(rest, 1) == 0x0000 ||
        flag!(fs, "kXR_fattr: the request's nvec rc is not zero")
    rest = rest[3:end]
    z = findfirst(==(0x00), rest)
    if z === nothing
        flag!(fs, "kXR_fattr: unterminated attribute name")
        return cs_error(sock, sid, FSC_ArgInvalid, "bad fattr body")
    end
    name = String(copy(rest[1:(z - 1)]))
    rest = rest[(z + 1):end]

    if subcode == Wire.kXR_fattrGet
        isempty(rest) ||
            flag!(fs, "kXR_fattr get: $(length(rest)) trailing bytes after the name")
        value = get(node.xattr, name, nothing)
        # A missing attribute is reported per attribute, not as a request error.
        value === nothing && return fsc_reply(
            fs, sock, sid, Wire.kXR_fattr, fsc_fattr_reply(name, FSC_AttrNotFound)
        )
        return fsc_reply(fs, sock, sid, Wire.kXR_fattr, fsc_fattr_reply(name, 0, value))
    elseif subcode == Wire.kXR_fattrDel
        isempty(rest) ||
            flag!(fs, "kXR_fattr del: $(length(rest)) trailing bytes after the name")
        haskey(node.xattr, name) || return fsc_reply(
            fs, sock, sid, Wire.kXR_fattr, fsc_fattr_reply(name, FSC_AttrNotFound)
        )
        delete!(node.xattr, name)
        return fsc_reply(fs, sock, sid, Wire.kXR_fattr, fsc_fattr_reply(name, 0))
    end
    if length(rest) < 4
        flag!(fs, "kXR_fattr set: no value vector")
        return cs_error(sock, sid, FSC_ArgInvalid, "bad fattr body")
    end
    vlen = cs_i32(rest, 1)
    rest = rest[5:end]
    if vlen != length(rest)
        flag!(fs, "kXR_fattr set: value length $vlen but $(length(rest)) bytes followed")
        return cs_error(sock, sid, FSC_ArgInvalid, "bad fattr body")
    end
    (options & Wire.kXR_fa_isNew) != 0 &&
        haskey(node.xattr, name) &&
        return fsc_reply(
            fs, sock, sid, Wire.kXR_fattr, fsc_fattr_reply(name, FSC_InvalidRequest)
        )
    node.xattr[name] = Vector{UInt8}(rest)
    return fsc_reply(fs, sock, sid, Wire.kXR_fattr, fsc_fattr_reply(name, 0))
end

"One single-attribute reply: `[errcount][numattr][rc][name\\0]` (+ the value on a get)."
function fsc_fattr_reply(name::AbstractString, rc::Integer, value=nothing)
    out = UInt8[rc == 0 ? 0x00 : 0x01, 0x01]
    append!(out, Wire.set_u16!(zeros(UInt8, 2), 1, UInt16(rc)))
    append!(out, Vector{UInt8}(codeunits(name)))
    push!(out, 0x00)
    if value !== nothing
        append!(out, cs_be32(length(value)))
        append!(out, value)
    end
    return out
end

function fsc_serve_locate(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 7:20, "kXR_locate")
    path = fsc_wantpath(fs, "kXR_locate", String(copy(payload)))
    haskey(fs.nodes, path) ||
        return cs_error(sock, sid, FSC_NotFound, "no such file or directory $path")
    # Space-separated `XY<host:port>` tokens: server/manager, read/write.
    text = "Sr127.0.0.1:1094 Mw127.0.0.2:1094"
    return fsc_reply(
        fs, sock, sid, Wire.kXR_locate, vcat(Vector{UInt8}(codeunits(text)), 0x00)
    )
end

function fsc_serve_prepare(fs::ConfFS, sock, sid, frame, payload)
    options, prty = frame[5], frame[6]
    fsc_zeroed(fs, frame, 11:20, "kXR_prepare")
    prty == 0x00 || flag!(fs, "kXR_prepare: priority $prty was never requested")
    (
        options & ~(
            Wire.kXR_cancel | Wire.kXR_notify | Wire.kXR_noerrs | Wire.kXR_stage |
            Wire.kXR_wmode
        )
    ) == 0 || flag!(fs, "kXR_prepare: unknown option bits $(string(options; base=16))")
    paths = split(String(copy(payload)), '\n'; keepempty=false)
    isempty(paths) && flag!(fs, "kXR_prepare: no paths")
    for p in paths
        fsc_wantpath(fs, "kXR_prepare", p)
    end
    return fsc_reply(
        fs, sock, sid, Wire.kXR_prepare, vcat(Vector{UInt8}(codeunits("prep-0001")), 0x00)
    )
end

function fsc_serve_symlink(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:18, "kXR_symlink")
    target, link = fsc_two_paths(fs, frame, payload, "kXR_symlink")
    target === nothing &&
        return cs_error(sock, sid, FSC_ArgInvalid, "bad kXR_symlink payload")
    haskey(fs.nodes, link) &&
        return cs_error(sock, sid, FSC_InvalidRequest, "$link already exists")
    fs.nodes[link] = ConfNode(; mode=0o777, link=target)
    return fsc_reply(fs, sock, sid, Wire.kXR_symlink)
end

function fsc_serve_link(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:18, "kXR_link")
    old, new = fsc_two_paths(fs, frame, payload, "kXR_link")
    old === nothing && return cs_error(sock, sid, FSC_ArgInvalid, "bad kXR_link payload")
    node = get(fs.nodes, old, nothing)
    node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such file $old")
    node.dir && return cs_error(sock, sid, FSC_isDirectory, "$old is a directory")
    haskey(fs.nodes, new) &&
        return cs_error(sock, sid, FSC_InvalidRequest, "$new already exists")
    fs.nodes[new] = node                     # a hard link is the same node
    return fsc_reply(fs, sock, sid, Wire.kXR_link)
end

function fsc_serve_readlink(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:20, "kXR_readlink")
    path = fsc_wantpath(fs, "kXR_readlink", String(copy(payload)))
    node = get(fs.nodes, path, nothing)
    node === nothing && return cs_error(sock, sid, FSC_NotFound, "no such file $path")
    isempty(node.link) && return cs_error(sock, sid, FSC_ArgInvalid, "$path is not a link")
    return fsc_reply(
        fs, sock, sid, Wire.kXR_readlink, vcat(Vector{UInt8}(codeunits(node.link)), 0x00)
    )
end

"""
`kXR_setattr` (vendor extension): a 44-byte big-endian prefix — flags, atime
and mtime as (s, ns) pairs, uid, gid — then the NUL-terminated path.
"""
function fsc_serve_setattr(fs::ConfFS, sock, sid, frame, payload)
    fsc_zeroed(fs, frame, 5:20, "kXR_setattr")
    if length(payload) <= Wire.SETATTR_PREFIX_LEN
        flag!(fs, "kXR_setattr: $(length(payload)) bytes is too short for a path")
        return cs_error(sock, sid, FSC_ArgInvalid, "bad setattr body")
    end
    flags = cs_i32(payload, 1)
    (flags & ~(Wire.kXR_sa_times | Wire.kXR_sa_owner)) == 0 ||
        flag!(fs, "kXR_setattr: unknown flag bits $(string(flags; base=16))")
    flags == 0 && flag!(fs, "kXR_setattr: no fields selected")
    payload[end] == 0x00 || flag!(fs, "kXR_setattr: the path is not NUL-terminated")
    raw = String(copy(payload[(Wire.SETATTR_PREFIX_LEN + 1):(end - 1)]))
    path = fsc_wantpath(fs, "kXR_setattr", raw)
    haskey(fs.nodes, path) || return cs_error(sock, sid, FSC_NotFound, "no such file $path")
    return fsc_reply(fs, sock, sid, Wire.kXR_setattr)
end

# File data movement: the namespace server keeps real bytes so that the
# operations built out of open/read/write/close — File I/O, `copy(fs, ...)`,
# the storage backend — can be judged by what it ends up holding.

function fsc_serve_read(fs::ConfFS, sock, sid, frame)
    path = fsc_open_path(fs, frame, "kXR_read")
    path === nothing && return cs_error(sock, sid, FSC_FileNotOpen, "file not open")
    offset, rlen = cs_i64(frame, 9), cs_i32(frame, 17)
    offset < 0 && flag!(fs, "kXR_read: negative offset $offset")
    rlen < 0 && flag!(fs, "kXR_read: negative rlen $rlen")
    data = fs.nodes[path].data
    lo, hi = offset + 1, min(offset + rlen, length(data))
    return fsc_reply(fs, sock, sid, Wire.kXR_read, lo <= hi ? data[lo:hi] : UInt8[])
end

function fsc_serve_write(fs::ConfFS, sock, sid, frame, payload)
    path = fsc_open_path(fs, frame, "kXR_write")
    path === nothing && return cs_error(sock, sid, FSC_FileNotOpen, "file not open")
    offset = cs_i64(frame, 9)
    offset < 0 && flag!(fs, "kXR_write: negative offset $offset")
    data = fs.nodes[path].data
    need = offset + length(payload)
    length(data) < need && append!(data, zeros(UInt8, need - length(data)))
    data[(offset + 1):need] = payload
    return fsc_reply(fs, sock, sid, Wire.kXR_write)
end

# ---- connection ----

function fsc_serve_conn(fs::ConfFS, sock)
    try
        serve_bringup(fs, sock)
        while isopen(sock)
            frame, payload = cs_take(sock)
            sid, rid = Wire.get_u16(frame, 1), Wire.get_u16(frame, 3)
            sid == 0x0000 && flag!(fs, "$(Wire.request_name(rid)): streamid 0")
            push!(fs.ops, rid)
            fsc_shape(fs, sock, sid, rid) && continue
            if rid == Wire.kXR_dirlist
                fsc_serve_dirlist(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_open
                fsc_serve_open(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_stat
                fsc_serve_stat(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_mkdir
                fsc_serve_mkdir(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_mv
                fsc_serve_mv(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_chmod
                fsc_serve_chmod(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_rm
                fsc_serve_rm(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_rmdir
                fsc_serve_rmdir(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_truncate
                fsc_serve_truncate(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_query
                fsc_serve_query(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_fattr
                fsc_serve_fattr(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_locate
                fsc_serve_locate(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_prepare
                fsc_serve_prepare(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_symlink
                fsc_serve_symlink(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_link
                fsc_serve_link(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_readlink
                fsc_serve_readlink(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_setattr
                fsc_serve_setattr(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_read
                fsc_serve_read(fs, sock, sid, frame)
            elseif rid == Wire.kXR_write
                fsc_serve_write(fs, sock, sid, frame, payload)
            elseif rid == Wire.kXR_sync
                if fsc_open_path(fs, frame, "kXR_sync") === nothing
                    cs_error(sock, sid, FSC_FileNotOpen, "file not open")
                else
                    fsc_reply(fs, sock, sid, Wire.kXR_sync)
                end
            elseif rid == Wire.kXR_close
                fsc_zeroed(fs, frame, 9:20, "kXR_close")
                fh = fsc_fhandle(frame, 5)
                if !haskey(fs.handles, fh)
                    flag!(fs, "kXR_close: unknown fhandle $fh")
                    cs_error(sock, sid, FSC_FileNotOpen, "file not open")
                else
                    delete!(fs.handles, fh)
                    fsc_reply(fs, sock, sid, Wire.kXR_close)
                end
            elseif rid == Wire.kXR_protocol
                # Re-asked after bring-up: the same 5.2.0 server answer.
                Wire.get_u32(frame, 5) >= 0x00000310 ||
                    flag!(fs, "kXR_protocol: client version below 3.1.0")
                fsc_zeroed(fs, frame, 11:20, "kXR_protocol")
                fsc_reply(
                    fs, sock, sid, Wire.kXR_protocol, vcat(cs_be32(0x520), cs_be32(1))
                )
            elseif rid == Wire.kXR_ping
                fsc_zeroed(fs, frame, 5:20, "kXR_ping")
                isempty(payload) || flag!(fs, "kXR_ping: $(length(payload)) payload bytes")
                fsc_reply(fs, sock, sid, Wire.kXR_ping)
            else
                flag!(fs, "unexpected request $(Wire.request_name(rid)) ($rid)")
                cs_error(sock, sid, FSC_Unsupported, "unsupported")
            end
        end
    catch
        # client hung up, or a deliberate hang-up from a shaping knob
    finally
        isopen(sock) && close(sock)
    end
    return nothing
end

"""
    start_conf_fs(paths) -> (fs, port)

Start a namespace conformance server. `paths` seeds the namespace: a
`String` names an empty file, a `String => data` pair names a file with
content, and a path ending in `/` names a directory. Parent directories are
created implicitly.
"""
function start_conf_fs(paths=[])
    fs = ConfFS()
    for entry in paths
        path, data = entry isa Pair ? entry : (entry, UInt8[])
        if endswith(path, "/")
            fsc_mkpath!(fs, fsc_norm(path))
        else
            p = fsc_norm(path)
            fsc_mkpath!(fs, fsc_parent(p))
            fs.nodes[p] = ConfNode(; data=Vector{UInt8}(data))
        end
    end
    listener = listen(ip"127.0.0.1", 0)
    _, port = getsockname(listener)
    @async while isopen(listener)
        local sock
        try
            sock = accept(listener)
        catch
            break
        end
        @async fsc_serve_conn(fs, sock)
    end
    return fs, Int(port)
end

"""
Open a FileSystem against the namespace server on `port`, with the
whole-operation stall deadline armed so that a client which desynchronizes the
stream fails the test instead of hanging it. The deadline rides on the
connection, so a reconnect returns to the default.
"""
function conf_fs(port::Int; stall_ms=CONF_STALL_MS)
    fs = XRootD.XrdCl.FileSystem("root://127.0.0.1:$port")
    XRootD.XrdCl.connection!(fs).stall_deadline_ms = stall_ms
    return fs
end

"""
Open a File on the namespace server, with the same stall deadline armed.
Returns `nothing` when the open fails — the status-bearing form is
`open(File(), url, flags)`.
"""
function fs_file(port::Int, path::AbstractString, flags=XRootD.XrdCl.OpenFlags.Read)
    f = XRootD.XrdCl.File("root://127.0.0.1:$port/$path", flags)
    f === nothing && return nothing
    conn = f.conn
    conn === nothing || (conn.stall_deadline_ms = CONF_STALL_MS)
    return f
end

"The requestids the namespace server saw, as names, for order assertions."
fsc_op_names(fs::ConfFS) = [Wire.request_name(id) for id in fs.ops]

"How many requests of `rid` the namespace server has served."
fsc_op_count(fs::ConfFS, rid::UInt16) = count(==(rid), fs.ops)
