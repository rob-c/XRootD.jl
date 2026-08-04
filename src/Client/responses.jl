# Response value types: StatInfo, Location, ProtocolInfo, with the 0.2.x
# field names and Base predicate overloads.

"""
    StatInfo(line::AbstractString)

Stat information for a file or directory, parsed from the wire's ASCII stat
line. The extended fields (`ctime`, `atime`, `mode`, `octmode`, `owner`,
`group`) are populated when the server returns the extended form
(stat_line.h) and empty/zero otherwise.

Predicates: `isdir`, `isfile`, `isreadable`, `iswritable` (Base overloads),
[`isExecutable`](@ref), [`isOffline`](@ref).
"""
struct StatInfo
    id::String
    size::Int64
    flags::UInt32
    modtime::Int64
    ctime::Int64
    atime::Int64
    mode::String
    octmode::String
    owner::String
    group::String
end

function StatInfo(line::AbstractString)
    s = Wire.parse_stat_line(line)
    octmode = s.has_ext ? symbolic_mode(s.mode) : ""
    return StatInfo(
        s.id, s.size, s.flags, s.mtime, s.ctime, s.atime, s.mode, octmode, s.owner, s.group
    )
end

"Render an octal mode string (`\"0644\"`) as the 9-char symbolic form (`\"rw-r--r--\"`)."
function symbolic_mode(octal::AbstractString)
    bits = parse(UInt16, octal; base=8)
    out = IOBuffer()
    for shift in (6, 3, 0)
        triad = (bits >> shift) & 0x7
        print(out, (triad & 0x4) != 0 ? 'r' : '-')
        print(out, (triad & 0x2) != 0 ? 'w' : '-')
        print(out, (triad & 0x1) != 0 ? 'x' : '-')
    end
    return String(take!(out))
end

Base.isdir(st::StatInfo) = (st.flags & Wire.kXR_isDir) != 0
Base.isfile(st::StatInfo) = (st.flags & (Wire.kXR_isDir | Wire.kXR_other)) == 0
Base.isreadable(st::StatInfo) = (st.flags & Wire.kXR_readable) != 0
Base.iswritable(st::StatInfo) = (st.flags & Wire.kXR_writable) != 0

"""
    isExecutable(st::StatInfo) -> Bool

`true` when the executable/searchable bit (`kXR_xset`) is set.
"""
isExecutable(st::StatInfo) = (st.flags & Wire.kXR_xset) != 0

"""
    isOffline(st::StatInfo) -> Bool

`true` when the file's data is not currently online (`kXR_offline`).
"""
isOffline(st::StatInfo) = (st.flags & Wire.kXR_offline) != 0

function Base.show(io::IO, st::StatInfo)
    print(io, "StatInfo(id=$(st.id), size=$(st.size), flags=$(st.flags), ")
    print(io, "modtime=$(st.modtime)")
    if !isempty(st.mode)
        print(io, ", mode=$(st.mode) ($(st.octmode)), owner=$(st.owner), ")
        print(io, "group=$(st.group)")
    end
    print(io, ")")
    return nothing
end

"""
    StatFlags(flags::Integer)

What a `kXR_statx` reply says about one path: the same flags bitfield
[`StatInfo`](@ref) carries, without the size, times or ownership — that is
all `statx` answers, one byte per path, which is what makes it cheap enough
to ask about a whole directory at once.

Predicates: `isdir`, `isfile`, `isreadable`, `iswritable` (Base overloads),
[`isExecutable`](@ref), [`isOffline`](@ref) — the same set `StatInfo` has,
so code that tests one reads the same on the other.
"""
struct StatFlags
    flags::UInt32
end

StatFlags(flags::Integer) = StatFlags(UInt32(flags))

Base.isdir(f::StatFlags) = (f.flags & Wire.kXR_isDir) != 0
Base.isfile(f::StatFlags) = (f.flags & (Wire.kXR_isDir | Wire.kXR_other)) == 0
Base.isreadable(f::StatFlags) = (f.flags & Wire.kXR_readable) != 0
Base.iswritable(f::StatFlags) = (f.flags & Wire.kXR_writable) != 0
isExecutable(f::StatFlags) = (f.flags & Wire.kXR_xset) != 0
isOffline(f::StatFlags) = (f.flags & Wire.kXR_offline) != 0

function Base.show(io::IO, f::StatFlags)
    kind = isdir(f) ? "dir" : ((f.flags & Wire.kXR_other) != 0 ? "other" : "file")
    perm = string(isreadable(f) ? 'r' : '-', iswritable(f) ? 'w' : '-')
    print(io, "StatFlags($kind, $perm")
    isOffline(f) && print(io, ", offline")
    print(io, ")")
    return nothing
end

"""
    Location(address, node, access)

One replica location from `locate`: `address` is `host:port`, `node` the
server type character (`'S'`/`'M'` online server/manager, lowercase when
pending), `access` `'r'` or `'w'`.
"""
struct Location
    address::String
    node::Char
    access::Char
end

function Base.show(io::IO, l::Location)
    kind = l.node in ('M', 'm') ? "manager" : "server"
    rw = l.access == 'w' ? "read-write" : "read-only"
    print(io, "Location($(l.address), $kind, $rw)")
    return nothing
end

"""
    ProtocolInfo(version, hostinfo)

Server protocol information: the protocol `version` (e.g. `0x0520` for
5.2.0) and the server's type/host flags.

Predicates over `hostinfo`: [`ismanager`](@ref) and [`isserver`](@ref) for the
endpoint's role, [`ismeta`](@ref), [`isproxy`](@ref) and [`issupervisor`](@ref)
for the attributes that qualify it. `ismanager` is the same question `locate`
answers about a replica, so it reads the same on either.
"""
struct ProtocolInfo
    version::UInt32
    hostinfo::UInt32
end

"""
`true` when the endpoint redirects to something else rather than holding data
itself — asked of a `protocol` reply, or of a `locate` answer's [`Location`](@ref).
"""
ismanager(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_isManager) != 0

"`true` when the endpoint holds data itself."
isserver(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_isServer) != 0

"`true` when the manager manages other managers rather than data servers."
ismeta(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_attrMeta) != 0

"`true` when the endpoint fronts a cluster it is not part of."
isproxy(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_attrProxy) != 0

"`true` when the manager is itself subordinate to another one."
issupervisor(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_attrSuper) != 0

"""
`true` when the server answers `kXR_gpfile` (`kXR_supgpf`). No server this
package was checked against sets it, which is the fact
[`XRootD.XrdCl.gpfile`](@ref) is written around.
"""
supports_gpfile(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_supgpf) != 0

"""
`true` when `kXR_gpfile` is open to clients that did not authenticate
(`kXR_anongpf`). It qualifies [`supports_gpfile`](@ref) rather than
standing on its own.
"""
allows_anon_gpfile(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_anongpf) != 0

"`true` when the server answers `kXR_pgread`/`kXR_pgwrite` (`kXR_suppgrw`)."
supports_pgio(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_suppgrw) != 0

"""
`true` when the server honours persist-on-successful-close (`kXR_supposc`),
the `OpenFlags.POSC` that leaves nothing behind when a transfer is
interrupted.
"""
supports_posc(p::ProtocolInfo) = (p.hostinfo & Wire.kXR_supposc) != 0

function protocol_role(p::ProtocolInfo)
    role = if ismanager(p)
        issupervisor(p) ? "supervisor" : (ismeta(p) ? "meta-manager" : "manager")
    elseif isserver(p)
        "server"
    else
        "unknown"
    end
    return isproxy(p) ? "proxy $role" : role
end

function Base.show(io::IO, p::ProtocolInfo)
    major = (p.version >> 8) & 0xff
    minor = (p.version >> 4) & 0xf
    patch = p.version & 0xf
    print(io, "ProtocolInfo(version=$(Int(p.version)) ($major.$minor.$patch), ")
    print(io, "$(protocol_role(p)), hostinfo=0x$(string(p.hostinfo; base=16)))")
    return nothing
end
