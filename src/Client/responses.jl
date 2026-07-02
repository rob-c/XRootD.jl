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
"""
struct ProtocolInfo
    version::UInt32
    hostinfo::UInt32
end

function Base.show(io::IO, p::ProtocolInfo)
    major = (p.version >> 8) & 0xff
    minor = (p.version >> 4) & 0xf
    patch = p.version & 0xf
    print(io, "ProtocolInfo(version=$(Int(p.version)) ($major.$minor.$patch), ")
    print(io, "hostinfo=0x$(string(p.hostinfo; base=16)))")
    return nothing
end
