# 0.2.x flag namespaces. Values are the kXR wire values (the same choice
# XrdCl made), so they compose with `|` and pass straight into Wire codecs.

"""
    OpenFlags

File-open flags: `Read`, `Update`, `Write`, `New`, `Delete` (truncate),
`Append`, `Refresh`, `MakePath`, `Force`, `Compress`, `None`. Compose with
`|`, e.g. `OpenFlags.New | OpenFlags.Write`.
"""
baremodule OpenFlags
const None = 0x0000
const Compress = 0x0001
const Delete = 0x0002
const Force = 0x0004
const New = 0x0008
const Read = 0x0010
const Update = 0x0020
const Refresh = 0x0080
const MakePath = 0x0100
const Append = 0x0200
const Write = 0x8000
end

"""
    Access

POSIX-style permission bits for created files/directories (`UR`, `UW`, `UX`,
`GR`, ..., `None`). Identical to the low nine POSIX mode bits.
"""
baremodule Access
const None = 0x0000
const UR = 0x0100
const UW = 0x0080
const UX = 0x0040
const GR = 0x0020
const GW = 0x0010
const GX = 0x0008
const OR = 0x0004
const OW = 0x0002
const OX = 0x0001
end

"""
    DirListFlags

`readdir` behavior flags: `Stat` requests per-entry stat info; `None` names
only.
"""
baremodule DirListFlags
const None = 0x0000
const Stat = 0x0001
const Locate = 0x0002
const Recursive = 0x0004
const Merge = 0x0008
const Chunked = 0x0010
const Zip = 0x0020
end

"""
    QueryCode

`query` information codes: `Stats`, `Space`, `Checksum`, `Config`, ...
"""
baremodule QueryCode
const Stats = 0x0001
const Prepare = 0x0002
const Checksum = 0x0003
const XAttr = 0x0004
const Space = 0x0005
const Config = 0x0007
const Visa = 0x0008
const Opaque = 0x0010
const OpaqueFile = 0x0020
end

"""
    MkDirFlags

`mkdir` flags: `MakePath` creates missing parent directories.
"""
baremodule MkDirFlags
const None = 0x0000
const MakePath = 0x0001
end
