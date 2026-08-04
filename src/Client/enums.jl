# 0.2.x flag namespaces. Values are the kXR wire values (the same choice
# XrdCl made), so they compose with `|` and pass straight into Wire codecs.

"""
    OpenFlags

File-open flags: `Read`, `Update`, `Write`, `New`, `Delete` (truncate),
`Append`, `Refresh`, `MakePath`, `Force`, `Compress`, `None`. Compose with
`|`, e.g. `OpenFlags.New | OpenFlags.Write`.

The v5 additions: `RetStat` asks the open to answer with a stat line;
`Replica` says this open is a replication copy; `POSC` makes the file
persist only on a successful close, so an interrupted transfer leaves
nothing behind; `NoWait` fails rather than waiting for an offline file to
stage in; `SeqIO` tells the server the reads will be sequential.
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
const RetStat = 0x0400
const Replica = 0x0800
const POSC = 0x1000
const NoWait = 0x2000
const SeqIO = 0x4000
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
`ChecksumCancel` withdraws a checksum the server is still computing.
"""
baremodule QueryCode
const Stats = 0x0001
const Prepare = 0x0002
const Checksum = 0x0003
const XAttr = 0x0004
const Space = 0x0005
const ChecksumCancel = 0x0006
const Config = 0x0007
const Visa = 0x0008
const Opaque = 0x0010
const OpaqueFile = 0x0020
const OpaqueGroup = 0x0040
end

"""
    MkDirFlags

`mkdir` flags: `MakePath` creates missing parent directories.
"""
baremodule MkDirFlags
const None = 0x0000
const MakePath = 0x0001
end

"""
    PrepareFlags

`prepare` options: `Stage` queues the file to be brought online, `Cancel`
withdraws an earlier request, `Notify` asks to be told when it finishes,
`Fresh` requeues a file already staged, `Colocate` places it with the
previous one, `WriteMode` prepares for writing, `NoErrors` suppresses the
per-file error report. `Evict` is not one of these — it rides in the
half-word beside them; pass `evict=true` to [`prepare`](@ref).
"""
baremodule PrepareFlags
const None = 0x00
const Cancel = 0x01
const Notify = 0x02
const NoErrors = 0x04
const Stage = 0x08
const WriteMode = 0x10
const Colocate = 0x20
const Fresh = 0x40
const UseTCP = 0x80
end

"""
    LocateFlags

`locate` options: `AddPeers` makes a manager report its subordinates'
answers too, `Refresh` bypasses the cached location, `PreferName` asks for
host names rather than addresses, `NoWait` answers from what is known now
rather than waiting.
"""
baremodule LocateFlags
const None = 0x0000
const AddPeers = 0x0001
const Refresh = 0x0080
const PreferName = 0x0100
const NoWait = 0x2000
end

"""
    ChkPointCode

`kXR_chkpoint` subcodes: `Begin`, `Commit`, `Rollback`, `Query`, and `Xeq`
for the form that carries a request to run inside the checkpoint.
"""
baremodule ChkPointCode
const Begin = 0x00
const Commit = 0x01
const Query = 0x02
const Rollback = 0x03
const Xeq = 0x04
end

"""
    ErrorCode

The server error codes an [`XRootDStatus`](@ref) carries in its `code`
field (`XErrorCode`), e.g. `st.code == ErrorCode.NotFound`. They share their
numeric range with the request opcodes but are a separate enumeration.
"""
baremodule ErrorCode
const ArgInvalid = UInt16(3000)
const ArgMissing = UInt16(3001)
const ArgTooLong = UInt16(3002)
const FileLocked = UInt16(3003)
const FileNotOpen = UInt16(3004)
const FSError = UInt16(3005)
const InvalidRequest = UInt16(3006)
const IOError = UInt16(3007)
const NoMemory = UInt16(3008)
const NoSpace = UInt16(3009)
const NotAuthorized = UInt16(3010)
const NotFound = UInt16(3011)
const ServerError = UInt16(3012)
const Unsupported = UInt16(3013)
const NoServer = UInt16(3014)
const NotFile = UInt16(3015)
const IsDirectory = UInt16(3016)
const Cancelled = UInt16(3017)
const ItExists = UInt16(3018)
const ChkSumErr = UInt16(3019)
const InProgress = UInt16(3020)
const OverQuota = UInt16(3021)
const Overloaded = UInt16(3024)
const FSReadOnly = UInt16(3025)
const AttrNotFound = UInt16(3027)
const TLSRequired = UInt16(3028)
const AuthFailed = UInt16(3030)
const Impossible = UInt16(3031)
const Conflict = UInt16(3032)
const TooManyErrs = UInt16(3033)
end
