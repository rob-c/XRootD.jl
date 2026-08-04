"""
    XRootD.XrdCl

Layer 3 of the client: the public API. The module keeps its 0.2.x name and
surface — `FileSystem`/`File` with `(status, result)` tuple returns — so
existing user code and the legacy test suite run unchanged on the native
implementation.

Operation semantics follow the `libxrdc` C client (`client/lib/ops_fs.c`,
`ops_file.c`); this module translates between that behavior and the 0.2.x
Julia API shapes.
"""
module XrdCl

using ..Wire
using ..Session
import ..Session: data_streams

export XRootDStatus, isOK, isError, error_name
export FileSystem, ping, locate, deep_locate, query, rmdir, protocol
export statx, query_config, set_property, appid, endsess, evict, gpfile
export dirlist_stat, dirlist_checksum
export File, sync, readv, writev, clone, pgread, pgwrite, visa, compression
export getxattr, setxattr, listxattr, removexattr, xattrs
export statvfs, checksum, checksum_cancel, prepare
export checkpoint, checkpoint_begin, checkpoint_commit, checkpoint_rollback
export checkpoint_query, checkpoint_write, checkpoint_truncate
export reopen!, recoverable, bind_data_path!, data_streams
export symlink, hardlink, readlink
export isExecutable, isOffline
export ismanager, isserver, ismeta, isproxy, issupervisor
export supports_gpfile, allows_anon_gpfile, supports_pgio, supports_posc
export StatInfo, StatFlags, Location, ProtocolInfo
export OpenFlags, Access, DirListFlags, QueryCode, MkDirFlags
export PrepareFlags, LocateFlags, ChkPointCode, ErrorCode

include("status.jl")
include("enums.jl")
include("responses.jl")
include("filesystem.jl")
include("file.jl")

end # module XrdCl
