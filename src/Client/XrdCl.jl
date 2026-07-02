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

export XRootDStatus, isOK, isError
export FileSystem, ping, locate, query, rmdir, protocol
export File, sync, readv, writev, pgread, pgwrite
export getxattr, setxattr, listxattr, removexattr, statvfs, checksum, prepare
export symlink, hardlink, readlink
export isExecutable, isOffline
export OpenFlags, Access, DirListFlags, QueryCode, MkDirFlags

include("status.jl")
include("enums.jl")
include("responses.jl")
include("filesystem.jl")
include("file.jl")

end # module XrdCl
