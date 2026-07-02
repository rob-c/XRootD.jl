"""
    XRootD.Tools

Layer 5 of the client: the backend-agnostic copy engine and Julia
equivalents of the `xrdcp`, `xrdfs`, and checksum CLI tools. Each tool
exposes a `main(args)::Int` returning a process exit code (mirroring
libxrdc `xrdc_shellcode`); the `bin/*.jl` launchers just call these.

The tool behaviors and exit-code conventions are translated from the
`libxrdc` command-line front-ends (`client/apps/`).
"""
module Tools

using ..XrdCl
using ..Storage
using ..Storage: storage_for, storage_stat, storage_read, storage_write, storage_list
using CRC32c: CRC32c

export copyfile, copytree
export adler32, crc64xz, checksum_file

# Exit codes (mirror libxrdc xrdc_shellcode).
const EXIT_OK = 0
const EXIT_USAGE = 2
const EXIT_ERROR = 1

include("checksums.jl")
include("copy.jl")
include("xrdcp.jl")
include("xrdfs.jl")
include("cksum_tools.jl")

end # module Tools
