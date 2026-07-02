#!/usr/bin/env julia
# Launcher for xrdcrc32c. Credits libxrdc (nginx-xrootd/client) as prior art.
using XRootD
exit(XRootD.Tools.Cksum.crc32c_main(ARGS))
