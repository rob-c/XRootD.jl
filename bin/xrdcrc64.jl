#!/usr/bin/env julia
# Launcher for xrdcrc64. Credits libxrdc (nginx-xrootd/client) as prior art.
using XRootD
exit(XRootD.Tools.Cksum.crc64_main(ARGS))
