#!/usr/bin/env julia
# Launcher for xrdadler32. Credits libxrdc (nginx-xrootd/client) as prior art.
using XRootD
exit(XRootD.Tools.Cksum.adler32_main(ARGS))
