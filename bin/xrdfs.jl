#!/usr/bin/env julia
# Launcher for xrdfs. Credits libxrdc (nginx-xrootd/client) as prior art.
using XRootD
exit(XRootD.Tools.Xrdfs.main(ARGS))
