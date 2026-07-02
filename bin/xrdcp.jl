#!/usr/bin/env julia
# Launcher for xrdcp. Credits libxrdc (nginx-xrootd/client) as prior art.
using XRootD
exit(XRootD.Tools.Xrdcp.main(ARGS))
