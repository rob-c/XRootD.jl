#!/usr/bin/env julia
# Launcher for xrdckverify. Credits libxrdc (nginx-xrootd/client) as prior art.
using XRootD
exit(XRootD.Tools.Cksum.ckverify_main(ARGS))
