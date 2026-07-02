# Cross-implementation parity harness. Locates the reference clients — the
# libxrdc binaries (nginx-xrootd/client/bin) and the official tools shipped
# in XRootD_jll — and provides helpers to run them and capture output. The
# parity tiers run only when the corresponding reference is present, so CI
# without libxrdc still passes.

using XRootD_jll: XRootD_jll

const LIBXRDC_DIR = "/home/rcurrie/HEP-x/nginx-xrootd/client"

"True when the libxrdc reference binaries are available."
libxrdc_available() = isfile(joinpath(LIBXRDC_DIR, "bin", "xrdcp"))

"Run a libxrdc binary (with its LD_LIBRARY_PATH) and capture (stdout, exitcode)."
function run_libxrdc(tool::AbstractString, args::Vector{String})
    bin = joinpath(LIBXRDC_DIR, "bin", tool)
    cmd = setenv(`$bin $args`, "LD_LIBRARY_PATH" => LIBXRDC_DIR)
    out = IOBuffer()
    p = run(pipeline(ignorestatus(cmd); stdout=out, stderr=devnull))
    return String(take!(out)), p.exitcode
end

"Run an official XRootD_jll tool and capture (stdout, exitcode)."
function run_official(tool::Symbol, args::Vector{String})
    exe = getproperty(XRootD_jll, tool)()
    out = IOBuffer()
    p = run(pipeline(ignorestatus(`$exe $args`); stdout=out, stderr=devnull))
    return String(take!(out)), p.exitcode
end

"First whitespace-separated token of a `<digest> <path>` checksum line."
first_token(s::AbstractString) = isempty(strip(s)) ? "" : String(split(strip(s))[1])
