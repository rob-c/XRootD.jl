# xrdcp — copy files between local paths and XRootD/web/S3 endpoints.

module Xrdcp

using ..Tools: copyfile, copytree, EXIT_OK, EXIT_USAGE, EXIT_ERROR

const USAGE = "usage: xrdcp [-f] [-r] [--verify] <src> <dst>"

"""
    main(args::Vector{String}) -> Int

Copy `src` to `dst`. Flags: `-f` overwrite, `-r` recursive, `--verify`
post-copy checksum check. Returns a process exit code.
"""
function main(args::Vector{String})
    force = false
    recursive = false
    verify = false
    positional = String[]
    for a in args
        if a == "-f" || a == "--force"
            force = true
        elseif a == "-r" || a == "--recursive"
            recursive = true
        elseif a == "--verify"
            verify = true
        elseif a == "--version"
            println("xrdcp (XRootD.jl) — Julia port of libxrdc's xrdcp")
            return EXIT_OK
        elseif startswith(a, "-")
            println(stderr, "xrdcp: unknown option $a\n$USAGE")
            return EXIT_USAGE
        else
            push!(positional, a)
        end
    end
    if length(positional) != 2
        println(stderr, USAGE)
        return EXIT_USAGE
    end
    src, dst = positional
    ok, msg =
        recursive ? copytree(src, dst; force, verify) : copyfile(src, dst; force, verify)
    if ok
        return EXIT_OK
    else
        println(stderr, "xrdcp: $msg")
        return EXIT_ERROR
    end
end

end # module Xrdcp
