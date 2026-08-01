# xrdcp — copy files between local paths and XRootD/web/S3 endpoints.

module Xrdcp

using ..Tools: copyfile, copytree, EXIT_OK, EXIT_USAGE, EXIT_ERROR

const USAGE = """
usage: xrdcp [-f] [-r] [--verify] [--tpc first|only] [--token T]
             [--cert C] [--key K] [--cafile F] [--insecure] <src> <dst>"""

"""
    main(args::Vector{String}) -> Int

Copy `src` to `dst`. Flags: `-f` overwrite, `-r` recursive, `--verify`
post-copy checksum check, `--tpc first|only` third-party copy,
`--token`/`--cert`/`--key` credentials, `--cafile` extra trusted CAs,
`--insecure` skip TLS verification.
Returns a process exit code.
"""
function main(args::Vector{String})
    force = false
    recursive = false
    verify = false
    tpc = :none
    creds = Dict{Symbol,Any}()
    positional = String[]
    i = 1
    while i <= length(args)
        a = args[i]
        if a == "-f" || a == "--force"
            force = true
        elseif a == "-r" || a == "--recursive"
            recursive = true
        elseif a == "--verify"
            verify = true
        elseif a == "--insecure"
            creds[:insecure_tls] = true
        elseif a in ("--tpc", "--token", "--cert", "--key", "--cafile")
            i += 1
            if i > length(args)
                println(stderr, "xrdcp: $a needs a value\n$USAGE")
                return EXIT_USAGE
            end
            value = args[i]
            if a == "--tpc"
                if !(value in ("first", "only"))
                    println(stderr, "xrdcp: --tpc takes first or only\n$USAGE")
                    return EXIT_USAGE
                end
                tpc = Symbol(value)
            else
                creds[Symbol(a[3:end])] = value
            end
        elseif a == "--version"
            println("xrdcp (XRootD.jl) — Julia port of libxrdc's xrdcp")
            return EXIT_OK
        elseif startswith(a, "-")
            println(stderr, "xrdcp: unknown option $a\n$USAGE")
            return EXIT_USAGE
        else
            push!(positional, a)
        end
        i += 1
    end
    if length(positional) != 2
        println(stderr, USAGE)
        return EXIT_USAGE
    end
    src, dst = positional
    ok, msg = if recursive
        copytree(src, dst; force, verify, creds...)
    else
        copyfile(src, dst; force, verify, tpc, creds...)
    end
    if ok
        return EXIT_OK
    else
        println(stderr, "xrdcp: $msg")
        return EXIT_ERROR
    end
end

end # module Xrdcp
