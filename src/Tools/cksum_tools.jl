# The checksum command-line tools: xrdadler32 / xrdcrc32c / xrdcrc64, and
# xrdckverify. Each exposes main(args)::Int; the bin/ launchers call these.

module Cksum

using ..Tools: checksum_file, EXIT_OK, EXIT_USAGE, EXIT_ERROR
using ..XrdCl

"Shared driver: print `<digest> <target>` for each argument."
function digest_main(toolname::AbstractString, algo::Symbol, args::Vector{String})
    if isempty(args) || args[1] == "--version"
        if !isempty(args) && args[1] == "--version"
            println("$toolname (XRootD.jl) — Julia port of libxrdc's $toolname")
            return EXIT_OK
        end
        println(stderr, "usage: $toolname <path-or-url> ...")
        return EXIT_USAGE
    end
    rc = EXIT_OK
    for target in args
        digest = try
            checksum_file(target, algo)
        catch err
            println(stderr, "$toolname: $target: $(sprint(showerror, err))")
            rc = EXIT_ERROR
            continue
        end
        println("$digest $target")
    end
    return rc
end

adler32_main(args::Vector{String}) = digest_main("xrdadler32", :adler32, args)
crc32c_main(args::Vector{String}) = digest_main("xrdcrc32c", :crc32c, args)
crc64_main(args::Vector{String}) = digest_main("xrdcrc64", :crc64, args)

"""
    ckverify_main(args) -> Int

`xrdckverify <path-or-url> <algo> <expected-hex>`: recompute and compare.
Exit 0 on match, 1 on mismatch/error, 2 on usage.
"""
function ckverify_main(args::Vector{String})
    if length(args) == 1 && args[1] == "--version"
        println("xrdckverify (XRootD.jl) — Julia port of libxrdc's xrdckverify")
        return EXIT_OK
    end
    length(args) == 3 || (
        println(stderr, "usage: xrdckverify <path-or-url> <algo> <expected>");
        return EXIT_USAGE
    )
    target, algo, expected = args
    digest = try
        checksum_file(target, Symbol(algo))
    catch err
        println(stderr, "xrdckverify: $(sprint(showerror, err))")
        return EXIT_ERROR
    end
    if lowercase(digest) == lowercase(expected)
        println("OK $target $digest")
        return EXIT_OK
    else
        println(stderr, "MISMATCH $target: got $digest, expected $expected")
        return EXIT_ERROR
    end
end

end # module Cksum
