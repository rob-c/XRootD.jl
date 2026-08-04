# xrdfs — filesystem operations against a root:// host, plus an interactive
# shell when no command is given.

module Xrdfs

using ..XrdCl
using ..Tools: EXIT_OK, EXIT_USAGE, EXIT_ERROR

const USAGE = "usage: xrdfs <host> [command args...]   (no command → interactive shell)"

"""
    main(args::Vector{String}) -> Int

`xrdfs <host> <command> [args]`. Commands: `ls`, `stat`, `statx`, `locate`,
`mkdir`, `touch`, `rm` (`-r` to recurse), `rmdir`, `mv`, `chmod`,
`truncate`, `cat`, `checksum`, `prepare`, `xattr`, `query`, `statvfs`.
With only a host, starts an interactive shell reading commands from stdin.
"""
function main(args::Vector{String})
    isempty(args) && (println(stderr, USAGE); return EXIT_USAGE)
    host = args[1]
    base = startswith(host, "root") ? host : "root://$host"
    fs = XrdCl.FileSystem(base)
    if length(args) == 1
        return shell(fs)
    end
    return run_command(fs, args[2], args[3:end])
end

function run_command(fs::XrdCl.FileSystem, cmd::AbstractString, rest::Vector{String})
    if cmd == "ls"
        path = isempty(rest) ? "/" : rest[1]
        st, entries = readdir(fs, path; sort=true)
        (XrdCl.isOK(st) && entries !== nothing) || return report(st)
        for e in entries
            println(e)
        end
        return EXIT_OK
    elseif cmd == "stat"
        isempty(rest) && return usage_err()
        st, info = stat(fs, rest[1])
        (XrdCl.isOK(st) && info !== nothing) || return report(st)
        println("size=$(info.size) flags=$(info.flags) mtime=$(info.modtime)")
        return EXIT_OK
    elseif cmd == "statx"
        isempty(rest) && return usage_err()
        st, flags = XrdCl.statx(fs, rest)
        (XrdCl.isOK(st) && flags !== nothing) || return report(st)
        for (path, fl) in zip(rest, flags)
            println("$path $fl")
        end
        return EXIT_OK
    elseif cmd == "locate"
        isempty(rest) && return usage_err()
        st, locs = locate(fs, rest[1], XrdCl.OpenFlags.None)
        (XrdCl.isOK(st) && locs !== nothing) || return report(st)
        for l in locs
            println(l)
        end
        return EXIT_OK
    elseif cmd == "mkdir"
        isempty(rest) && return usage_err()
        # -p is the protocol's own kXR_mkdirpath, not a walk of the path.
        recurse, paths = take_flag(rest, "-p")
        isempty(paths) && return usage_err()
        return report(first(recurse ? mkpath(fs, paths[1]) : mkdir(fs, paths[1])))
    elseif cmd == "touch"
        isempty(rest) && return usage_err()
        return report(first(touch(fs, rest[1])))
    elseif cmd == "rm"
        recursive, paths = take_flag(rest, "-r")
        isempty(paths) && return usage_err()
        return report(first(rm(fs, paths[1]; recursive=recursive)))
    elseif cmd == "chmod"
        length(rest) == 2 || return usage_err()
        mode = tryparse(UInt16, rest[2]; base=8)
        mode === nothing && return usage_err()
        return report(first(chmod(fs, rest[1], mode)))
    elseif cmd == "truncate"
        length(rest) == 2 || return usage_err()
        size = tryparse(Int64, rest[2])
        size === nothing && return usage_err()
        return report(first(truncate(fs, rest[1], size)))
    elseif cmd == "checksum"
        isempty(rest) && return usage_err()
        algorithm = length(rest) >= 2 ? rest[2] : ""
        st, cks = XrdCl.checksum(fs, rest[1]; algorithm=algorithm)
        (XrdCl.isOK(st) && cks !== nothing) || return report(st)
        println(cks)
        return EXIT_OK
    elseif cmd == "prepare"
        evicting, paths = take_flag(rest, "-e")
        isempty(paths) && return usage_err()
        st, handle = evicting ? XrdCl.evict(fs, paths) : XrdCl.prepare(fs, paths)
        (XrdCl.isOK(st) && handle !== nothing) || return report(st)
        println(handle)
        return EXIT_OK
    elseif cmd == "xattr"
        return xattr_command(fs, rest)
    elseif cmd == "rmdir"
        isempty(rest) && return usage_err()
        return report(first(rmdir(fs, rest[1])))
    elseif cmd == "mv"
        length(rest) == 2 || return usage_err()
        return report(first(mv(fs, rest[1], rest[2])))
    elseif cmd == "cat"
        isempty(rest) && return usage_err()
        return cat_file(fs, rest[1])
    elseif cmd == "statvfs"
        isempty(rest) && return usage_err()
        st, vfs = XrdCl.statvfs(fs, rest[1])
        (XrdCl.isOK(st) && vfs !== nothing) || return report(st)
        println(vfs.raw)
        return EXIT_OK
    elseif cmd == "query"
        length(rest) == 2 || return usage_err()
        code = getproperty(XrdCl.QueryCode, Symbol(rest[1]))
        st, resp = query(fs, code, rest[2])
        (XrdCl.isOK(st) && resp !== nothing) || return report(st)
        println(resp)
        return EXIT_OK
    else
        println(stderr, "xrdfs: unknown command $cmd")
        return EXIT_USAGE
    end
end

function cat_file(fs::XrdCl.FileSystem, path::AbstractString)
    # root://host:port  +  //path  →  the File URL convention
    url = "root://$(fs.host):$(fs.port)/" * (startswith(path, "/") ? path : "/" * path)
    f = XrdCl.File(String(url))
    f === nothing && (println(stderr, "xrdfs: cannot open $path"); return EXIT_ERROR)
    try
        st, info = stat(f)
        (XrdCl.isOK(st) && info !== nothing) || return report(st)
        st, data = read(f, info.size, 0)
        (XrdCl.isOK(st) && data !== nothing) || return report(st)
        write(stdout, data)
        return EXIT_OK
    finally
        close(f)
    end
end

"""
`xattr <path> list|get|set|rm [args]` — the four `kXR_fattr` subcodes. `list`
prints one attribute per line, `get` prints the value of one, and `set`/`rm`
report only whether they worked.
"""
function xattr_command(fs::XrdCl.FileSystem, rest::Vector{String})
    length(rest) >= 2 || return usage_err()
    path, action = rest[1], rest[2]
    if action == "list"
        st, names = XrdCl.listxattr(fs, path)
        (XrdCl.isOK(st) && names !== nothing) || return report(st)
        for name in names
            println(name)
        end
        return EXIT_OK
    elseif action == "get"
        length(rest) == 3 || return usage_err()
        st, value = XrdCl.getxattr(fs, path, rest[3])
        (XrdCl.isOK(st) && value !== nothing) || return report(st)
        write(stdout, value)
        println()
        return EXIT_OK
    elseif action == "set"
        length(rest) == 4 || return usage_err()
        return report(first(XrdCl.setxattr(fs, path, rest[3], Vector{UInt8}(rest[4]))))
    elseif action == "rm"
        length(rest) == 3 || return usage_err()
        return report(first(XrdCl.removexattr(fs, path, rest[3])))
    end
    println(stderr, "xrdfs: unknown xattr action $action")
    return EXIT_USAGE
end

"Split a leading option flag off an argument list: `(present, remaining)`."
function take_flag(rest::Vector{String}, flag::AbstractString)
    !isempty(rest) && rest[1] == flag && return true, rest[2:end]
    return false, rest
end

usage_err() = (println(stderr, "xrdfs: missing argument"); EXIT_USAGE)
report(st) = XrdCl.isOK(st) ? EXIT_OK : (println(stderr, "xrdfs: $st"); EXIT_ERROR)

"Interactive command loop (reads lines from stdin until EOF or `exit`)."
function shell(fs::XrdCl.FileSystem)
    while true
        print("xrdfs> ")
        line = readline(stdin)
        # Only an empty read means end of input: a piped script whose last
        # line is a command must still see that command run.
        if isempty(line)
            eof(stdin) && break
            continue
        end
        strip(line) in ("exit", "quit") && break
        parts = split(strip(line))
        isempty(parts) && continue
        run_command(fs, parts[1], String.(parts[2:end]))
    end
    return EXIT_OK
end

end # module Xrdfs
