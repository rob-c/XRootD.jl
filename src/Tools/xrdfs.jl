# xrdfs — filesystem operations against a root:// host, plus an interactive
# shell when no command is given.

module Xrdfs

using ..XrdCl
using ..Tools: EXIT_OK, EXIT_USAGE, EXIT_ERROR

const USAGE = "usage: xrdfs <host> [command args...]   (no command → interactive shell)"

"""
    main(args::Vector{String}) -> Int

`xrdfs <host> <command> [args]`. Commands: `ls`, `stat`, `mkdir`, `rm`,
`rmdir`, `mv`, `cat`, `query`, `statvfs`. With only a host, starts an
interactive shell reading commands from stdin.
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
    elseif cmd == "mkdir"
        isempty(rest) && return usage_err()
        return report(first(mkdir(fs, rest[1])))
    elseif cmd == "rm"
        isempty(rest) && return usage_err()
        return report(first(rm(fs, rest[1])))
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

usage_err() = (println(stderr, "xrdfs: missing argument"); EXIT_USAGE)
report(st) = XrdCl.isOK(st) ? EXIT_OK : (println(stderr, "xrdfs: $st"); EXIT_ERROR)

"Interactive command loop (reads lines from stdin until EOF or `exit`)."
function shell(fs::XrdCl.FileSystem)
    while true
        print("xrdfs> ")
        line = readline(stdin)
        isempty(line) && !eof(stdin) && continue
        (eof(stdin) || strip(line) == "exit" || strip(line) == "quit") && break
        parts = split(strip(line))
        isempty(parts) && continue
        run_command(fs, parts[1], String.(parts[2:end]))
    end
    return EXIT_OK
end

end # module Xrdfs
