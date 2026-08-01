# The informational surfaces — locate, query, checksum, statvfs, protocol and
# the stat line itself — driven against a server that replies with bodies a
# stock XrdXrootd emits. The namespace server answers these too, but only in
# the one shape it happens to produce; a client is judged here on the whole
# range a real federation puts on the wire: pending locations, IPv6 addresses,
# multi-key config replies, the extended stat line, and the truncated or
# nonsensical versions of each.
#
# The other direction is checked from the same recordings: the infotype, flag
# word and argument text the client emitted for the call it was asked to make.

using XRootD.XrdCl
using XRootD.XrdCl: statvfs, checksum
using XRootD: Wire

"The stat flags for a plain, readable, writable file."
const IQ_FILE_FLAGS = Wire.kXR_readable | Wire.kXR_writable

@testset "conformance: locate, query and the stat surfaces" begin
    srv, port = start_info_server()
    fs = info_fs(port)

    @testset "a locate reply is parsed token by token" begin
        info_reset!(srv)
        info_reply!(srv, "Sr127.0.0.1:1094 Mw127.0.0.2:1094")
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && length(locs) == 2
        @test locs[1].address == "127.0.0.1:1094"
        @test locs[1].node == 'S' && locs[1].access == 'r'
        @test locs[2].address == "127.0.0.2:1094"
        @test locs[2].node == 'M' && locs[2].access == 'w'
        # `show` spells the token out for a human reading a listing.
        @test occursin("manager", sprint(show, locs[2]))
        @test occursin("read-write", sprint(show, locs[2]))

        # Lowercase is the same node type, not yet online: a client that
        # folded the case would report a pending replica as a live one.
        info_reply!(srv, "sr10.0.0.1:1094 mw10.0.0.2:1094")
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && [l.node for l in locs] == ['s', 'm']

        # An IPv6 address is bracketed, so the colon in it is not a separator.
        info_reply!(srv, "Sr[2001:db8::1]:1094")
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && length(locs) == 1
        @test locs[1].address == "[2001:db8::1]:1094"

        # A single token, sent without the trailing NUL some servers omit.
        info_reply!(srv, "Mwmanager.example:1213"; nul=false)
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && locs[1].address == "manager.example:1213"

        # A file no server holds locates to nowhere, which is not an error.
        info_reply!(srv, "")
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && isempty(locs)

        # ... and neither is the NUL padding some servers send instead.
        srv.body = zeros(UInt8, 4)
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && isempty(locs)

        info_reply!(srv, join(["Sr10.0.0.$i:1094" for i in 1:8], " "))
        st, locs = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && length(locs) == 8
        @test locs[8].address == "10.0.0.8:1094"
        @test isempty(srv.violations)
    end

    @testset "a locate reply the client cannot parse is an error, not a throw" begin
        info_reset!(srv)
        # A token is at least a type, an access mode and an address; anything
        # shorter names no replica, and one bad token spoils the list — a
        # client that dropped it would report a shorter list as a complete one.
        for text in ("X", "Sr", "Sr1.2.3.4:1094 Xy")
            info_reply!(srv, text)
            st, locs = locate(fs, "/data/a.txt", 0)
            @test isError(st) && locs === nothing
            @test occursin("malformed", st.message)
        end
        @test isempty(srv.violations)
    end

    @testset "locate puts the caller's flags on the wire and the path beside them" begin
        info_reset!(srv)
        info_reply!(srv, "Sr127.0.0.1:1094")
        # kXR_refresh | kXR_nowait as the reference client composes them: the
        # options are a u16 at byte 5, ahead of the reserved bytes.
        st, _ = locate(fs, "/data/a.txt?authz=t", 0x0005)
        @test isOK(st)
        @test srv.ops == [Wire.kXR_locate]
        @test info_u16(srv, 5) == 0x0005
        @test srv.args == ["/data/a.txt?authz=t"]

        st, _ = locate(fs, "/data/a.txt", 0)
        @test isOK(st) && info_u16(srv, 5) == 0x0000
        @test isempty(srv.violations)
    end

    @testset "every QueryCode is the number the protocol assigns it" begin
        info_reset!(srv)
        info_reply!(srv, "x")
        codes = [
            QueryCode.Stats => Wire.kXR_QStats,
            QueryCode.Prepare => Wire.kXR_QPrep,
            QueryCode.Checksum => Wire.kXR_Qcksum,
            QueryCode.XAttr => Wire.kXR_Qxattr,
            QueryCode.Space => Wire.kXR_Qspace,
            QueryCode.Config => Wire.kXR_Qconfig,
            QueryCode.Visa => Wire.kXR_Qvisa,
            QueryCode.Opaque => Wire.kXR_Qopaque,
            QueryCode.OpaqueFile => Wire.kXR_Qopaquf,
        ]
        for (code, wire) in codes
            st, _ = query(fs, code, "arg")
            @test isOK(st)
            @test info_u16(srv, 5) == wire
        end
        @test srv.ops == fill(Wire.kXR_query, length(codes))
        @test srv.args == fill("arg", length(codes))
        @test isempty(srv.violations)
    end

    @testset "query hands back the server's text, NUL stripped" begin
        info_reset!(srv)
        # kXR_Qconfig answers one line per keyword asked, in the order asked;
        # a keyword the server does not know is answered with a bare "0".
        info_reply!(srv, "server\nconformance\n0\n")
        st, cfg = query(fs, QueryCode.Config, "role sitename no.such.key")
        @test isOK(st)
        @test split(strip(cfg), '\n') == ["server", "conformance", "0"]
        @test srv.args == ["role sitename no.such.key"]

        # Values come back bare — there is no `key=` echo to strip.
        info_reply!(srv, "v5.2.0\n")
        st, cfg = query(fs, QueryCode.Config, "version")
        @test isOK(st) && strip(cfg) == "v5.2.0"

        info_reply!(srv, "adler32 crc32 md5\n")
        st, cfg = query(fs, QueryCode.Config, "chksum")
        @test isOK(st) && occursin("adler32", cfg)

        # The other codes are text of the server's choosing, handed through
        # whole: a client that "helpfully" parsed them would lose fields.
        info_reply!(srv, "oss.cgroup=public&oss.space=1024&oss.free=512&oss.used=512")
        st, sp = query(fs, QueryCode.Space, "/data")
        @test isOK(st) && count(==('&'), sp) == 3

        info_reply!(
            srv, "<statistics tod=\"1\" ver=\"v5.2.0\"><stats id=\"info\"/></statistics>"
        )
        st, stats = query(fs, QueryCode.Stats, "a")
        @test isOK(st) &&
            startswith(stats, "<statistics") &&
            endswith(stats, "</statistics>")

        # An empty reply is an empty string, not a missing value.
        info_reply!(srv, "")
        st, empty_reply = query(fs, QueryCode.Config, "role")
        @test isOK(st) && empty_reply == ""
        @test isempty(srv.violations)
    end

    @testset "checksum is a two-token line and the algorithm rides on the path" begin
        info_reset!(srv)
        info_reply!(srv, "adler32 062c0215")
        st, cks = checksum(fs, "/data/a.txt")
        @test isOK(st) && cks == "adler32 062c0215"
        @test length(split(cks)) == 2
        @test info_u16(srv, 5) == Wire.kXR_Qcksum

        # Selecting the algorithm is CGI on the path, so the client must pass
        # the path through untouched rather than trimming it to a filename.
        info_reply!(srv, "md5 5d41402abc4b2a76b9719d911017c592")
        st, cks = checksum(fs, "/data/a.txt?cks.type=md5")
        @test isOK(st) && split(cks)[1] == "md5"
        @test srv.args[end] == "/data/a.txt?cks.type=md5"

        # A digest the client did not ask for is still handed back: the
        # server picks the algorithm when the request names none.
        info_reply!(srv, "crc32c 00000000")
        st, cks = checksum(fs, "/data/a.txt")
        @test isOK(st) && cks == "crc32c 00000000"
        @test isempty(srv.violations)
    end

    @testset "statvfs reads the oss space report" begin
        info_reset!(srv)
        # The report is six numbers: nodes, free KB and utilization for the
        # read-write area, then the same three for the staging area.
        info_reply!(srv, "2 1024 50 1 2048 25")
        st, vfs = statvfs(fs, "/data")
        @test isOK(st)
        @test vfs.nodes == 2 && vfs.free_kb == 1024 && vfs.utilization == 50
        @test length(split(vfs.raw)) == 6

        # kXR_vfs is an option byte on kXR_stat, and the path is the payload.
        @test srv.ops == [Wire.kXR_stat]
        @test srv.frames[end][5] == Wire.kXR_vfs
        @test srv.args == ["/data"]

        # A shorter report is not a malformed one: the fields that are there
        # are parsed and the rest are absent.
        info_reply!(srv, "7 512")
        st, vfs = statvfs(fs, "/data")
        @test isOK(st) && vfs.nodes == 7 && vfs.free_kb == 512
        @test vfs.utilization === nothing

        # Nor is a report that is not numbers at all — the raw text survives
        # so a caller can look at what the server actually said.
        info_reply!(srv, "oss.space=1024")
        st, vfs = statvfs(fs, "/data")
        @test isOK(st) && vfs.nodes === nothing && vfs.raw == "oss.space=1024"
        @test isempty(srv.violations)
    end

    @testset "the stat line's extended form fills the extended fields" begin
        info_reset!(srv)
        # The four-field form is all a server has to send.
        info_reply!(srv, "1234 4096 $(IQ_FILE_FLAGS) 1700000000")
        st, si = stat(fs, "/data/a.txt")
        @test isOK(st)
        @test si.id == "1234" && si.size == 4096 && si.modtime == 1700000000
        @test si.ctime == 0 && si.atime == 0
        @test si.mode == "" && si.octmode == "" && si.owner == "" && si.group == ""

        # The extended form (stat_line.h) appends ctime, atime, the octal
        # mode, owner and group.
        info_reply!(
            srv,
            "1234 4096 $(IQ_FILE_FLAGS) 1700000000 1690000000 1695000000 0644 root wheel",
        )
        st, si = stat(fs, "/data/a.txt")
        @test isOK(st)
        @test si.ctime == 1690000000 && si.atime == 1695000000
        @test si.mode == "0644" && si.octmode == "rw-r--r--"
        @test si.owner == "root" && si.group == "wheel"

        # The symbolic form is derived from the octal one, triad by triad.
        for (octal, symbolic) in
            ("0751" => "rwxr-x--x", "0000" => "---------", "0777" => "rwxrwxrwx")
            info_reply!(srv, "1 0 0 0 0 0 $octal u g")
            st, si = stat(fs, "/data/a.txt")
            @test isOK(st) && si.octmode == symbolic
        end

        # An id is whatever the server calls the file — it is not a number to
        # the client, and a 64-bit device/inode composition must survive.
        info_reply!(srv, "18446744073709551615 0 0 0")
        st, si = stat(fs, "/data/a.txt")
        @test isOK(st) && si.id == "18446744073709551615"
        @test isempty(srv.violations)
    end

    @testset "the stat flag bits are what the predicates read" begin
        info_reset!(srv)
        # Each case is the flag word a server can set and what every predicate
        # must then say about it: (flags, dir, file, readable, writable,
        # executable, offline). `kXR_other` is neither a file nor a directory —
        # a client that read "not a directory" as "a file" would call a socket
        # one.
        searchable_dir = Wire.kXR_isDir | Wire.kXR_readable | Wire.kXR_xset
        cases = [
            (UInt32(0), false, true, false, false, false, false),
            (Wire.kXR_isDir, true, false, false, false, false, false),
            (Wire.kXR_other, false, false, false, false, false, false),
            (Wire.kXR_readable, false, true, true, false, false, false),
            (Wire.kXR_writable, false, true, false, true, false, false),
            (Wire.kXR_xset, false, true, false, false, true, false),
            (Wire.kXR_offline, false, true, false, false, false, true),
            (searchable_dir, true, false, true, false, true, false),
        ]
        for (flags, isd, isf, r, w, x, off) in cases
            info_reply!(srv, "1 0 $(flags) 0")
            st, si = stat(fs, "/data/a.txt")
            @test isOK(st) && si.flags == flags
            @test isdir(si) == isd
            @test isfile(si) == isf
            @test isreadable(si) == r
            @test iswritable(si) == w
            @test XrdCl.isExecutable(si) == x
            @test XrdCl.isOffline(si) == off
        end
        @test isempty(srv.violations)
    end

    @testset "a stat line the client cannot parse is an error, not a throw" begin
        info_reset!(srv)
        for text in ("", "1 2 3", "a b c d", "1 2 3 x", "1 nine 3 4")
            info_reply!(srv, text)
            st, si = stat(fs, "/data/a.txt")
            @test isError(st) && si === nothing
            @test occursin("malformed", st.message)
        end
        @test isempty(srv.violations)
    end

    @testset "a listing is names, and dstat pairs each with a stat line" begin
        info_reset!(srv)
        # A name is a whole line: spaces, dots and colons are part of it, and
        # a client that split on whitespace would invent entries.
        info_reply!(srv, "a b.txt\n.hidden\nrun:2024\n")
        st, names = readdir(fs, "/data")
        @test isOK(st) && names == ["a b.txt", ".hidden", "run:2024"]
        @test srv.frames[end][20] == 0x00       # no kXR_dstat was asked for

        # The trailing newline is a separator, not a terminator.
        info_reply!(srv, "only.txt")
        st, names = readdir(fs, "/data")
        @test isOK(st) && names == ["only.txt"]

        # An empty directory lists nothing, which is not an error.
        srv.body = zeros(UInt8, 1)
        st, names = readdir(fs, "/data")
        @test isOK(st) && isempty(names)

        # `join` prefixes the directory the caller named; `sort` orders what
        # the server sent, which is under no obligation to be sorted.
        info_reply!(srv, "c.txt\na.txt\nb.txt\n")
        st, names = readdir(fs, "/data"; sort=true)
        @test isOK(st) && names == ["a.txt", "b.txt", "c.txt"]
        st, names = readdir(fs, "/data"; join=true)
        @test isOK(st) && names[1] == "/data/c.txt"

        # dstat: the sentinel, then name/stat-line pairs — here in the
        # extended form, so the mode and owner arrive with the listing.
        info_reply!(
            srv,
            ".\n0 0 0 0\n" *
            "a.txt\n1 5 $(IQ_FILE_FLAGS) 1700000000 1 2 0644 root wheel\n" *
            "sub\n2 0 $(Wire.kXR_isDir) 1700000000 1 2 0755 root wheel\n",
        )
        st, names, stats = XrdCl.dirlist_stat(fs, "/data")
        @test isOK(st) && names == ["a.txt", "sub"]
        @test srv.frames[end][20] == Wire.kXR_dstat
        @test stats[1].size == 5 && isfile(stats[1]) && stats[1].octmode == "rw-r--r--"
        @test stats[2].size == 0 && isdir(stats[2]) && stats[2].owner == "root"

        # The same reply through `readdir` is just the names: the stat lines
        # must not leak into the list.
        info_reply!(
            srv,
            ".\n0 0 0 0\na.txt\n1 5 $(IQ_FILE_FLAGS) 1700000000\nsub\n2 0 2 1700000000\n",
        )
        st, names = readdir(fs, "/data", DirListFlags.Stat)
        @test isOK(st) && names == ["a.txt", "sub"]
        @test isempty(srv.violations)
    end

    @testset "kXR_protocol reports the server's version and flags" begin
        info_reset!(srv)
        srv.status = Wire.kXR_ok
        srv.body = vcat(cs_be32(0x520), cs_be32(0x0100))
        st, p = protocol(fs)
        @test isOK(st) && p.version == 0x520 && p.hostinfo == 0x0100
        @test occursin("5.2.0", sprint(show, p))

        # Eight bytes is the whole record; anything shorter names no version.
        srv.body = cs_be32(0x520)
        st, p = protocol(fs)
        @test isError(st) && p === nothing && occursin("malformed", st.message)
        @test isempty(srv.violations)
    end

    @testset "an error reply carries the server's code and message" begin
        info_reset!(srv)
        # kXR_error bodies are `[errnum i32][text]`; every surface here reads
        # the same encoding, so one operation of each shape is enough.
        srv.status = Wire.kXR_error
        srv.body = vcat(
            cs_be32(3011), Vector{UInt8}(codeunits("no such file or directory"))
        )
        for call in (
            () -> stat(fs, "/nope"),
            () -> locate(fs, "/nope", 0),
            () -> statvfs(fs, "/nope"),
            () -> checksum(fs, "/nope"),
            () -> query(fs, QueryCode.Config, "role"),
        )
            st, value = call()
            @test isError(st) && value === nothing
            @test st.code == 3011
            @test occursin("no such file or directory", st.message)
        end
        srv.status = Wire.kXR_ok
        @test isempty(srv.violations)
    end
end
