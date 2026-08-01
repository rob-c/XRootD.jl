# What a failing server does to a caller. Every operation in this client
# returns `(status, result)`, so an error is not an exception to be caught
# somewhere else — it is a value that has to carry the server's code and
# message intact, on every surface, whatever shape the `kXR_error` body
# arrived in.
#
# The bodies here are the ones a real server sends: NUL-terminated and not,
# empty, truncated, and with a code the client has never heard of. A client
# that guesses at any of them tells its caller a story the server did not.

using XRootD.XrdCl
using XRootD.XrdCl: statvfs, checksum, prepare, symlink, readlink, hardlink
using XRootD: Wire

"The code a stock server answers with for a path that is not there."
const IE_NOTFOUND = 3011

@testset "conformance: what a failing server tells the caller" begin
    srv, port = start_info_server()
    fs = info_fs(port)

    @testset "every filesystem surface reports the server's failure" begin
        # (name, call) — each is one request and one scripted error reply.
        cases = [
            ("stat", () -> stat(fs, "/p")),
            ("statvfs", () -> statvfs(fs, "/p")),
            ("readdir", () -> readdir(fs, "/p")),
            ("dirlist_stat", () -> XrdCl.dirlist_stat(fs, "/p")),
            ("locate", () -> locate(fs, "/p", 0)),
            ("query", () -> query(fs, QueryCode.Config, "sitename")),
            ("checksum", () -> checksum(fs, "/p")),
            ("mkdir", () -> mkdir(fs, "/p")),
            ("rmdir", () -> rmdir(fs, "/p")),
            ("rm", () -> rm(fs, "/p")),
            ("mv", () -> mv(fs, "/a", "/b")),
            ("chmod", () -> chmod(fs, "/p", 0o755)),
            ("truncate", () -> truncate(fs, "/p", 0)),
            ("ping", () -> ping(fs)),
            ("protocol", () -> protocol(fs)),
            ("prepare", () -> prepare(fs, ["/p"])),
            ("symlink", () -> symlink(fs, "/a", "/b")),
            ("hardlink", () -> hardlink(fs, "/a", "/b")),
            ("readlink", () -> readlink(fs, "/p")),
            ("getxattr", () -> getxattr(fs, "/p", "k")),
            ("setxattr", () -> setxattr(fs, "/p", "k", Vector{UInt8}("v"))),
            ("listxattr", () -> listxattr(fs, "/p")),
            ("removexattr", () -> removexattr(fs, "/p", "k")),
        ]
        for (name, call) in cases
            info_reset!(srv)
            info_error!(srv, IE_NOTFOUND, "no such file or directory")
            st, result = call()
            @test isError(st)
            @test st.code == IE_NOTFOUND
            @test st.message == "no such file or directory"
            # A failed call has no result to hand back — never a partial one.
            @test result === nothing || isempty(result)
            @test length(srv.ops) == 1                  # asked once, told once
            @test isempty(srv.violations)
        end
    end

    @testset "the code the server sent is the code the caller sees" begin
        # The client does not translate the server's numbering, because a
        # caller that special-cases a code has to see the one that arrived.
        for code in (0, 1, 3000, 3010, IE_NOTFOUND, 3016, 3019, 9999, 65535)
            info_reset!(srv)
            info_error!(srv, code, "code $code")
            st, _ = stat(fs, "/p")
            @test isError(st)
            @test st.code == code
            @test st.message == "code $code"
        end

        # An errnum wider than the field it is read into is still an error,
        # and still carries its message.
        info_reset!(srv)
        info_error!(srv, -1, "negative code")
        st, _ = stat(fs, "/p")
        @test isError(st) && st.message == "negative code"
    end

    @testset "an error body is read the way it arrives, not the way it should" begin
        # Terminated, unterminated, empty, and padded: all four are on the wire.
        for (label, nul) in [("NUL-terminated", true), ("bare", false)]
            info_reset!(srv)
            info_error!(srv, IE_NOTFOUND, "gone"; nul=nul)
            st, _ = stat(fs, "/p")
            @test isError(st) && st.message == "gone"
        end

        # A code with no message at all: the caller still learns which code.
        info_reset!(srv)
        info_error!(srv, IE_NOTFOUND, "")
        st, _ = stat(fs, "/p")
        @test isError(st) && st.code == IE_NOTFOUND && isempty(st.message)

        # A message that is nothing but padding is an empty message.
        info_reset!(srv)
        srv.status = Wire.kXR_error
        srv.body = vcat(cs_be32(IE_NOTFOUND), zeros(UInt8, 8))
        st, _ = stat(fs, "/p")
        @test isError(st) && isempty(st.message)

        # A body too short to hold a code is not decoded into one.
        info_reset!(srv)
        srv.status = Wire.kXR_error
        srv.body = UInt8[0x00, 0x0b]
        st, _ = stat(fs, "/p")
        @test isError(st) && st.code == 0x0000
        @test occursin("unexpected response status", st.message)

        # An embedded NUL ends the message: the bytes past it are padding.
        info_reset!(srv)
        srv.status = Wire.kXR_error
        srv.body = vcat(cs_be32(IE_NOTFOUND), Vector{UInt8}(codeunits("gone\0junk")))
        st, _ = stat(fs, "/p")
        @test isError(st) && st.message == "gone"
        @test isempty(srv.violations)
    end

    @testset "a status the client has no meaning for is refused, not guessed at" begin
        for status in (UInt16(4008), UInt16(4999), UInt16(9), UInt16(65535))
            info_reset!(srv)
            srv.status = status
            srv.body = Vector{UInt8}(codeunits("something"))
            st, result = stat(fs, "/p")
            @test isError(st)
            @test occursin("unexpected response status $(status)", st.message)
            @test result === nothing
        end
        @test isempty(srv.violations)
    end

    @testset "a failed status prints the code and the message" begin
        st = XRootDStatus(Wire.kXR_error, UInt16(IE_NOTFOUND), 0, "no such file")
        text = sprint(show, st)
        @test occursin("ERROR", text)
        @test occursin(string(IE_NOTFOUND), text)
        @test occursin("no such file", text)
        @test !occursin("SUCCESS", text)
        # A success says so and says nothing else.
        @test sprint(show, XRootDStatus()) == "[SUCCESS]"
    end

    @testset "a file handle reports the failure at the operation that failed" begin
        # The open itself fails: the 0.2.x constructor answers with `nothing`,
        # and the handle form with the server's status.
        info_reset!(srv)
        info_error!(srv, IE_NOTFOUND, "no such file")
        @test File("root://127.0.0.1:$port//p") === nothing

        f = File()
        st, _ = open(f, "root://127.0.0.1:$port//p")
        @test isError(st) && st.code == IE_NOTFOUND && st.message == "no such file"
        @test !isopen(f)

        # An open that works, followed by a server that fails everything: the
        # handle stays open (the caller decides what to do), and each call
        # reports the failure it was given.
        info_reset!(srv)
        srv.status = Wire.kXR_ok
        srv.body = collect(CONF_FHANDLE)
        f = File()
        st, _ = open(f, "root://127.0.0.1:$port//p")
        @test isOK(st) && isopen(f)

        info_error!(srv, 3019, "checksum error")
        buf = Vector{UInt8}(undef, 4)
        for call in (
            () -> read(f, 4, 0),
            () -> write(f, "x"),
            () -> stat(f),
            () -> sync(f),
            () -> truncate(f, 0),
            () -> readv(f, [(0, 4)]),
            () -> writev(f, [(0, buf)]),
            () -> pgread(f, 4),
            () -> pgwrite(f, buf),
        )
            st, _ = call()
            @test isError(st) && st.code == 3019 && st.message == "checksum error"
        end
        @test isopen(f)

        # ... including the close, which still lets go of the handle: a client
        # that kept it would leak one every time a server failed a close.
        st, _ = close(f)
        @test isError(st) && st.code == 3019
        @test !isopen(f)
        @test isempty(srv.violations)
    end

    @testset "a read that fails part-way is not a short read" begin
        # readlines stops at the first failure rather than handing back the
        # lines it happened to get: a caller cannot tell those from the file.
        info_reset!(srv)
        srv.status = Wire.kXR_ok
        srv.body = collect(CONF_FHANDLE)
        f = File()
        st, _ = open(f, "root://127.0.0.1:$port//p")
        @test isOK(st)
        f.filesize = 100                        # the server told us nothing else

        info_error!(srv, 3007, "I/O error")
        st, lines = readlines(f)
        @test isError(st) && st.code == 3007
        @test lines === nothing

        st, line = readline(f)
        @test isError(st) && line === nothing
        close(f)
        @test isempty(srv.violations)
    end
end
