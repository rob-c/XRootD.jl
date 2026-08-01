# The whole client surface driven against a server that answers every request
# with garbage. Nothing here checks a result: the contract under test is that
# every call comes back — with a status, in bounded time, without throwing —
# no matter what the peer says. A client that throws out of `stat` because a
# server sent 33 bytes of 0xff has handed a remote peer the ability to crash
# any program using it.
#
# The body matrix straddles every fixed-size record in the protocol and
# includes length prefixes that promise more data than follows; see
# [`hostile_bodies`](@ref).

using XRootD.XrdCl
using XRootD.XrdCl: statvfs, checksum, prepare
# The vendor link operations are XrdCl functions of their own, not Base
# methods: name them explicitly so they do not resolve to Base's.
using XRootD.XrdCl: symlink, hardlink, readlink
using XRootD: Wire

"""
Every FileSystem call that decodes a reply, as `(name, call, wants_value)`.
`wants_value` marks the calls that must produce a result when they report
success — a status of OK with a `nothing` result is a lie the caller cannot
detect.
"""
function hostile_ops(fs::XrdCl.FileSystem, url::AbstractString)
    xattr = Vector{UInt8}("v")
    return [
        ("ping", () -> ping(fs), false),
        ("stat", () -> stat(fs, "/f"), true),
        ("statvfs", () -> statvfs(fs, "/"), true),
        ("dirlist", () -> readdir(fs, "/d"), true),
        ("dirlist-stat", () -> readdir(fs, "/d", DirListFlags.Stat), true),
        ("mkdir", () -> mkdir(fs, "/d"), false),
        ("rmdir", () -> rmdir(fs, "/d"), false),
        ("rm", () -> rm(fs, "/f"), false),
        ("mv", () -> mv(fs, "/a", "/b"), false),
        ("chmod", () -> chmod(fs, "/f", 0o600), false),
        ("truncate", () -> truncate(fs, "/f", Int64(0)), false),
        ("locate", () -> locate(fs, "/f", 0), true),
        ("query", () -> query(fs, QueryCode.Config, "version"), true),
        ("checksum", () -> checksum(fs, "/f"), true),
        ("protocol", () -> protocol(fs), true),
        ("prepare", () -> prepare(fs, ["/f"]), true),
        ("symlink", () -> symlink(fs, "/f", "/l"), false),
        ("hardlink", () -> hardlink(fs, "/f", "/h"), false),
        ("readlink", () -> readlink(fs, "/l"), true),
        ("listxattr", () -> listxattr(fs, "/f"), true),
        ("getxattr", () -> getxattr(fs, "/f", "user.a"), true),
        ("setxattr", () -> setxattr(fs, "/f", "user.a", xattr), false),
        ("removexattr", () -> removexattr(fs, "/f", "user.a"), false),
        ("open", () -> hostile_open(url), false),
    ]
end

"Open a file and close it again, reporting the open's status."
function hostile_open(url::AbstractString)
    f = XrdCl.File()
    st, _ = open(f, url, OpenFlags.Read)
    isopen(f) && close(f)
    return st, nothing
end

@testset "conformance: a server that answers with garbage" begin
    srv, port = start_hostile()
    url = "root://127.0.0.1:$port//f"
    bodies = hostile_bodies()

    # A whole-operation deadline, so a call that never comes back fails the
    # test instead of hanging it, and a short retry window, so a garbage error
    # body that happens to read as a lost link is not retried for 30 seconds.
    withenv(
        "XRDC_STALL_DEADLINE_MS" => string(CONF_STALL_MS), "XRDC_MAX_STALL_MS" => "500"
    ) do
        for (label, status) in (
            "ok" => Wire.kXR_ok, "error" => Wire.kXR_error, "authmore" => Wire.kXR_authmore
        )
            @testset "every call survives a $label reply with any body" begin
                srv.status = status
                fs = XrdCl.FileSystem("root://127.0.0.1:$port")
                for (i, body) in enumerate(bodies)
                    srv.body = body
                    for (name, call, wants_value) in hostile_ops(fs, url)
                        st, result = try
                            call()
                        catch err
                            # Report which case escaped rather than aborting
                            # the whole matrix on the first one.
                            (err, nothing)
                        end
                        ok =
                            st isa XRootDStatus &&
                            (!wants_value || isError(st) || result !== nothing)
                        ok || @info "hostile $label/$name/body-$i" st result
                        @test ok
                    end
                end
            end
        end
    end

    @testset "the garbage reached the client through the wire, not a local check" begin
        # Every operation above was actually sent: none of them were refused
        # by an argument check before the reply could be decoded.
        @test length(srv.ops) > 3 * length(bodies) * 20
        @test Wire.kXR_open in srv.ops
        @test isempty(srv.violations)
    end
end
