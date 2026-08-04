# The everyday API, driven against the local backend: path algebra, the verbs
# `Base` already names, the listing and error rendering a person reads, and the
# keyword resolution that decides what a bare `download(url)` actually does.
#
# The same verbs over `root://` are in test/conformance/test_api.jl — this file
# is where the parts that do not depend on a protocol are pinned down.

using XRootD: StoragePath, StorageError, @xrd_str
using XRootD.Storage: StorageInfo

"The `text/plain` rendering of `x`, as the REPL and a notebook would show it."
function api_show(x; limit::Bool=false)
    return sprint(show, MIME("text/plain"), x; context=:limit => limit)
end

@testset "the everyday API" begin
    @testset "a path is a URL you can hold" begin
        p = StoragePath("root://host:1094//data/a.root")
        @test p.url == "root://host:1094//data/a.root"
        @test p.opts == NamedTuple()
        @test string(p) == p.url
        @test sprint(print, p) == p.url
        @test sprint(show, p) == "xrd\"root://host:1094//data/a.root\""

        # `path` is the seam every verb goes through: a string becomes a path,
        # a path is itself, and new credentials copy rather than mutate.
        @test XRootD.path(p) === p
        @test XRootD.path("root://host//x") isa StoragePath
        withtok = XRootD.path(p; token="t")
        @test withtok !== p && withtok.opts.token == "t" && p.opts == NamedTuple()
        @test XRootD.path(withtok; token="u").opts.token == "u"

        # Equality is the URL *and* the credentials: two paths to one object
        # under different tokens are not interchangeable.
        @test StoragePath("root://h//x") == StoragePath("root://h//x")
        @test StoragePath("root://h//x"; token="a") != StoragePath("root://h//x")
        @test hash(StoragePath("root://h//x")) == hash(StoragePath("root://h//x"))
        @test length(Set([StoragePath("root://h//x"), StoragePath("root://h//x")])) == 1

        # A secret in the URL is not printed, and `print` is the escape hatch
        # for the times you need the URL itself.
        secret = StoragePath("https://host/f?authz=Bearer%20abc")
        @test !occursin("abc", sprint(show, secret))
        @test occursin("abc", sprint(print, secret))
    end

    @testset "a misspelled credential is caught where it was written" begin
        err = try
            StoragePath("root://h//x"; tokne="oops")
        catch e
            e
        end
        @test err isa ArgumentError
        @test occursin("unknown option `tokne`", err.msg)
        # The message lists what it should have been.
        @test occursin("token", err.msg) && occursin("cert", err.msg)

        @test StoragePath("root://h//x"; token="t", insecure_tls=true).opts.insecure_tls
        @test_throws ArgumentError XRootD.ls("/tmp"; nosuchthing=1)
    end

    @testset "the xrd\"…\" literal" begin
        f = xrd"root://eos.example//eos/data.root"
        @test f isa StoragePath
        @test f.url == "root://eos.example//eos/data.root"

        # A run number in a path is the normal case, so interpolation works as
        # it does in any other string.
        run = "Run2012B"
        n = 7
        @test xrd"root://h//$run/run$n.root".url == "root://h//Run2012B/run7.root"
        @test xrd"/tmp/$(n + 1).txt".url == "/tmp/8.txt"
        # A backslash is a backslash: the literal is not re-escaped behind you.
        @test xrd"root://h//a\b".url == "root://h//a\\b"
    end

    @testset "path algebra needs no endpoint" begin
        dir = xrd"root://host:1094//eos/opendata/cms"
        @test joinpath(dir, "Run2012B", "data.root").url ==
            "root://host:1094//eos/opendata/cms/Run2012B/data.root"
        @test joinpath(dir) === dir
        # Slashes on either side of the join do not double up.
        @test joinpath(xrd"root://h//a/", "/b").url == "root://h//a/b"
        # Credentials survive the descent; the backend does not.
        joined = joinpath(StoragePath("root://h//a"; token="t"), "b")
        @test joined.opts.token == "t"

        @test basename(dir) == "cms"
        @test basename(xrd"root://h//a/b/") == "b"
        @test basename(xrd"/tmp/x/data.root") == "data.root"
        # A signed URL still names the object it names.
        @test basename(xrd"https://host/data/f.root?authz=abc") == "f.root"

        @test dirname(xrd"root://h//a/b/c").url == "root://h//a/b"
        @test dirname(xrd"root://h//a/b/").url == "root://h//a"
        @test dirname(xrd"/tmp/x/data.root").url == "/tmp/x"
        # The top of an endpoint is its own parent, as `dirname("/")` is `"/"`.
        @test dirname(xrd"root://h//a").url == "root://h/"
        @test dirname(xrd"root://h//").url == "root://h//"
        @test dirname(xrd"root://h").url == "root://h"
        @test dirname(xrd"/").url == "/"
    end

    @testset "sizes and times as a person says them" begin
        @test XRootD.human_size(0) == "0 B"
        @test XRootD.human_size(999) == "999 B"
        @test XRootD.human_size(1000) == "1.0 kB"
        @test XRootD.human_size(1536) == "1.5 kB"
        @test XRootD.human_size(45_000) == "45 kB"
        @test XRootD.human_size(4_200_000_000) == "4.2 GB"
        @test XRootD.human_size(3 * 10^15) == "3.0 PB"
        # Beyond the last unit it keeps counting rather than losing the number.
        @test XRootD.human_size(typemax(Int64)) == "9223 PB"

        @test XRootD.mtime_string(0) == "-"
        @test XRootD.mtime_string(-1) == "-"
        @test XRootD.mtime_string(1_700_000_000) == "2023-11-14 22:13"

        @test api_show(StorageInfo(Int64(1500), Int64(1_700_000_000), false)) ==
            "1.5 kB  2023-11-14 22:13"
        @test api_show(StorageInfo(Int64(0), Int64(1_700_000_000), true)) ==
            "directory  2023-11-14 22:13"
    end

    @testset "reading and browsing a local tree" begin
        root = mktempdir()
        write(joinpath(root, "a.txt"), "hello\nworld\n")
        write(joinpath(root, "b.bin"), rand(UInt8, 4096))
        mkpath(joinpath(root, "sub", "deep"))
        write(joinpath(root, "sub", "c.txt"), "third")
        write(joinpath(root, "sub", "deep", "d.txt"), "fourth")

        d = StoragePath(root)
        a = joinpath(d, "a.txt")

        @test isfile(a) && !isdir(a)
        @test isdir(d) && !isfile(d)
        @test ispath(a) && !ispath(joinpath(d, "nope"))
        @test filesize(a) == 12
        @test mtime(a) > 0
        @test stat(a) isa StorageInfo
        @test !stat(a).isdir

        # The string front doors answer the same questions without a path.
        @test XRootD.isfile(a.url) && !XRootD.isdir(a.url)
        @test XRootD.isdir(root) && XRootD.exists(root)
        @test !XRootD.exists(joinpath(root, "nope"))
        @test XRootD.filesize(a.url) == 12
        @test XRootD.info(a.url).size == 12

        listing = XRootD.ls(d)
        @test listing isa AbstractVector{XRootD.DirEntry}
        @test [e.name for e in listing] == ["a.txt", "b.bin", "sub"]
        @test [isdir(e) for e in listing] == [false, false, true]
        @test [isfile(e) for e in listing] == [true, true, false]
        @test filesize(listing[1]) == 12
        @test basename(listing[1]) == "a.txt"
        @test string(listing[3]) == joinpath(d, "sub").url
        # An entry carries a usable path, not just a name.
        @test read(listing[1].path, String) == "hello\nworld\n"

        @test readdir(d) == ["a.txt", "b.bin", "sub"]
        @test readdir(d; join=true) == [joinpath(d, n).url for n in readdir(d)]
        @test Set(readdir(d; sort=false)) == Set(readdir(d))

        # It prints as a listing, not as a wall of structs.
        out = api_show(listing)
        @test occursin(root, out)
        @test occursin("(3 entries)", out)
        @test occursin("sub/", out)          # directories wear their slash
        @test occursin("12 B", out)
        @test occursin("4.1 kB", out)
        @test sprint(show, listing) == "Listing($(repr(d.url)), 3 entries)"
        @test occursin("(1 entry)", api_show(XRootD.ls(joinpath(d, "sub", "deep"))))

        # A directory with more in it than anyone reads at once is capped in
        # the REPL and not when a program asks for the whole thing.
        many = StoragePath(mktempdir())
        for i in 1:50
            write(joinpath(many, "f$(lpad(i, 3, '0')).txt"), "x")
        end
        @test occursin("… and 10 more", api_show(XRootD.ls(many); limit=true))
        @test !occursin("more", api_show(XRootD.ls(many)))

        walked = collect(walkdir(d))
        @test [w[1].url for w in walked] == [d.url, joinpath(d, "sub").url, joinpath(d, "sub", "deep").url]
        @test walked[1][2] == ["sub"]
        @test walked[1][3] == ["a.txt", "b.bin"]
        @test walked[2][3] == ["c.txt"]
        @test Base.IteratorSize(walkdir(d)) == Base.SizeUnknown()
        # Bottom-up is the same walk, reversed.
        @test [w[1].url for w in walkdir(d; topdown=false)] == reverse([w[1].url for w in walked])
        # A walk that stops early has not listed the rest of the tree.
        @test first(walkdir(d))[1].url == d.url
    end

    @testset "reading a file" begin
        root = mktempdir()
        text = "hello\nworld\nagain\n"
        write(joinpath(root, "a.txt"), text)
        a = StoragePath(joinpath(root, "a.txt"))

        @test read(a) == Vector{UInt8}(text)
        @test read(a, String) == text
        @test read(a, 5) == Vector{UInt8}("hello")
        @test readlines(a) == ["hello", "world", "again"]
        @test readlines(a; keep=true)[1] == "hello\n"
        @test collect(eachline(a)) == ["hello", "world", "again"]
        @test collect(eachline(a; keep=true))[2] == "world\n"

        @test XRootD.read(a.url, String) == text
        @test XRootD.read(a.url) == Vector{UInt8}(text)
        @test XRootD.read(a.url; length=5) == Vector{UInt8}("hello")
        @test XRootD.read(a.url; offset=6, length=5) == Vector{UInt8}("world")
        @test XRootD.read(a.url; offset=6) == Vector{UInt8}("world\nagain\n")
        @test XRootD.read(a; length=5) == Vector{UInt8}("hello")

        # The stream is the point: hand it to anything that takes an `IO`.
        @test open(io -> read(io, String), a) == text
        @test open(a) do io
            seek(io, 6)
            return String(read(io, 5))
        end == "world"
        io = open(a)
        try
            @test read(io, 5) == Vector{UInt8}("hello")
        finally
            close(io)
        end

        @test XRootD.open(io -> read(io, String), a.url) == text
        @test XRootD.open(io -> countlines(io), a.url) == 3
        # `readlines` on the URL goes through the same stream.
        @test XRootD.open(readlines, a.url) == ["hello", "world", "again"]
        handle = XRootD.open(a.url, "r")
        try
            @test handle isa IO
        finally
            close(handle)
        end

        # A byte range that cannot exist is said so in those words, rather than
        # reaching the allocator as an enormous unsigned count.
        @test_throws ArgumentError XRootD.read(a.url; length=-5)
        @test_throws ArgumentError XRootD.read(a.url; offset=-1)
        @test_throws ArgumentError read(a, -1)
        # Past the end is not an error; there is simply nothing there.
        @test isempty(XRootD.read(a.url; offset=10_000))
    end

    @testset "writing output back" begin
        root = mktempdir()
        out = StoragePath(joinpath(root, "out.txt"))

        @test write(out, "42 events\n") == 10
        @test read(out, String) == "42 events\n"
        @test write(out, Vector{UInt8}("shorter")) == 7
        @test read(out, String) == "shorter"   # a write replaces, it does not append
        @test XRootD.write(out.url, "through the URL") == 15
        @test read(out.url, String) == "through the URL"

        # Something bigger than memory goes out through the stream.
        big = joinpath(root, "big.bin")
        payload = rand(UInt8, 300_000)
        XRootD.open(big, "w"; length=length(payload)) do io
            for chunk in Iterators.partition(payload, 65_536)
                write(io, chunk)
            end
        end
        @test read(big) == payload

        @test XRootD.mkdir(joinpath(root, "deep", "deeper")) isa StoragePath
        @test isdir(joinpath(root, "deep", "deeper"))
        # Already being there is success — this is called before writing.
        @test isdir(mkpath(StoragePath(joinpath(root, "deep"))))
        @test isdir(mkdir(StoragePath(joinpath(root, "other"))))
    end

    @testset "moving files" begin
        root = mktempdir()
        src = StoragePath(joinpath(root, "src.txt"))
        write(src, "payload")

        # cp keeps Base's refusal to clobber; XRootD.copy overwrites, because a
        # notebook cell that is run twice should not stop at the second run.
        dst = cp(src, joinpath(root, "dst.txt"))
        @test dst isa StoragePath
        @test read(dst, String) == "payload"
        @test_throws StorageError cp(src, dst)
        @test cp(src, dst; force=true) == dst
        @test XRootD.copy(src.url, dst.url) isa StoragePath

        # A destination that is a directory takes the source's own name.
        into = joinpath(root, "into")
        mkpath(into)
        @test cp(src, into).url == joinpath(into, "src.txt")
        @test isfile(joinpath(into, "src.txt"))

        landed = XRootD.download(src.url, mktempdir())
        @test landed isa String && endswith(landed, "src.txt")
        @test read(landed, String) == "payload"
        @test read(XRootD.download(src.url, joinpath(root, "named.txt")), String) ==
            "payload"

        up = XRootD.upload(src.url, joinpath(root, "up"))
        @test up isa StoragePath && read(up, String) == "payload"

        # A move within one endpoint is a rename; the source stops existing.
        moved = mv(src, joinpath(root, "moved.txt"))
        @test read(moved, String) == "payload"
        @test !ispath(src)
        @test read(XRootD.mv(moved.url, src.url), String) == "payload"
        @test_throws StorageError mv(src, dst)
        @test mv(src, dst; force=true) == dst

        @test rm(StoragePath(joinpath(root, "into", "src.txt"))) === nothing
        @test !ispath(StoragePath(joinpath(root, "into", "src.txt")))
        # A directory is not deleted by accident.
        @test_throws StorageError rm(StoragePath(into))
        @test rm(StoragePath(into); recursive=true) === nothing
        @test !ispath(StoragePath(into))
        # Deleting what is already gone is an error, unless it is forced.
        @test_throws StorageError XRootD.rm(joinpath(root, "gone.txt"))
        @test XRootD.rm(joinpath(root, "gone.txt"); force=true) === nothing
    end

    @testset "a copy onto itself is refused, not performed" begin
        # A copy truncates its destination before it reads its source, so this
        # is the one mistake that destroys the file it was asked to preserve.
        root = mktempdir()
        f = StoragePath(joinpath(root, "run7.root"))
        payload = "the only copy"
        write(f, payload)

        @test_throws StorageError XRootD.copy(f.url, f.url)
        @test read(f, String) == payload

        # The same object reached by a different name is still the same object.
        link = joinpath(root, "link.root")
        # `Base.` because `XrdCl.symlink` is in scope for the whole suite.
        Base.symlink(f.url, link)
        @test_throws StorageError XRootD.copy(f.url, link)
        @test read(f, String) == payload

        # …and a directory destination that resolves onto the source counts.
        @test_throws StorageError XRootD.copy(f.url, root)
        @test read(f, String) == payload

        # A copy to somewhere else still works, and says what it did.
        @test read(XRootD.copy(f.url, joinpath(root, "elsewhere.root")), String) == payload

        ok, msg = XRootD.Tools.copyfile(f.url, f.url; force=true)
        @test !ok && occursin("same object", msg)
        @test XRootD.Tools.same_object("root://h//a", "roots://h//a")
        @test XRootD.Tools.same_object("root://h:1094//a", "root://h//a")
        @test !XRootD.Tools.same_object("root://h//a", "root://h//b")
        @test !XRootD.Tools.same_object("root://h//a", "root://g//a")
        @test !XRootD.Tools.same_object("root://h//a", "/a")
    end

    @testset "a destination that cannot be written blames the destination" begin
        root = mktempdir()
        src = StoragePath(joinpath(root, "src.txt"))
        write(src, "payload")

        err = try
            XRootD.download(src.url, joinpath(root, "no", "such", "dir", "out.txt"))
        catch e
            e
        end
        @test err isa StorageError
        # The source is fine; saying "read failed" here sends someone looking
        # in the wrong place, and the endpoint's own reason is the useful part.
        @test !occursin("read failed", err.detail)
        @test occursin("write failed", err.detail)
        @test occursin("No such file or directory", err.detail)
    end

    @testset "progress is reported, resolved, and stays out of a log" begin
        # A non-terminal gets whole lines, five seconds apart, because a
        # carriage return in a batch log is noise.
        buf = IOBuffer()
        r = XRootD.ProgressReporter("download f.root", buf)
        @test r.interval == 5.0 && !r.tty
        r(100, 1000)
        r(200, 1000)                     # inside the interval: not printed
        line = String(take!(buf))
        @test count(==('\n'), line) == 1
        @test !occursin('\r', line)
        @test occursin("download f.root", line)
        @test occursin("100 B / 1.0 kB", line)
        @test occursin("10%", line)
        @test occursin("/s", line)

        # A source that would not say how big it is still reports what moved.
        XRootD.render(XRootD.ProgressReporter("copy", buf), 2.0)
        @test occursin("0 B", String(take!(buf)))

        # A terminal gets one line, rewritten, and closed out at the end.
        tty = XRootD.ProgressReporter(
            "copy f", buf, true, 0.2, time(), 0.0, Int64(4096), Int64(4096), false
        )
        XRootD.render(tty, 1.0)
        XRootD.finish!(tty)
        painted = String(take!(buf))
        @test startswith(painted, "\r")
        @test occursin("\e[K", painted)
        @test occursin("4.1 kB / 4.1 kB  100%", painted)
        @test endswith(painted, "\n")

        # Nothing moved and nothing printed: there is no line to close out.
        quiet = XRootD.ProgressReporter("tpc", buf)
        XRootD.finish!(quiet)
        @test isempty(take!(buf))
        # A caller's own function has no line either.
        @test XRootD.finish!((done, total) -> nothing) === nothing

        @test XRootD.progress_for(false, "x") === nothing
        @test XRootD.progress_for(true, "x") isa XRootD.ProgressReporter
        mine = (done, total) -> nothing
        @test XRootD.progress_for(mine, "x") === mine
        # `:auto` is on exactly when someone is watching.
        @test (XRootD.progress_for(:auto, "x") !== nothing) == (stderr isa Base.TTY)
        @test_throws ArgumentError XRootD.progress_for(:sometimes, "x")

        # `:auto` verification checksums a local destination, where the second
        # read is cheap, and leaves a remote one alone.
        @test XRootD.verify_for(:auto, xrd"/tmp/f.root")
        @test !XRootD.verify_for(:auto, xrd"root://host//f.root")
        @test !XRootD.verify_for(:auto, xrd"https://host/f.root")
        @test XRootD.verify_for(true, xrd"root://host//f.root")
        @test !XRootD.verify_for(false, xrd"/tmp/f.root")
        @test_throws ArgumentError XRootD.verify_for(:maybe, xrd"/tmp/f.root")

        # ... and a transfer actually drives whatever was passed.
        root = mktempdir()
        write(joinpath(root, "src.bin"), rand(UInt8, 200_000))
        seen = Tuple{Int64,Any}[]
        XRootD.copy(
            joinpath(root, "src.bin"),
            joinpath(root, "dst.bin");
            progress=(done, total) -> push!(seen, (Int64(done), total)),
        )
        @test !isempty(seen)
        @test last(seen) == (200_000, 200_000)
        @test issorted(first.(seen))
        @test filesize(StoragePath(joinpath(root, "dst.bin"))) == 200_000
    end

    @testset "what went wrong, in words" begin
        root = mktempdir()
        write(joinpath(root, "a.txt"), "hello")
        missing_path = StoragePath(joinpath(root, "nope.txt"))

        err = try
            filesize(missing_path)
        catch e
            e
        end
        @test err isa StorageError
        @test err.op == "stat"
        @test occursin("no such file or directory", sprint(showerror, err))
        @test occursin(missing_path.url, sprint(showerror, err))

        @test_throws StorageError read(missing_path)
        @test_throws StorageError XRootD.ls(missing_path.url)
        # A file is not a directory, and saying so beats an empty listing.
        err = try
            XRootD.ls(joinpath(root, "a.txt"))
        catch e
            e
        end
        @test err isa StorageError
        @test occursin("this is a file, not a directory", err.detail)

        err = try
            rm(StoragePath(root))
        catch e
            e
        end
        @test occursin("pass `recursive=true`", err.detail)

        # A failed copy names the destination and says what the engine said.
        err = try
            XRootD.download(missing_path.url, joinpath(root, "down.txt"))
        catch e
            e
        end
        @test err isa StorageError && err.op == "download"
        @test occursin("read failed", err.detail)

        # The words come from the backend when it kept any, and a credential
        # failure says which keyword would fix it.
        b = XRootD.Storage.storage_for("https://example.invalid/f")
        b.lasterror = "the endpoint answered HTTP 403"
        @test occursin("403", XRootD.explain(:error, b))
        @test occursin("pass `token=`", XRootD.explain(:error, b))
        @test XRootD.explain(:notfound, b) == "no such file or directory"
        b.lasterror = nothing
        @test XRootD.explain(:unsupported, b) == "this endpoint cannot do that"
        @test XRootD.explain(:truncated, b) ==
            "the transfer stopped before the object ended"
        @test XRootD.explain(:error, b) == "the endpoint refused the request"
    end
end
