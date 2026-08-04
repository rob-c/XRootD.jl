# The front door: one vocabulary for every endpoint this client can reach.
#
# Everything here is a thin layer over `Storage` and `Tools`. It exists because
# those layers answer in the vocabulary of a protocol client — a `(status,
# result)` pair, or a `Symbol` that a copy engine can carry up through a
# recursion — and someone who has a file to read wants `read(f)`, an exception
# when it is not there, and a listing that prints.
#
# Two front doors, one implementation. Every verb is implemented on
# `StoragePath` through the `Base` function that already means it (`read`,
# `open`, `filesize`, `cp`), which is what lets a remote object be handed to
# code that was written for a local one. The `XRootD.<verb>` forms take a URL
# string as well, because `Base.read("root://…")` is Base's local-file read and
# adding methods to Base's functions on `String` is not ours to do.

using Dates: Dates
using .Storage: Storage, StorageError, StorageInfo

export StoragePath, StorageError, @xrd_str

# ---- the path ----

"""
    StoragePath(url; kwargs...)
    xrd"root://host//path/to/file"

A file or a directory somewhere: on an XRootD server (`root://`, `roots://`),
behind HTTPS or WebDAV (`https://`, `davs://`), in an S3 bucket (`s3://`), or
on the local disk (anything without a scheme).

A path behaves like a filename. The verbs you already know work on it and reach
the endpoint the URL names:

    f = xrd"root://eospublic.cern.ch//eos/opendata/cms/Run2012B/data.root"

    isfile(f)                 # is it there?
    filesize(f)               # how big?
    cp(f, "data.root")        # bring it here
    open(f) do io             # or read it where it is
        header = read(io, 1024)
    end

Anything that fails raises [`StorageError`](@ref); nothing returns a status code
you have to remember to check.

Credential keywords (`token`, `cert`/`key`, `cafile`, `insecure_tls`, …) are
kept on the path and applied to everything done through it. Without them the
client finds the usual credentials by itself — `\$BEARER_TOKEN`,
`\$X509_USER_PROXY`, the proxy in `/tmp` — so most of the time there is nothing
to pass.

The connection a path opens is kept for reuse, so a hundred operations on one
endpoint cost one login. `close(p)` gives it back; the path stays usable and
the next operation opens a new one.
"""
mutable struct StoragePath
    const url::String
    const opts::NamedTuple
    backend::Union{Storage.Backend,Nothing}
end

function StoragePath(url::AbstractString; kwargs...)
    opts = values(kwargs)
    check_opts(opts)
    return StoragePath(String(url), opts, nothing)
end

"""
Reject a misspelled credential where it was written. `storage_for` would raise
the same complaint, but not until the first operation — by which point the
keyword looks like it was accepted.
"""
function check_opts(opts::NamedTuple)
    for k in keys(opts)
        k in Storage._KNOWN_OPTS || throw(
            ArgumentError(
                "unknown option `$k`; a storage path takes " *
                join(sort!(String[String(o) for o in Storage._KNOWN_OPTS]), ", "),
            ),
        )
    end
    return nothing
end

"""
    xrd"root://host//path"

A [`StoragePath`](@ref) written as a literal. `\$` interpolates as it does in
any Julia string:

    run = "Run2012B"
    f = xrd"root://eospublic.cern.ch//eos/opendata/cms/\$run/data.root"

A path that needs credentials is built with `StoragePath(url; token=…)`
instead; a literal takes no keywords.
"""
macro xrd_str(url)
    # A non-standard string literal is handed its text raw, so interpolation has
    # to be put back: escaping first (which leaves `$` alone) and re-parsing as
    # an ordinary literal is what does it. A run number or a username in a path
    # is the normal case, not the exotic one.
    return esc(:(StoragePath($(Meta.parse(string('"', escape_string(url), '"'))))))
end

"""
    path(x; kwargs...) -> StoragePath

`x` as a [`StoragePath`](@ref): a URL string becomes one, a path already is one.
Keywords add credentials, and a path given new ones is copied rather than
changed under whoever else is holding it.
"""
path(url::AbstractString; kwargs...) = StoragePath(url; kwargs...)

function path(p::StoragePath; kwargs...)
    isempty(kwargs) && return p
    return StoragePath(p.url; p.opts..., kwargs...)
end

"""
    backend!(p) -> Storage.Backend

The backend behind a path, built on first use and kept.

The backend is where the connection lives: an `XRootDBackend` holds a
`FileSystem`, which logs in once and answers every later request over the same
session. Rebuilding it per call would turn `filesize` over ten files into ten
logins.
"""
function backend!(p::StoragePath)
    b = p.backend
    b === nothing || return b
    b = Storage.storage_for(p.url; p.opts...)
    p.backend = b
    return b
end

"""
    close(p::StoragePath)

Give back the connection the path is holding. The path stays usable — the next
operation opens a new one — so this is a courtesy to the endpoint rather than
something the caller has to get right.
"""
function Base.close(p::StoragePath)
    b = p.backend
    p.backend = nothing
    b isa Storage.XRootDBackend && close(b.fs)
    return nothing
end

Base.show(io::IO, p::StoragePath) = print(io, "xrd\"", Session.redact_url(p.url), '"')

"A path prints as its URL where a string is expected, so `\"\$p\"` and
`` `xrdcp \$p .` `` carry the URL rather than the literal that made it."
Base.print(io::IO, p::StoragePath) = print(io, p.url)

Base.string(p::StoragePath) = p.url
Base.:(==)(a::StoragePath, b::StoragePath) = a.url == b.url && a.opts == b.opts
Base.hash(p::StoragePath, h::UInt) = hash(p.url, hash(p.opts, h))

# Every verb below names its own keywords and lets the rest fall through to
# `path`, so a caller has one keyword namespace to think about:
# `XRootD.download(url, "f.root"; token = t, verify = false)`.

# ---- what went wrong ----

"What the endpoint said about the last failure, for the backends that kept it."
backend_detail(::Storage.Backend) = ""
backend_detail(b::Storage.XRootDBackend) = something(b.lasterror, "")
backend_detail(b::Storage.WebBackend) = something(b.lasterror, "")

"A missing credential is the one failure nobody guesses their way out of."
const _CREDENTIAL_SIGNS = ("401", "403", "permission", "not authorized", "unauthorized")

"""
    explain(code, backend) -> String

Turn a backend's `Symbol` into the sentence that goes in the exception. The
endpoint's own words are preferred where there are any: `No such file or
directory` from the server beats anything this layer could infer.
"""
function explain(code::Symbol, b::Storage.Backend)
    code === :notfound && return "no such file or directory"
    detail = backend_detail(b)
    msg = if !isempty(detail)
        detail
    elseif code === :unsupported
        "this endpoint cannot do that"
    elseif code === :truncated
        "the transfer stopped before the object ended"
    else
        "the endpoint refused the request"
    end
    lowered = lowercase(msg)
    if any(sign -> occursin(sign, lowered), _CREDENTIAL_SIGNS)
        return msg *
               " — the endpoint wants a credential: pass `token=`, or `cert=`/`key=`, " *
               "or set \$BEARER_TOKEN or \$X509_USER_PROXY"
    end
    return msg
end

"Raise the failure of `op` on `p`, in the endpoint's own words where it gave any."
function failed(p::StoragePath, op::AbstractString, code::Symbol)
    return throw(StorageError(p.url, op, explain(code, backend!(p))))
end

# ---- metadata ----

"""
    XRootD.info(x) -> Storage.StorageInfo

Size, modification time and directory flag for a file or directory, whether it
is named by a URL string or by a [`StoragePath`](@ref). Raises
[`StorageError`](@ref) if it is not there.

    julia> XRootD.info("root://eospublic.cern.ch//eos/opendata/cms")
    directory  2024-03-19 08:11
"""
info(x; kwargs...) = info(path(x; kwargs...))

function info(p::StoragePath)
    code, i = Storage.storage_stat(backend!(p))
    (code === :ok && i !== nothing) || failed(p, "stat", code)
    return i::StorageInfo
end

function Base.show(io::IO, ::MIME"text/plain", i::StorageInfo)
    print(io, i.isdir ? "directory" : human_size(i.size), "  ", mtime_string(i.mtime))
    return nothing
end

"""
    stat(p::StoragePath) -> Storage.StorageInfo

What the endpoint knows about `p`. This is a `StorageInfo`, not the `StatStruct`
that `stat` returns for a local file: a remote object has no inode, no device
and no permission bits this client can speak for, and inventing them would be
worse than answering with the three facts every endpoint does report.
"""
Base.stat(p::StoragePath) = info(p)

"""
    filesize(p::StoragePath) -> Int64

Bytes in the object. Raises [`StorageError`](@ref) if it is not there — which is
what `filesize` does for a local file that is not there either.
"""
Base.filesize(p::StoragePath) = info(p).size

"Seconds since the epoch, as `mtime` reports for a local file."
Base.mtime(p::StoragePath) = Float64(info(p).mtime)

"""
    ispath(p::StoragePath) -> Bool

Whether anything is there at all. This is the question that answers `false`
rather than raising: everything else assumes the object exists.
"""
function Base.ispath(p::StoragePath)
    code, _ = Storage.storage_stat(backend!(p))
    return code === :ok
end

"`true` when `p` is there and is not a directory."
function Base.isfile(p::StoragePath)
    code, i = Storage.storage_stat(backend!(p))
    return code === :ok && i !== nothing && !i.isdir
end

"`true` when `p` is there and is a directory."
function Base.isdir(p::StoragePath)
    code, i = Storage.storage_stat(backend!(p))
    return code === :ok && i !== nothing && i.isdir
end

"""
    XRootD.exists(x) -> Bool

Whether a URL names anything at all. This never raises: a storage element that
cannot be reached and a path that is not there both answer `false`, because the
question was whether to go ahead, not why not. The same goes for
[`XRootD.isfile`](@ref) and [`XRootD.isdir`](@ref).
"""
exists(x; kwargs...) = Base.ispath(path(x; kwargs...))

"`true` when the URL names a file that is there. See [`XRootD.exists`](@ref)."
isfile(x; kwargs...) = Base.isfile(path(x; kwargs...))

"`true` when the URL names a directory that is there. See [`XRootD.exists`](@ref)."
isdir(x; kwargs...) = Base.isdir(path(x; kwargs...))

"""
    XRootD.filesize(x) -> Int64

Bytes in the object `x` names. Raises [`StorageError`](@ref) if it is not there.
"""
filesize(x; kwargs...) = Base.filesize(path(x; kwargs...))

# ---- listings ----

"""
One entry of a [`Listing`](@ref): the child's [`StoragePath`](@ref), its name
within the directory, and the metadata that came back with the listing —
`isfile`, `isdir` and `filesize` read it rather than asking the endpoint again.
"""
struct DirEntry
    path::StoragePath
    name::String
    info::StorageInfo
end

Base.isdir(e::DirEntry) = e.info.isdir
Base.isfile(e::DirEntry) = !e.info.isdir
Base.filesize(e::DirEntry) = e.info.size
Base.basename(e::DirEntry) = e.name
Base.string(e::DirEntry) = e.path.url

"""
The contents of one directory, as returned by [`XRootD.ls`](@ref).

It is a vector of [`DirEntry`](@ref) — index it, iterate it, `filter` it — that
prints as a listing rather than as a wall of structs:

    julia> XRootD.ls("root://eospublic.cern.ch//eos/opendata/cms/Run2012B")
    root://eospublic.cern.ch//eos/opendata/cms/Run2012B  (3 entries)
      AOD/                   2024-03-19 08:11
      index.json     1.8 kB  2024-03-19 08:11
      data.root     4.2 GB   2024-03-19 08:12
"""
struct Listing <: AbstractVector{DirEntry}
    dir::StoragePath
    entries::Vector{DirEntry}
end

Base.size(l::Listing) = size(l.entries)
Base.getindex(l::Listing, i::Int) = l.entries[i]
Base.IndexStyle(::Type{Listing}) = IndexLinear()

"""
    XRootD.ls(x; sort=true, kwargs...) -> Listing

What is in a directory, named by URL string or [`StoragePath`](@ref). Entries
come back sorted by name, each carrying the size and modification time the
endpoint reported with the listing.

    for e in XRootD.ls("root://eospublic.cern.ch//eos/opendata/cms")
        isdir(e) || println(e.name, "  ", filesize(e))
    end

Raises [`StorageError`](@ref) when the directory is not there or is not a
directory — an empty listing means an empty directory and nothing else.
"""
function ls(x; sort::Bool=true, kwargs...)
    p = path(x; kwargs...)
    b = backend!(p)
    entries = Storage.storage_list(b)
    if isempty(entries)
        # Nothing listed is an empty directory, a file, or a failure, and only a
        # stat tells them apart — the backends report a listing they could not
        # make as no entries.
        code, i = Storage.storage_stat(b)
        code === :ok || failed(p, "list", code)
        (i !== nothing && i.isdir) ||
            throw(StorageError(p.url, "list", "this is a file, not a directory"))
    end
    sort && sort!(entries; by=first)
    return Listing(p, [DirEntry(Base.joinpath(p, name), name, i) for (name, i) in entries])
end

"""
    readdir(p::StoragePath; join=false, sort=true) -> Vector{String}

The names in a directory, as `readdir` gives them for a local one. `join=true`
returns full URLs instead of bare names. [`XRootD.ls`](@ref) is the same listing
with the sizes and times kept.
"""
function Base.readdir(p::StoragePath; join::Bool=false, sort::Bool=true)
    return String[join ? e.path.url : e.name for e in ls(p; sort=sort)]
end

"""
    walkdir(p::StoragePath; topdown=true) -> iterator of (dir, dirs, files)

Walk the tree under `p`, as `walkdir` does for a local one: `dir` is a
[`StoragePath`](@ref), `dirs` and `files` are the names within it.

Each directory is listed as the walk reaches it, so a walk that stops early —
`first`, or a `break` — has not listed the rest of the tree. That matters on a
namespace with a million files in it.
"""
function Base.walkdir(p::StoragePath; topdown::Bool=true)
    w = StorageWalk(p)
    # Children before parents means knowing every child first, which is the
    # walk itself; there is nothing to be lazy about.
    return topdown ? w : reverse(collect(w))
end

"Depth-first walk of a storage tree, one listing per step. See [`walkdir`](@ref)."
struct StorageWalk
    root::StoragePath
end

Base.IteratorSize(::Type{StorageWalk}) = Base.SizeUnknown()
Base.eltype(::Type{StorageWalk}) = Tuple{StoragePath,Vector{String},Vector{String}}

function Base.iterate(w::StorageWalk, stack::Vector{StoragePath}=[w.root])
    isempty(stack) && return nothing
    dir = pop!(stack)
    entries = ls(dir)
    dirs = String[e.name for e in entries if e.info.isdir]
    files = String[e.name for e in entries if !e.info.isdir]
    # Pushed in reverse so the first subdirectory is the next one popped.
    for name in Iterators.reverse(dirs)
        push!(stack, Base.joinpath(dir, name))
    end
    return (dir, dirs, files), stack
end

# ---- path algebra ----

"""
    joinpath(p::StoragePath, parts...) -> StoragePath

A path below `p`, keeping its scheme, endpoint and credentials.

    dir = xrd"root://eospublic.cern.ch//eos/opendata/cms"
    joinpath(dir, "Run2012B", "data.root")
"""
function Base.joinpath(p::StoragePath, parts::AbstractString...)
    isempty(parts) && return p
    url = rstrip(p.url, '/')
    for part in parts
        url = string(url, '/', lstrip(part, '/'))
    end
    return StoragePath(String(url), p.opts, nothing)
end

"""
    basename(p::StoragePath) -> String

The object's own name, without the endpoint, the directories or any query
string the URL carries (`…/data.root?authz=…` is still `data.root`).
"""
function Base.basename(p::StoragePath)
    objectpath = rstrip(first(split(Storage.parse_url(p.url).path, '?')), '/')
    return String(Base.basename(objectpath))
end

"""
    dirname(p::StoragePath) -> StoragePath

The directory `p` is in. A path already at the top of its endpoint is its own
directory, as `dirname("/")` is `"/"`.
"""
function Base.dirname(p::StoragePath)
    url = rstrip(p.url, '/')
    cut = findlast('/', url)
    (cut === nothing || cut <= endpoint_end(url)) && return p
    return StoragePath(String(url[1:prevind(url, cut)]), p.opts, nothing)
end

"""
Index of the `/` that begins the path part of `url`, or `0` when there is no
`scheme://` in front of it. `dirname` stops here: `root://host//f` has a
directory above `f`, but `root://host` is not a place.
"""
function endpoint_end(url::AbstractString)
    sep = findfirst("://", url)
    sep === nothing && return 0
    slash = findnext('/', url, nextind(url, last(sep)))
    return slash === nothing ? lastindex(url) : slash
end

# ---- reading ----

"""
    open(p::StoragePath, mode="r"; length=nothing) -> IO
    open(f::Function, p::StoragePath, mode="r"; length=nothing)

Open a storage object as a Julia stream, readable (`"r"`) or writable (`"w"`),
and hand it to anything that takes an `IO`. See
[`XRootD.Storage.storage_open`](@ref) for what the stream can do and why
`length` is worth passing on a write.
"""
function Base.open(p::StoragePath, mode::AbstractString="r"; length=nothing)
    return Base.open(backend!(p), mode; length=length)
end

function Base.open(f::Function, p::StoragePath, mode::AbstractString="r"; length=nothing)
    return Base.open(f, backend!(p), mode; length=length)
end

"""
    XRootD.open(x, mode="r"; length=nothing, kwargs...) -> IO
    XRootD.open(f::Function, x, mode="r"; length=nothing, kwargs...)

Open the object `x` names — a URL string or a [`StoragePath`](@ref) — as a Julia
stream. The `do` form closes it afterwards, including when the body throws.

    XRootD.open("root://host//data/run7.raw") do io
        seek(io, 4096)
        header = read(io, 1024)
    end

Reading and writing go through the endpoint a chunk at a time, so a file bigger
than memory is not a problem.
"""
function open(x, mode::AbstractString="r"; length=nothing, kwargs...)
    return Base.open(path(x; kwargs...), mode; length=length)
end

function open(f::Function, x, mode::AbstractString="r"; length=nothing, kwargs...)
    return Base.open(f, path(x; kwargs...), mode; length=length)
end

# `open(f, url)` reads both as "call f with the stream" and as "open the object
# f, in mode url"; only the first is anything anyone meant.
function open(f::Function, x::AbstractString; length=nothing, kwargs...)
    return Base.open(f, path(x; kwargs...), "r"; length=length)
end

"""
Check a byte range before anything is opened. A negative count reaches Julia's
allocator as an enormous unsigned one, and `invalid GenericMemory size` is not
an answer to "why will it not read my file".
"""
function check_extent(offset::Integer, length)
    offset < 0 && throw(ArgumentError("offset cannot be negative (got $offset)"))
    (length !== nothing && length < 0) &&
        throw(ArgumentError("length cannot be negative (got $length)"))
    return nothing
end

"Everything in the object, as bytes."
Base.read(p::StoragePath) = Base.open(Base.read, p)

"The first `n` bytes."
function Base.read(p::StoragePath, n::Integer)
    check_extent(0, n)
    return Base.open(io -> Base.read(io, Int(n)), p)
end

"Everything in the object, as text."
Base.read(p::StoragePath, ::Type{String}) = String(Base.read(p))

"The object's lines, as `readlines` gives them for a local file."
function Base.readlines(p::StoragePath; kwargs...)
    return Base.open(io -> Base.readlines(io; kwargs...), p)
end

"""
    eachline(p::StoragePath; keep=false)

The object's lines, one at a time, without holding the file in memory — for the
file lists and text catalogues that are half of what sits on a storage element.
The stream closes when the iteration finishes.
"""
function Base.eachline(p::StoragePath; keep::Bool=false)
    io = Base.open(p)
    return Base.EachLine(io; ondone=() -> close(io), keep=keep)
end

"""
    XRootD.read(x; offset=0, length=nothing, kwargs...) -> Vector{UInt8}
    XRootD.read(x, String; kwargs...) -> String

Read an object into memory. `offset` and `length` take a piece out of the
middle of it, which is how you look at a header without moving a 4 GB file:

    header = XRootD.read(url; length = 1024)
    piece  = XRootD.read(url; offset = 1_000_000, length = 4096)

Raises [`StorageError`](@ref) if the object is not there. Use
[`XRootD.open`](@ref) instead when the object is larger than memory.
"""
function read(x; offset::Integer=0, length=nothing, kwargs...)
    check_extent(offset, length)
    p = path(x; kwargs...)
    (offset == 0 && length === nothing) && return Base.read(p)
    return Base.open(p) do io
        offset > 0 && seek(io, offset)
        return length === nothing ? Base.read(io) : Base.read(io, Int(length))
    end
end

read(x, ::Type{String}; kwargs...) = String(read(x; kwargs...))

# ---- writing ----

"""
    write(p::StoragePath, data) -> Int

Write `data` — bytes or a string — to the object, replacing whatever was there,
and return how many bytes landed. Raises [`StorageError`](@ref) if the endpoint
would not take it; nothing is reported by return value.
"""
function Base.write(p::StoragePath, data::AbstractVector{UInt8})
    return Base.open(io -> Base.write(io, data), p, "w"; length=Base.length(data))
end

function Base.write(p::StoragePath, data::AbstractString)
    s = String(data)
    return Base.open(io -> Base.write(io, s), p, "w"; length=sizeof(s))
end

"""
    XRootD.write(x, data; kwargs...) -> Int

Write bytes or text to the object `x` names, replacing whatever was there.

    XRootD.write("root://host//results/summary.txt", "42 events\\n")

An upload that the endpoint refused raises [`StorageError`](@ref) — including
one refused at the very end, since a storage element only commits an object
when it has all of it. Use [`XRootD.open`](@ref) with `"w"` to write something
larger than memory.
"""
function write(x, data; kwargs...)
    return Base.write(path(x; kwargs...), data)
end

# ---- the namespace ----

"""
    mkpath(p::StoragePath) -> StoragePath

Create the directory, and any missing directory above it. A directory that
already exists is success, so this is safe to call before writing.
"""
function Base.mkpath(p::StoragePath)
    code = Storage.storage_mkdir(backend!(p))
    code === :ok || failed(p, "mkdir", code)
    return p
end

"""
    mkdir(p::StoragePath) -> StoragePath

The same as [`mkpath`](@ref): the protocols underneath create a whole path in
one request (`kXR_mkdirpath`, `MKCOL`), and making the two spellings differ
would cost a round trip per level to enforce a distinction nothing here needs.
"""
Base.mkdir(p::StoragePath) = Base.mkpath(p)

"""
    XRootD.mkdir(x; kwargs...) -> StoragePath

Create a directory, and any missing directory above it. Already being there is
success, so this is safe to call before writing.
"""
mkdir(x; kwargs...) = Base.mkpath(path(x; kwargs...))

"""
    rm(p::StoragePath; force=false, recursive=false)

Delete the object. `recursive=true` empties a directory first; `force=true`
makes a path that is already gone a success rather than an error.
"""
function Base.rm(p::StoragePath; force::Bool=false, recursive::Bool=false)
    b = backend!(p)
    code, i = Storage.storage_stat(b)
    if code !== :ok
        # `force` is the whole difference between "make sure it is gone" and
        # "delete this", and a path that was never there is where they part.
        force && return nothing
        failed(p, "rm", code)
    end
    if i !== nothing && i.isdir
        recursive ||
            throw(StorageError(p.url, "rm", "this is a directory; pass `recursive=true`"))
        for e in ls(p)
            Base.rm(e.path; force=force, recursive=true)
        end
    end
    rcode = Storage.storage_remove(b)
    rcode === :ok || failed(p, "rm", rcode)
    return nothing
end

"""
    XRootD.rm(x; force=false, recursive=false, kwargs...)

Delete a file, or a directory and everything under it with `recursive=true`.

    XRootD.rm("root://host//scratch/run7", recursive = true)
"""
function rm(x; force::Bool=false, recursive::Bool=false, kwargs...)
    return Base.rm(path(x; kwargs...); force=force, recursive=recursive)
end

"""
    mv(src::StoragePath, dst; force=false) -> StoragePath

Move the object to `dst`. Within one endpoint this is a rename and no bytes
move; between two it is a copy followed by a delete, and the source is only
removed once the copy has landed.
"""
function Base.mv(src::StoragePath, dst::StoragePath; force::Bool=false)
    code = Storage.storage_move(backend!(src), dst.url; overwrite=force)
    code === :ok && return dst
    code === :unsupported || failed(src, "mv", code)
    Base.cp(src, dst; force=force)
    Base.rm(src)
    return dst
end

function Base.mv(src::StoragePath, dst::AbstractString; kwargs...)
    return Base.mv(src, path(dst); kwargs...)
end

function Base.mv(src::AbstractString, dst::StoragePath; kwargs...)
    return Base.mv(path(src), dst; kwargs...)
end

"""
    XRootD.mv(src, dst; force=false, kwargs...) -> StoragePath

Move an object, within one endpoint or between two. `force=true` replaces an
existing destination.
"""
function mv(src, dst; force::Bool=false, kwargs...)
    return Base.mv(path(src; kwargs...), path(dst; kwargs...); force=force)
end

# ---- moving bytes ----

const _SIZE_UNITS = ("B", "kB", "MB", "GB", "TB", "PB")

"A byte count the way a person would say it: `4.2 GB`, not `4200000000`."
function human_size(n::Integer)
    n < 1000 && return string(n, " B")
    x = Float64(n)
    unit = 1
    while x >= 1000 && unit < Base.length(_SIZE_UNITS)
        x /= 1000
        unit += 1
    end
    return string(x < 10 ? round(x; digits=1) : round(Int, x), " ", _SIZE_UNITS[unit])
end

"A modification time as a date, or `-` when the endpoint did not report one."
function mtime_string(t::Integer)
    t <= 0 && return "-"
    return Dates.format(Dates.unix2datetime(t), "yyyy-mm-dd HH:MM")
end

function Base.show(io::IO, ::MIME"text/plain", l::Listing)
    n = Base.length(l.entries)
    print(io, Session.redact_url(l.dir.url), "  (", n, n == 1 ? " entry)" : " entries)")
    n == 0 && return nothing
    shown = get(io, :limit, false)::Bool ? min(n, 40) : n
    width = maximum(e -> Base.length(entry_name(e)), view(l.entries, 1:shown))
    for e in view(l.entries, 1:shown)
        print(
            io,
            "\n  ",
            rpad(entry_name(e), width),
            "  ",
            lpad(e.info.isdir ? "" : human_size(e.info.size), 9),
            "  ",
            mtime_string(e.info.mtime),
        )
    end
    shown < n && print(io, "\n  … and ", n - shown, " more")
    return nothing
end

function Base.show(io::IO, l::Listing)
    return print(io, "Listing(", repr(l.dir.url), ", ", Base.length(l.entries), " entries)")
end

"How an entry is named in a listing: directories wear their trailing slash."
entry_name(e::DirEntry) = e.info.isdir ? e.name * "/" : e.name

"""
Prints how far a transfer has got and how fast, over the top of its own last
line on a terminal and on a fresh line anywhere else — a carriage return in a
log file is noise, and a batch job's log is where most of these run.
"""
mutable struct ProgressReporter
    const label::String
    const io::IO
    const tty::Bool
    const interval::Float64
    const started::Float64
    last::Float64
    done::Int64
    total::Union{Int64,Nothing}
    printed::Bool
end

function ProgressReporter(label::AbstractString, io::IO=stderr)
    tty = io isa Base.TTY
    return ProgressReporter(
        String(label), io, tty, tty ? 0.2 : 5.0, time(), 0.0, Int64(0), nothing, false
    )
end

function (r::ProgressReporter)(done::Integer, total)
    r.done = Int64(done)
    r.total = total === nothing ? nothing : Int64(total)
    now = time()
    now - r.last < r.interval && return nothing
    r.last = now
    render(r, now - r.started)
    return nothing
end

function render(r::ProgressReporter, elapsed::Float64)
    rate = elapsed > 0 ? human_size(round(Int, r.done / elapsed)) * "/s" : "—"
    total = r.total
    line = if total === nothing || total <= 0
        string(r.label, "  ", human_size(r.done), "  ", rate)
    else
        pct = round(Int, 100 * r.done / total)
        string(
            r.label,
            "  ",
            human_size(r.done),
            " / ",
            human_size(total),
            "  ",
            pct,
            "%  ",
            rate,
        )
    end
    # `\e[K` wipes what the previous, longer line left behind.
    r.tty ? print(r.io, '\r', line, "\e[K") : println(r.io, line)
    flush(r.io)
    r.printed = true
    return nothing
end

"""
Finish the line. A transfer that reported nothing — a third-party copy moves no
bytes through this client — has nothing to close out.
"""
function finish!(r::ProgressReporter)
    r.done == 0 && !r.printed && return nothing
    render(r, max(time() - r.started, 1e-9))
    r.tty && println(r.io)
    flush(r.io)
    return nothing
end

"A caller's own progress function has no line to close out."
finish!(::Any) = nothing

"""
    progress_for(progress, label) -> ProgressReporter | Nothing

Resolve the `progress` keyword. `:auto` reports on a terminal and stays quiet
otherwise, so a transfer run from a notebook or a batch job does not fill its
log with a progress bar nobody will read. `true` reports either way, `false`
never, and a function of `(done, total)` is called instead of printing.
"""
function progress_for(progress, label::AbstractString)
    progress === false && return nothing
    progress === :auto && return stderr isa Base.TTY ? ProgressReporter(label) : nothing
    progress === true && return ProgressReporter(label)
    progress isa Function && return progress
    return throw(
        ArgumentError("progress is true, false, :auto, or a function of (done, total)")
    )
end

"""
    verify_for(verify, dst) -> Bool

Resolve the `verify` keyword. `:auto` checksums the copy when the destination is
local, because re-reading a file from a disk is cheap. Verifying a *remote*
destination means pulling the whole object back over the network, which doubles
a transfer that was expensive enough to be worth thinking about — ask for it
with `verify=true` when the object is worth the second trip.
"""
verify_for(verify::Bool, ::StoragePath) = verify

function verify_for(verify::Symbol, dst::StoragePath)
    verify === :auto ||
        throw(ArgumentError("verify is true, false, or :auto (got $(repr(verify)))"))
    return Storage.parse_url(dst.url).scheme == "file"
end

"""
A destination that is an existing directory takes the source's own name, as
`cp` does locally: `download(url, "data/")` puts the file *in* `data`.
"""
function resolve_destination(src::StoragePath, dst::StoragePath)
    Base.isdir(dst) || return dst
    return Base.joinpath(dst, Base.basename(src))
end

"""
    transfer(src, dst; label, force, verify, progress, tpc) -> StoragePath

The one copy path behind `cp`, `download`, `upload` and `XRootD.copy`: resolve
the destination, move the bytes, and raise when they did not all get there.
"""
function transfer(
    src::StoragePath,
    dst::StoragePath;
    label::AbstractString="copy",
    force::Bool=true,
    verify=:auto,
    progress=:auto,
    tpc::Symbol=:none,
)
    target = resolve_destination(src, dst)
    reporter = progress_for(progress, string(label, ' ', Base.basename(src)))
    ok, msg = try
        Tools.copyfile(
            src.url,
            target.url;
            force=force,
            verify=verify_for(verify, target),
            tpc=tpc,
            progress=reporter,
            src_opts=src.opts,
            dst_opts=target.opts,
        )
    finally
        finish!(reporter)
    end
    ok || throw(StorageError(target.url, label, msg))
    return target
end

"""
    cp(src::StoragePath, dst; force=false, verify=:auto, progress=:auto, tpc=:none)
    cp(src, dst::StoragePath; …)

Copy one object to another place, in either direction and between any two
endpoints this client can reach. Returns the destination.

`force` overwrites an existing destination — `false`, as it is for a local `cp`.
See [`XRootD.copy`](@ref) for the other keywords.
"""
function Base.cp(src::StoragePath, dst::StoragePath; force::Bool=false, kwargs...)
    return transfer(src, dst; force=force, kwargs...)
end

function Base.cp(src::StoragePath, dst::AbstractString; kwargs...)
    return Base.cp(src, path(dst); kwargs...)
end

function Base.cp(src::AbstractString, dst::StoragePath; kwargs...)
    return Base.cp(path(src), dst; kwargs...)
end

"""
    XRootD.copy(src, dst; force=true, verify=:auto, progress=:auto, tpc=:none, kwargs...)

Copy an object from anywhere to anywhere: local disk, `root://`, `https://`,
`s3://`, in any combination.

    XRootD.copy("root://siteA//data/run7.root", "davs://siteB/data/run7.root")

  - `force` overwrites an existing destination; unlike `cp`, it defaults to
    `true`, because a call that names its destination is a call that meant it.
  - `verify` re-reads the destination and compares checksums. `:auto` does this
    when the destination is local, where the second read is cheap; pass `true`
    to insist on it for a remote one. A transfer that ended early is caught
    either way, by the byte count the source declared.
  - `progress` prints how far along the transfer is: `:auto` on a terminal,
    `true` anywhere, `false` never, or your own function of `(done, total)`.
  - `tpc = :first` asks the two endpoints to move the bytes between themselves
    and falls back to streaming through this client; `:only` fails rather than
    falling back.

Returns the destination as a [`StoragePath`](@ref), and raises
[`StorageError`](@ref) if any of it went wrong.
"""
function copy(
    src, dst; force::Bool=true, verify=:auto, progress=:auto, tpc::Symbol=:none, kwargs...
)
    return transfer(
        path(src; kwargs...),
        path(dst; kwargs...);
        force=force,
        verify=verify,
        progress=progress,
        tpc=tpc,
    )
end

"""
    XRootD.download(url, dest="."; kwargs...) -> String

Bring a remote object here, and return the local path it landed at. `dest` may
be a filename or a directory, in which case the file keeps its own name — so
the common case is a URL and nothing else:

    file = XRootD.download("root://eospublic.cern.ch//eos/opendata/cms/data.root")

The copy is checksummed against the source, and progress is printed if this is
a terminal. Keywords are those of [`XRootD.copy`](@ref); an existing file is
replaced unless `force=false`.
"""
function download(
    url,
    dest::AbstractString=".";
    force::Bool=true,
    verify=:auto,
    progress=:auto,
    tpc::Symbol=:none,
    kwargs...,
)
    landed = transfer(
        path(url; kwargs...),
        path(dest);
        label="download",
        force=force,
        verify=verify,
        progress=progress,
        tpc=tpc,
    )
    return landed.url
end

"""
    XRootD.upload(file, url; kwargs...) -> StoragePath

Put a local file on a storage element, and return where it landed. `url` may
name the object or the directory to put it in.

    XRootD.upload("results.root", "root://myserver//eos/user/r/rob/")

Keywords are those of [`XRootD.copy`](@ref). The upload raises
[`StorageError`](@ref) rather than reporting failure quietly, including when the
endpoint rejects it at the close — a storage element publishes an object only
once it has all of it.
"""
function upload(
    file::AbstractString,
    url;
    force::Bool=true,
    verify=:auto,
    progress=:auto,
    tpc::Symbol=:none,
    kwargs...,
)
    return transfer(
        path(file),
        path(url; kwargs...);
        label="upload",
        force=force,
        verify=verify,
        progress=progress,
        tpc=tpc,
    )
end
