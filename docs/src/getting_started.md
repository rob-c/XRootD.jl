# Getting started

This page is for reading and writing files that live somewhere else. It
assumes you can run Julia and that someone has given you a URL; it assumes
nothing about the XRootD protocol, and you should not need to learn any of it
to get your data.

```julia
using Pkg
Pkg.add("XRootD")
```

## Your first file

A URL is all you need. Nothing has to be mounted, configured or downloaded
first.

```julia
using XRootD

XRootD.ls("root://eospublic.cern.ch//eos/opendata/cms/Run2012B")
```

```
root://eospublic.cern.ch//eos/opendata/cms/Run2012B  (3 entries)
  AOD/                   2024-03-19 08:11
  data.root      4.2 GB  2024-03-19 08:12
  index.json     1.8 kB  2024-03-19 08:11
```

Bring one here:

```julia
file = XRootD.download("root://eospublic.cern.ch//eos/opendata/cms/Run2012B/data.root")
```

`download` returns the local path it landed at, checks that everything
arrived, and prints how it is getting on if you are sitting at a terminal. If
anything went wrong you get an error, not a status code you have to remember
to look at.

Or read it where it is, without downloading it at all:

```julia
header = XRootD.read(
    "root://eospublic.cern.ch//eos/opendata/cms/Run2012B/data.root"; length=1024
)
```

That is one kilobyte off the front of a four-gigabyte file, and one kilobyte
is what crosses the network.

## Two ways to say the same thing

Everything above is spelled `XRootD.something(url)`, with the `XRootD.` in
front. That is because `read("root://…")` already means something in Julia —
open a *local* file with that peculiar name — and quietly changing what it
means for everyone would be worse than making you type six characters.

If you would rather write `filesize(f)` and `open(f)` and `cp(f, "here.root")`
with no prefix at all, turn the URL into a **path** first:

```julia
f = xrd"root://eospublic.cern.ch//eos/opendata/cms/Run2012B/data.root"

filesize(f)                 # how big is it
isfile(f)                   # is it there
cp(f, "data.root")          # bring it here
open(f) do io               # or read it where it is
    read(io, 1024)
end
```

A [`StoragePath`](@ref) is just a URL you are holding onto. Every verb works
on one, and they are the verbs you already know, because a file on a storage
element in another country is still a file. Use whichever form reads better;
they are the same code underneath.

The `xrd"…"` literal interpolates like any other Julia string, which is how
you build a path out of a run number:

```julia
dataset = "Run2012B"
f = xrd"root://eospublic.cern.ch//eos/opendata/cms/$dataset/data.root"
```

The same works for `https://`, `davs://`, `s3://` and ordinary local paths —
`XRootD.copy` from any of them to any other one.

## Looking around

```julia
dir = xrd"root://xrootd.example.org//store/user/me"

for entry in XRootD.ls(dir)
    isdir(entry) || println(entry.name, "  ", filesize(entry))
end
```

The listing brings the sizes and dates back with it, so asking an entry how
big it is costs nothing — no second trip to the server.

`readdir(dir)` gives just the names, `walkdir(dir)` walks the whole tree, and
`isfile`, `isdir`, `ispath`, `filesize`, `mtime` and `stat` answer about one
path. Those all take a `StoragePath`; the ones a job asks most often also
take the URL as a string:

```julia
XRootD.isdir("root://xrootd.example.org//store/user/me")
XRootD.filesize("root://xrootd.example.org//store/user/me/run7.root")
XRootD.info("root://xrootd.example.org//store/user/me/run7.root")   # size, time, kind
```

The questions asked *before* going ahead — `XRootD.exists` (`ispath` on a
path), `isfile` and `isdir` — answer `false` rather than raising when they
cannot tell, including when the server is unreachable, because you asked
whether to go ahead and not why not. Everything else assumes the file is
there and says so when it is not.

## Reading a file

Small enough to hold in memory:

```julia
data = XRootD.read(url)                    # every byte, as a Vector{UInt8}
text = XRootD.read(url, String)            # …as text
head = XRootD.read(url; length=1024)       # the first kilobyte
mid  = XRootD.read(url; offset=1_000_000, length=4096)   # a piece of the middle
```

Bigger than memory, or you want to hand it to something else:

```julia
XRootD.open(url) do io
    seek(io, 1 << 30)                      # a gigabyte in
    read(io, 4096)                         # …and only these 4 kB move
end
```

`io` is an ordinary Julia `IO`. Any function that takes one — a parser, a
decompressor, a file format library that has never heard of XRootD — can be
handed it directly. The data arrives a chunk at a time as you read, so file
size is not the limit; memory is not either.

Line-oriented files (catalogues, file lists, logs) read the way they do
locally:

```julia
for line in eachline(xrd"root://xrootd.example.org//store/user/me/files.txt")
    println(line)
end
```

## Moving files around

```julia
XRootD.download(url)                       # bring it here, keeping its name
XRootD.download(url, "run7.root")          # …under a name you choose
XRootD.download(url, "data/")              # …into a directory

XRootD.upload("results.root", "root://xrootd.example.org//store/user/me/")

XRootD.copy("root://siteA//data/run7.root", "davs://siteB/data/run7.root")
```

`copy` goes from anywhere to anywhere: `root://`, `https://`, `davs://`,
`s3://` and local paths, in any combination. Some things worth knowing:

- **It checks.** The size the source declared is compared with what arrived,
  so a transfer that died half way through fails instead of leaving you a
  file that is quietly half a file. A local destination is also checksummed
  against the source. Pass `verify=true` to insist on that for a remote
  destination too — it means reading the whole object back over the network,
  which is why it is not the default there.
- **It says how it is getting on.** At a terminal you get a line that
  rewrites itself with how much has moved and how fast. Anywhere else — a
  batch job, a notebook — the default is to stay quiet, because nobody reads
  a progress bar in a log file. `progress=true` reports either way, printing
  a fresh line every five seconds where there is no terminal to rewrite;
  `progress=false` never does; and your own function of `(done, total)` is
  called instead of anything being printed.
- **It overwrites.** `download`, `upload` and `XRootD.copy` replace an
  existing destination, because a notebook cell you run twice should not fail
  the second time. `cp` and `mv` — the `Base` spellings — keep Base's
  refusal to clobber, and take `force=true`.
- **It can step out of the way.** `tpc=:first` asks the two endpoints to move
  the bytes between themselves, so nothing travels via your laptop, and falls
  back to streaming if they cannot.

## Writing output back

```julia
XRootD.write("root://xrootd.example.org//store/user/me/summary.txt", "42 events\n")
```

Something larger goes out through a stream, the same way it comes in:

```julia
XRootD.open(url, "w"; length=nbytes) do io
    for chunk in chunks
        write(io, chunk)
    end
end
```

Pass `length=` whenever you know it. It lets the client frame the upload the
way storage elements like best, and it is what makes an upload that stopped
early fail instead of landing short.

A refused upload raises, including one refused at the very end — a storage
element only publishes an object once it has all of it, so the last thing
that happens in that `do` block is the endpoint's verdict.

The rest of the namespace:

```julia
XRootD.mkdir("root://xrootd.example.org//store/user/me/run7")   # parents included
XRootD.mv(oldurl, newurl)                                       # rename
XRootD.rm(url)                                                  # delete a file
XRootD.rm(dirurl; recursive=true)                               # …and a directory
```

## Credentials and tokens

Most of the time there is nothing to do. If your session already has a token
or a grid proxy — `$BEARER_TOKEN`, `$X509_USER_PROXY`, the proxy file in
`/tmp` that `voms-proxy-init` leaves behind — the client finds it and uses it.

When it does not, and the server asks for one, you will be asked for it at
the terminal. If there is no terminal (a batch job, a notebook) you get an
error saying exactly what was wanted and everywhere that was searched, rather
than a job that hangs forever waiting for someone to type.

To be explicit, pass it — to a path, where it sticks to everything done
through that path, or to a single call:

```julia
f = StoragePath("davs://storage.example.org/data/run7.root"; token=mytoken)
filesize(f)

XRootD.download(url, "run7.root"; cert="/tmp/x509up_u1000")
```

The full list of credential keywords is under [Credentials](@ref).
Whatever you pass is kept out of anything the client
prints: a path with a token in it shows as `<redacted>`, so a stack trace
pasted into a chat window does not hand over your credential with it.

## When something goes wrong

Failures raise `StorageError`, and the message is the server's own words
where the server gave any:

```julia
julia> XRootD.filesize("root://xrootd.example.org//store/user/me/nope.root")
ERROR: StorageError: stat failed on root://xrootd.example.org//store/user/me/nope.root: no such file or directory
```

```julia
julia> XRootD.ls("davs://storage.example.org/private")
ERROR: StorageError: list failed on davs://storage.example.org/private: the endpoint answered HTTP 403 — the endpoint wants a credential: pass `token=`, or `cert=`/`key=`, or set $BEARER_TOKEN or $X509_USER_PROXY
```

The two things that go wrong most often are the file not being there and the
credential not being found, and both say so in as many words.

## Where to go next

- [Recipes](@ref) — thirty-three short programs, including the lower-level
  APIs this page is built on and what to set when the network between you and
  the storage is unreliable.
- [Everyday API](@ref) — every verb on this page, with its keywords.
- [Credentials](@ref) and [Environment](@ref), for a site that needs
  something specific.

If you want the protocol itself — status codes instead of exceptions,
`kXR_*` requests, open handles you manage — that is
[`XRootD.XrdCl`](@ref). You do not need it for anything on this page.
