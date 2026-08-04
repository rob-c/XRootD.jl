# Local-filesystem backend.

"Local filesystem path backend."
struct LocalBackend <: Backend
    path::String
end

LocalBackend(u::StorageURL) = LocalBackend(u.path)

backend_url(b::LocalBackend) = b.path

function storage_stat(b::LocalBackend)
    ispath(b.path) || return :notfound, nothing
    s = stat(b.path)
    return :ok, StorageInfo(Int64(s.size), Int64(floor(s.mtime)), isdir(b.path))
end

function storage_read(b::LocalBackend, sink::IO; offset::Integer=0, length=nothing)
    open(b.path, "r") do io
        offset > 0 && seek(io, offset)
        return pump(io, sink, length)
    end
    return :ok
end

function storage_write(b::LocalBackend, source::IO; length=nothing)
    open(b.path, "w") do io
        return pump(source, io, length)
    end
    return :ok
end

"""
A stream over an open file. The generic handles exist because a remote object
has no cursor to hold open; a local file does, and going through them would
reopen the file for every chunk.
"""
struct LocalStream <: StreamHandle
    io::IOStream
    path::String
    size::Int64
end

stream_size(h::LocalStream) = h.size
stream_seekable(::LocalStream) = true

function stream_read!(h::LocalStream, buf::Vector{UInt8}, offset::Int64, n::Int)
    position(h.io) == offset || seek(h.io, offset)
    return readbytes!(h.io, buf, n)
end

function stream_write(h::LocalStream, data::Vector{UInt8}, n::Int, offset::Int64)
    position(h.io) == offset || seek(h.io, offset)
    GC.@preserve data unsafe_write(h.io, pointer(data), UInt(n))
    return nothing
end

function stream_close(h::LocalStream)
    close(h.io)
    return :ok
end

function open_read_handle(b::LocalBackend)
    # A directory opens perfectly well on Linux and then answers every read
    # with an error from the kernel; the generic handle rules it out from the
    # stat, and so does this one.
    isdir(b.path) && throw(StorageError(b.path, "open", "is a directory"))
    io = try
        open(b.path, "r")
    catch err
        throw(StorageError(b.path, "open", sprint(showerror, err)))
    end
    return LocalStream(io, b.path, Int64(filesize(io)))
end

function open_write_handle(b::LocalBackend, total)
    io = try
        open(b.path, "w")
    catch err
        throw(StorageError(b.path, "open", sprint(showerror, err)))
    end
    return LocalStream(io, b.path, total === nothing ? Int64(-1) : Int64(total))
end

function storage_list(b::LocalBackend)
    isdir(b.path) || return Tuple{String,StorageInfo}[]
    out = Tuple{String,StorageInfo}[]
    for name in readdir(b.path)
        s = stat(joinpath(b.path, name))
        push!(out, (name, StorageInfo(Int64(s.size), Int64(floor(s.mtime)), isdir(s))))
    end
    return out
end

function storage_remove(b::LocalBackend)
    try
        rm(b.path; force=true)
    catch
        return :error
    end
    return :ok
end

function storage_mkdir(b::LocalBackend)
    try
        mkpath(b.path)
    catch
        return :error
    end
    return :ok
end

function storage_move(b::LocalBackend, dst_url::AbstractString; overwrite::Bool=false)
    dst = parse_url(dst_url)
    dst.scheme == "file" || return :unsupported
    try
        mv(b.path, dst.path; force=overwrite)
    catch
        return :error
    end
    return :ok
end

function storage_copy(b::LocalBackend, dst_url::AbstractString; overwrite::Bool=false)
    dst = parse_url(dst_url)
    dst.scheme == "file" || return :unsupported
    try
        cp(b.path, dst.path; force=overwrite)
    catch
        return :error
    end
    return :ok
end
