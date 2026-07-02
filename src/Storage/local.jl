# Local-filesystem backend.

"Local filesystem path backend."
struct LocalBackend <: Backend
    path::String
end

LocalBackend(u::StorageURL) = LocalBackend(u.path)

function storage_stat(b::LocalBackend)
    ispath(b.path) || return :notfound, nothing
    s = stat(b.path)
    return :ok, StorageInfo(Int64(s.size), Int64(floor(s.mtime)), isdir(b.path))
end

function storage_read(b::LocalBackend, sink::IO; offset::Integer=0, length=nothing)
    open(b.path, "r") do io
        offset > 0 && seek(io, offset)
        if length === nothing
            write(sink, read(io))
        else
            write(sink, read(io, Int(length)))
        end
    end
    return :ok
end

function storage_write(b::LocalBackend, source::IO; length=nothing)
    open(b.path, "w") do io
        return write(io, length === nothing ? read(source) : read(source, Int(length)))
    end
    return :ok
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
    rm(b.path; force=true)
    return :ok
end
