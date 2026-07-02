# HTTP / WebDAV backend on HTTP.jl. Read = GET (+ Range), write = PUT,
# stat = HEAD, list = WebDAV PROPFIND depth 1.

"HTTP/WebDAV (`http(s)://`, `dav(s)://`) backend."
struct WebBackend <: Backend
    url::StorageURL
    headers::Vector{Pair{String,String}}
end

function WebBackend(u::StorageURL; headers=Pair{String,String}[])
    return WebBackend(u, collect(headers))
end

function storage_stat(b::WebBackend)
    resp = try
        HTTP.request("HEAD", http_url(b.url), b.headers; status_exception=false)
    catch
        return :error, nothing
    end
    resp.status == 200 || return (resp.status == 404 ? :notfound : :error), nothing
    size = parse_content_length(resp)
    mtime = parse_last_modified(resp)
    isdir = endswith(b.url.path, "/")
    return :ok, StorageInfo(size, mtime, isdir)
end

function storage_read(b::WebBackend, sink::IO; offset::Integer=0, length=nothing)
    headers = copy(b.headers)
    if offset > 0 || length !== nothing
        last = length === nothing ? "" : string(offset + Int(length) - 1)
        push!(headers, "Range" => "bytes=$offset-$last")
    end
    resp = try
        HTTP.request("GET", http_url(b.url), headers; status_exception=false)
    catch
        return :error
    end
    (resp.status == 200 || resp.status == 206) || return :error
    write(sink, resp.body)
    return :ok
end

function storage_write(b::WebBackend, source::IO; length=nothing)
    body = length === nothing ? read(source) : read(source, Int(length))
    resp = try
        HTTP.request("PUT", http_url(b.url), b.headers, body; status_exception=false)
    catch
        return :error
    end
    return (200 <= resp.status < 300) ? :ok : :error
end

function storage_list(b::WebBackend)
    headers = vcat(b.headers, ["Depth" => "1", "Content-Type" => "application/xml"])
    body = """<?xml version="1.0"?><propfind xmlns="DAV:"><prop>
             <getcontentlength/><getlastmodified/><resourcetype/></prop></propfind>"""
    resp = try
        HTTP.request("PROPFIND", http_url(b.url), headers, body; status_exception=false)
    catch
        return Tuple{String,StorageInfo}[]
    end
    resp.status == 207 || return Tuple{String,StorageInfo}[]
    return parse_propfind(String(resp.body), b.url.path)
end

function storage_remove(b::WebBackend)
    resp = try
        HTTP.request("DELETE", http_url(b.url), b.headers; status_exception=false)
    catch
        return :error
    end
    return (200 <= resp.status < 300) ? :ok : :error
end

# ---- header / XML helpers ----

function parse_content_length(resp)
    for (k, v) in resp.headers
        lowercase(k) == "content-length" && return something(tryparse(Int64, v), Int64(0))
    end
    return Int64(0)
end

function parse_last_modified(resp)
    for (k, v) in resp.headers
        if lowercase(k) == "last-modified"
            dt = tryparse(Dates.DateTime, v, Dates.dateformat"e, d u Y H:M:S \G\M\T")
            dt === nothing && return Int64(0)
            return Int64(round(Dates.datetime2unix(dt)))
        end
    end
    return Int64(0)
end

"""
Parse a WebDAV `multistatus` body into `(name, StorageInfo)` entries.
Deliberately minimal (regex over `<response>` blocks) — enough for a
directory listing without pulling in a full XML dependency.
"""
function parse_propfind(xml::AbstractString, base_path::AbstractString)
    out = Tuple{String,StorageInfo}[]
    for resp in eachmatch(r"<(?:\w+:)?response\b.*?</(?:\w+:)?response>"s, xml)
        block = resp.match
        href_m = match(r"<(?:\w+:)?href>\s*([^<]+?)\s*</(?:\w+:)?href>", block)
        href_m === nothing && continue
        href = URIs.unescapeuri(strip(String(something(href_m.captures[1]))))
        name = rstrip(basename(rstrip(href, '/')), '/')
        isempty(name) && continue
        occursin(rstrip(base_path, '/') * "\$", rstrip(href, '/')) && continue  # skip self
        len_m = match(r"<(?:\w+:)?getcontentlength>\s*(\d+)", block)
        size = len_m === nothing ? Int64(0) : parse(Int64, something(len_m.captures[1]))
        isdir = occursin(r"<(?:\w+:)?collection\b", block)
        push!(out, (String(name), StorageInfo(size, Int64(0), isdir)))
    end
    return out
end
