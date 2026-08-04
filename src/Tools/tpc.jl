# Third-party copy: the endpoints move the bytes between themselves and this
# client only orchestrates. Two protocols, one entry point — WLCG HTTP-TPC
# (`COPY` with a Source/Destination header) and the xroot rendezvous
# (`tpc.stage=placement` on the source, `tpc.stage=copy` on the destination).

"Seconds a TPC rendezvous key stays valid at the source."
const TPC_TTL = 60

"""
    tpc_copy(src::Backend, dst::Backend; overwrite=false, mode=:pull)
        -> (Symbol, String)

Ask the two endpoints to transfer the object directly. Returns `(:ok, msg)`,
`(:error, msg)` when a copy was attempted and failed, or
`(:unsupported, msg)` when this pair of endpoints has no third-party path —
which is the signal for [`copyfile`](@ref) to fall back to streaming.
"""
function tpc_copy(src, dst; overwrite::Bool=false, mode::Symbol=:pull)
    return :unsupported, "no third-party copy between $(typeof(src)) and $(typeof(dst))"
end

function tpc_copy(
    src::Storage.WebBackend,
    dst::Storage.WebBackend;
    overwrite::Bool=false,
    mode::Symbol=:pull,
)
    return Storage.storage_tpc(dst, src; overwrite, mode)
end

"""
S3 has no third party, but `x-amz-copy-source` is the same bargain from the
caller's side: the endpoint copies the object itself and no bytes cross this
client. It needs one endpoint and one credential — a copy between two accounts
is a transfer, and falls back to streaming.
"""
function tpc_copy(
    src::Storage.S3Backend,
    dst::Storage.S3Backend;
    overwrite::Bool=false,
    mode::Symbol=:pull,
)
    reachable = Storage.s3_destination(src, dst.url.raw)
    if reachable === nothing || reachable.endpoint_host != dst.endpoint_host
        return :unsupported, "$(dst.url.raw) is not at the endpoint holding $(src.url.raw)"
    end
    if src.creds.access_key != dst.creds.access_key
        return :unsupported, "an S3 server-side copy signs both ends with one credential"
    end
    code = Storage.storage_copy(src, dst.url.raw; overwrite=overwrite)
    code === :ok && return :ok, "server-side copy of $(src.key) to $(dst.key)"
    return :error, "the endpoint refused to copy $(src.key) to $(dst.key)"
end

"""
The xroot rendezvous (XRootD protocol reference, "Third Party Copy"): the
client opens the *source* with `tpc.stage=placement` to register a one-shot
key, then opens the *destination* with `tpc.stage=copy` naming that key — the
destination is now the one reading from the source. `kXR_sync` on the
destination handle is the wait: it returns when the transfer has completed,
and only then does the close publish the file.
"""
function tpc_copy(
    src::Storage.XRootDBackend,
    dst::Storage.XRootDBackend;
    overwrite::Bool=false,
    mode::Symbol=:pull,
)
    key = tpc_key()
    origin = "$(get(ENV, "USER", "nobody"))@$(gethostname())"

    placement = tpc_url(
        src,
        [
            "tpc.stage" => "placement",
            "tpc.key" => key,
            "tpc.dst" => dst.url.host,
            "tpc.ttl" => string(TPC_TTL),
        ],
    )
    f = XrdCl.File()
    st, _ = open(f, placement, XrdCl.OpenFlags.Read; src.creds...)
    XrdCl.isOK(st) || return tpc_open_result(st, "source placement open failed")
    close(f)

    copyurl = tpc_url(
        dst,
        [
            "tpc.stage" => "copy",
            "tpc.key" => key,
            "tpc.src" => src.url.host,
            "tpc.lfn" => src.path,
            "tpc.org" => origin,
            "tpc.ttl" => string(TPC_TTL),
        ],
    )
    flags =
        XrdCl.OpenFlags.Write | (overwrite ? XrdCl.OpenFlags.Delete : XrdCl.OpenFlags.New)
    d = XrdCl.File()
    st, _ = open(d, copyurl, flags; dst.creds...)
    XrdCl.isOK(st) || return tpc_open_result(st, "destination copy open failed")

    sst, _ = XrdCl.sync(d)
    cst, _ = close(d)
    XrdCl.isOK(sst) || return :error, "third-party transfer failed: $(sst.message)"
    XrdCl.isOK(cst) || return :error, "third-party transfer close failed: $(cst.message)"
    return :ok, "third-party copy of $(src.path) to $(dst.url.host)"
end

"""
A server without TPC support answers the rendezvous open with
`kXR_Unsupported` / "not supported"; that is a missing capability, not a
failed transfer, so it maps to `:unsupported` and lets the caller fall back.
"""
function tpc_open_result(st, what::AbstractString)
    unsupported = st.code == 3013 || occursin(r"unsupported|not supported"i, st.message)
    return (unsupported ? :unsupported : :error), "$what: $(st.message)"
end

"Append TPC rendezvous CGI to a file URL, keeping any query it already has."
function tpc_url(b::Storage.XRootDBackend, params::Vector{Pair{String,String}})
    url = Storage.file_url(b)
    sep = occursin('?', url) ? "&" : "?"
    return url * sep * join(("$k=$v" for (k, v) in params), "&")
end

"One-shot rendezvous key: the source will only honour it once, for this copy."
tpc_key() = bytes2hex(rand(UInt8, 16))
