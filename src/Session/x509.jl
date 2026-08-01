# X.509 client credentials for TLS. Discovery order and file layout follow
# the grid conventions (a delegated proxy from `voms-proxy-init` holds the
# proxy chain and its unencrypted key in one PEM), so a `roots://` session
# presents the same identity the C++ client would.

"A client X.509 identity: a certificate (chain) PEM and its private key PEM."
struct X509Credentials
    cert::String
    key::String
end

"""
    discover_x509(; cert=nothing, key=nothing, proxies=x509_proxy_candidates())
        -> Union{X509Credentials,Nothing}

Locate the client's X.509 identity, in the grid tools' order: the explicit
`cert` argument (`key` defaults to `cert`, since a proxy keeps both in one
file), `\$X509_USER_PROXY`, `/tmp/x509up_u<uid>`, `\$X509_USER_CERT` +
`\$X509_USER_KEY`, then `~/.globus/usercert.pem` + `~/.globus/userkey.pem`.
Returns `nothing` when no readable pair exists — having no credential is not
an error, it just means the handshake carries no client certificate.

`proxies` overrides the proxy search path, for a caller (or a test) that keeps
delegated proxies somewhere other than the two conventional locations.
"""
function discover_x509(;
    cert::Union{AbstractString,Nothing}=nothing,
    key::Union{AbstractString,Nothing}=nothing,
    proxies=x509_proxy_candidates(),
)
    if cert !== nothing
        c = String(cert)
        k = key === nothing ? c : String(key)
        isfile(c) || throw(ArgumentError("X.509 certificate not found: $c"))
        isfile(k) || throw(ArgumentError("X.509 private key not found: $k"))
        return X509Credentials(c, k)
    end
    if key !== nothing
        throw(ArgumentError("an X.509 key needs its certificate: pass cert= as well"))
    end

    for path in proxies
        isfile(path) && return X509Credentials(path, path)
    end

    envcert = get(ENV, "X509_USER_CERT", "")
    if !isempty(envcert) && isfile(envcert)
        envkey = get(ENV, "X509_USER_KEY", envcert)
        isfile(envkey) && return X509Credentials(String(envcert), String(envkey))
    end

    home = get(ENV, "HOME", "")
    if !isempty(home)
        c = joinpath(home, ".globus", "usercert.pem")
        k = joinpath(home, ".globus", "userkey.pem")
        isfile(c) && isfile(k) && return X509Credentials(c, k)
    end
    return nothing
end

"The conventional proxy locations, most specific first: `\$X509_USER_PROXY`, then
the per-uid file the grid tools write under `/tmp`."
function x509_proxy_candidates()
    paths = String[]
    p = get(ENV, "X509_USER_PROXY", "")
    isempty(p) || push!(paths, String(p))
    uid = ccall(:getuid, Cuint, ())
    push!(paths, "/tmp/x509up_u$(uid)")
    return paths
end

"""
    x509_ca_path() -> Union{String,Nothing}

The grid CA store (`\$X509_CERT_DIR`, else `/etc/grid-security/certificates`)
when it exists. IGTF CAs are not in the Mozilla bundle OpenSSL.jl loads by
default, so this is added to the verify locations rather than replacing them.
"""
function x509_ca_path()
    dir = get(ENV, "X509_CERT_DIR", "")
    isempty(dir) || return isdir(dir) ? String(dir) : nothing
    return if isdir("/etc/grid-security/certificates")
        "/etc/grid-security/certificates"
    else
        nothing
    end
end

const SSL_FILETYPE_PEM = Cint(1)

"""
    client_ssl_context(; insecure_tls=false, creds=nothing, ca_path=x509_ca_path())

Build the client-side `SSLContext`: the default CA bundle, plus the grid CA
directory when one is present, plus the client certificate when `creds` are
given.
"""
function client_ssl_context(;
    insecure_tls::Bool=false,
    creds::Union{X509Credentials,Nothing}=nothing,
    ca_path::Union{AbstractString,Nothing}=x509_ca_path(),
)
    ctx = OpenSSL.SSLContext(OpenSSL.TLSClientMethod())
    if !insecure_tls && ca_path !== nothing
        OpenSSL.ca_chain!(ctx, String(ca_path))
    end
    creds === nothing || use_x509!(ctx, creds)
    return ctx
end

"""
Load `creds` into `ctx` for client authentication. The certificate is loaded
as a *chain*: a proxy is only meaningful together with the delegation chain
that leads back to the user certificate, and a leaf-only handshake is rejected
by every grid endpoint.
"""
function use_x509!(ctx::OpenSSL.SSLContext, creds::X509Credentials)
    check_key_secrecy(creds.key)
    if encrypted_key(creds.key)
        error(
            "the X.509 private key $(creds.key) is passphrase-encrypted; " *
            "XRootD.jl cannot prompt for it — create a proxy " *
            "(voms-proxy-init / grid-proxy-init) and use that instead",
        )
    end
    if ccall(
        (:SSL_CTX_use_certificate_chain_file, libssl),
        Cint,
        (OpenSSL.SSLContext, Cstring),
        ctx,
        creds.cert,
    ) != 1
        error("failed to load the X.509 certificate chain from $(creds.cert)")
    end
    if ccall(
        (:SSL_CTX_use_PrivateKey_file, libssl),
        Cint,
        (OpenSSL.SSLContext, Cstring, Cint),
        ctx,
        creds.key,
        SSL_FILETYPE_PEM,
    ) != 1
        error("failed to load the X.509 private key from $(creds.key)")
    end
    if ccall((:SSL_CTX_check_private_key, libssl), Cint, (OpenSSL.SSLContext,), ctx) != 1
        error("X.509 certificate $(creds.cert) and key $(creds.key) do not match")
    end
    return ctx
end

"True when the PEM at `path` holds a passphrase-encrypted private key."
function encrypted_key(path::AbstractString)
    head = try
        open(path, "r") do io
            return String(read(io, 4096))
        end
    catch
        return false
    end
    return occursin("BEGIN ENCRYPTED PRIVATE KEY", head) ||
           occursin("Proc-Type: 4,ENCRYPTED", head)
end

"""
Warn when a private key is readable beyond its owner. The grid tools refuse
outright; we warn, because container and network filesystems report permission
bits that the user cannot always fix — but a world-readable key is a leaked
credential either way.
"""
function check_key_secrecy(path::AbstractString)
    mode = try
        filemode(path)
    catch
        return nothing
    end
    if (mode & 0o077) != 0
        @warn "X.509 private key is readable by other users" path mode = string(
            mode & 0o777; base=8
        )
    end
    return nothing
end
