# Keeping credentials out of everything a person reads. A bearer token is a
# password with a longer name: printed once into a log, a CI transcript or an
# exception message, it is as compromised as one typed into a chat window. The
# structs that carry credentials therefore print what they *are* rather than
# what they hold, and the URLs that carry them in a query string are rewritten
# on the way out.

"""
Keyword and query-parameter names whose values are credentials. Both spellings
of the same thing are listed where the wire and the API disagree — `authz` is
what an XRootD URL calls the token that the API calls `token`.
"""
const SECRET_NAMES = Set([
    "token",
    "keytab",
    "passphrase",
    "authz",
    "access_token",
    "id_token",
    "refresh_token",
    "password",
    "access_key",
    "secret_key",
    "session_token",
    "signature",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
])

"What stands in for a credential that is not being printed."
const REDACTED = "<redacted>"

"""
    is_secret(name) -> Bool

Whether a keyword or query parameter holds a credential. Matching is
case-insensitive because query strings are written both ways.
"""
is_secret(name::AbstractString) = lowercase(String(name)) in SECRET_NAMES
is_secret(name::Symbol) = is_secret(String(name))

"""
    redacted(value) -> Any

A credential as it may be shown. `nothing` and the empty string stay
themselves — "no token was supplied" and "a token is being withheld from this
message" are different diagnoses of the same failed request, and collapsing
them turns a printout into a worse debugging aid than no printout at all.
"""
redacted(::Nothing) = nothing
redacted(v::AbstractString) = isempty(v) ? v : REDACTED
redacted(v) = REDACTED

"""
    redact(opts::AbstractDict) -> Dict

A copy of a credential-carrying option dictionary with the credentials
replaced. The keys stay: which credential a handle was given is exactly what
someone reading a failure wants to know.
"""
function redact(opts::AbstractDict{Symbol,<:Any})
    return Dict{Symbol,Any}(k => (is_secret(k) ? redacted(v) : v) for (k, v) in opts)
end

"""
    redact_url(url) -> String

A URL with the credential-bearing values in its query string replaced. An
XRootD `?authz=Bearer%20…` CGI element, a presigned S3 signature and an
`?access_token=` are all credentials that travel as part of the path, and a
URL is the one thing a client prints on every error it raises.
"""
function redact_url(url::AbstractString)
    s = String(url)
    q = findfirst('?', s)
    q === nothing && return s
    head = s[1:q]
    parts = String.(split(s[(q + 1):end], '&'; keepempty=true))
    for (i, part) in pairs(parts)
        eq = findfirst('=', part)
        eq === nothing && continue
        name = part[1:(eq - 1)]
        is_secret(name) || continue
        parts[i] = "$name=$REDACTED"
    end
    return head * join(parts, '&')
end
