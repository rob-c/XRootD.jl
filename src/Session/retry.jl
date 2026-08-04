# Backing off between attempts. Two lanes reconnect and replay — the
# FileSystem lane (`XrdCl.perform`) and a read whose handle lost its session
# (`XrdCl.retry_reopened`) — and the HTTP lane hands the same budget to
# HTTP.jl's own retry controller, so one set of knobs governs all three.

"""
Delay before the first retry, and the ceiling the doubling stops at
(milliseconds). A fixed delay is the wrong shape for both failures worth
retrying: a link that flapped for a moment is back before the first delay is
over, and a server that fell over is not coming back inside any delay short
enough to be worth spending on the first attempt.
"""
const DEFAULT_RETRY_BASE_MS = 200
const DEFAULT_RETRY_CAP_MS = 5_000

"""
Retries after the first attempt, per operation. The window
(`XRDC_MAX_STALL_MS`) alone is not a budget: against a peer that refuses in a
millisecond it permits hundreds of attempts, which is a client hammering a
server that is already in trouble. Whichever of the two runs out first ends
the operation.
"""
const DEFAULT_MAX_RETRIES = 4

"Milliseconds before the first retry (`\$XRDC_RETRY_BASE_MS`)."
retry_base_ms() = env_number("XRDC_RETRY_BASE_MS", DEFAULT_RETRY_BASE_MS)

"Ceiling on one backoff delay (`\$XRDC_RETRY_CAP_MS`)."
retry_cap_ms() = env_number("XRDC_RETRY_CAP_MS", DEFAULT_RETRY_CAP_MS)

"Retries allowed after the first attempt (`\$XRDC_MAX_RETRIES`; 0 disables retrying)."
max_retries() = env_int("XRDC_MAX_RETRIES", DEFAULT_MAX_RETRIES)

"""
    retry_delay(attempt; base_ms, cap_ms, jitter = true) -> Float64

Seconds to wait before retry number `attempt` (1 is the first retry): a
uniform draw from `[0, min(cap, base × 2^(attempt-1))]`.

The jitter is not decoration. Everything that went away took every client with
it, and a fleet that all backed off by the same 200 ms returns as one burst,
which is how a storage element that dropped one link comes back to a
synchronized stampede. Drawing from the window instead of waiting the whole of
it spreads the return out. Pass `jitter = false` for a deterministic delay.
"""
function retry_delay(
    attempt::Integer;
    base_ms::Real=retry_base_ms(),
    cap_ms::Real=retry_cap_ms(),
    jitter::Bool=true,
)
    attempt < 1 && return 0.0
    window = min(Float64(cap_ms), Float64(base_ms) * 2.0^(attempt - 1)) / 1000
    return jitter ? window * rand() : window
end

"""
    backoff!(attempt, deadline; retries = max_retries(), kwargs...) -> Bool

Wait for retry number `attempt`, and answer whether it is still worth making.
`false` — the attempt budget is spent, or the delay would outlast `deadline`
(an absolute `time()`) — means the operation should report the failure it
already has.

A delay that would run past the deadline is not slept: waiting out a window
that has already been decided is time the caller spends learning nothing.
"""
function backoff!(
    attempt::Integer, deadline::Float64; retries::Integer=max_retries(), kwargs...
)
    attempt > retries && return false
    delay = retry_delay(attempt; kwargs...)
    time() + delay >= deadline && return false
    sleep(delay)
    return true
end
