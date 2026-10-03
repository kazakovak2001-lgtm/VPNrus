"""B57 - layered request admission for pocvpn-api.

Every endpoint calls `AdmissionControl.admit(identity, endpoint_class)`
right after its own config-availability check and before any header/body
validation, store read, OS lock or provisioning. Layers, in order:

    1. per-client     (edge, client address/prefix, endpoint class)
    2. edge ceiling   (only edges listed in EDGE_CEILINGS, e.g. staging)
    3. class ceiling  (bootstrap / activation / relay_probe / field_enroll)
    4. global ceiling (the pre-B57 hard ceiling, one bucket per process)

A request rejected by a layer never reaches the later layers, so it never
consumes their budget: one client is capped at its own per-client budget
of every shared ceiling. A rejection by a later layer has already
consumed the earlier ones (the client's own buckets), which is intended.

The global ceiling keeps its pre-B57 value, so the total safety budget is
unchanged. The class ceilings for bootstrap and relay_probe sit below it,
so a /v1/manifest or /v1/relay-health flood can never take the activation
class's reserve.

All state is process-local and in memory (see ratelimit.py): one process
per role (pocvpn-api 8443, -ingress 8444, -xhttp-ingress 8445), reset on
restart. Values marked PROPOSED / NOT YET VERIFIED were not derived from
measured traffic; they are deliberately kept in this one table.
"""
from . import ratelimit

CLASS_BOOTSTRAP = "bootstrap"
CLASS_ACTIVATION = "activation"
CLASS_RELAY_PROBE = "relay_probe"
CLASS_FIELD_ENROLL = "field_enroll"
ENDPOINT_CLASSES = (CLASS_BOOTSTRAP, CLASS_ACTIVATION, CLASS_RELAY_PROBE, CLASS_FIELD_ENROLL)

WINDOW_SECONDS = 10.0

# Hard ceiling: the pre-B57 process-wide global limiter, value unchanged.
GLOBAL_LIMIT = 60

CLASS_CEILINGS = {
    # PROPOSED / NOT YET VERIFIED - one third of the global ceiling.
    CLASS_BOOTSTRAP: 20,
    # Derived: equal to the global ceiling (activation may use all of it
    # when the other classes are idle).
    CLASS_ACTIVATION: GLOBAL_LIMIT,
    # PROPOSED / NOT YET VERIFIED - one third of the global ceiling.
    CLASS_RELAY_PROBE: 20,
    # Derived: field-enroll previously consumed the global limiter; it
    # keeps that same ceiling (its own stricter limiters are unchanged).
    CLASS_FIELD_ENROLL: GLOBAL_LIMIT,
}

PER_CLIENT_LIMITS = {
    # PROPOSED / NOT YET VERIFIED - a client's manifest fetches.
    CLASS_BOOTSTRAP: 10,
    # PROPOSED / NOT YET VERIFIED - two full activation sequences
    # (activate + up to 4 profile requests = 5) per client per window.
    CLASS_ACTIVATION: 10,
    # relay_probe: no per-client layer. A probe's source address is not a
    #   reliable client identity (it depends on how the relayed request
    #   reaches the exit), so a per-address bucket could 429 many unrelated
    #   relay sessions at once; the class ceiling bounds the class instead.
    # field_enroll: no per-client layer; its existing per-public-key and
    #   endpoint-global limiters (server.py) are unchanged.
}

EDGE_CEILINGS = {
    # PROPOSED / NOT YET VERIFIED - the staging Cloudflare listener can use
    # at most a third of the global ceiling, so staging traffic cannot
    # exhaust the production vhosts served by the same process.
    "cp-loopback": 20,
}


def _limiter(max_requests, clock):
    return ratelimit.RateLimiter(max_requests, WINDOW_SECONDS, clock=clock)


class AdmissionControl:
    def __init__(self, clock, global_limiter):
        self.global_limiter = global_limiter
        self.class_limiters = {name: _limiter(limit, clock) for name, limit in CLASS_CEILINGS.items()}
        self.per_client_limiters = {name: _limiter(limit, clock) for name, limit in PER_CLIENT_LIMITS.items()}
        self.edge_limiters = {edge: _limiter(limit, clock) for edge, limit in EDGE_CEILINGS.items()}

    def admit(self, identity, endpoint_class):
        if endpoint_class not in self.class_limiters:
            raise ValueError(f"unknown endpoint class: {endpoint_class}")
        per_client = self.per_client_limiters.get(endpoint_class)
        if per_client is not None and not per_client.allow(identity.limiter_key(endpoint_class)):
            return False
        edge_limiter = self.edge_limiters.get(identity.edge)
        if edge_limiter is not None and not edge_limiter.allow(identity.edge):
            return False
        if not self.class_limiters[endpoint_class].allow(endpoint_class):
            return False
        return self.global_limiter.allow("global")
