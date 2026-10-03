"""B57 - layered request admission for pocvpn-api.

Every endpoint calls `AdmissionControl.admit(identity, endpoint_class)`
right after its own config-availability check and before any header/body
validation, store read, OS lock or provisioning. Layers, in order:

    1. per-client     (edge, client address/prefix, endpoint class)
    2. edge ceiling   (only edges listed in EDGE_CEILINGS, e.g. staging)
    3. class ceiling  (bootstrap / activation / relay_probe / field_enroll)
    4. global ceiling (the pre-B57 hard ceiling, one bucket per process)

Gateway self-connect (client_identity.GATEWAY_SELF, bootstrap class only):
layers 1 and 3 are replaced by ONE self-scope limiter (SELF_SCOPE_LIMITS),
keyed (edge, gateway-self, class); layers 2 and 4 still apply. The self
scope never spends an ordinary client's per-client bucket or the
bootstrap class ceiling, and ordinary clients never spend the self scope.
For every other class a GATEWAY_SELF request takes the ordinary path with
`gateway-self` as its client key.

A request rejected by a layer never reaches the later layers, so it never
consumes their budget: one client is capped at its own per-client budget
of every shared ceiling. A rejection by a later layer has already
consumed the earlier ones (the client's own buckets), which is intended.

The global ceiling keeps its pre-B57 value and remains the one shared,
process-wide safety ceiling. The class, edge and self-scope ceilings are
separate fixed-window limiters (ratelimit.py): each window starts at that
limiter's own first request, so the windows are not aligned with the
global window. A class can therefore admit up to twice its ceiling inside
one global window (e.g. bootstrap 2 x 20), and bootstrap + relay_probe
traffic together can use the whole global ceiling. This design caps each
class; it does NOT guarantee activation any reserved number of global
requests.

All state is process-local and in memory (see ratelimit.py): one process
per role (pocvpn-api 8443, -ingress 8444, -xhttp-ingress 8445), reset on
restart. Values marked PROPOSED / NOT YET VERIFIED were not derived from
measured traffic; they are deliberately kept in this one table.
"""
from . import client_identity, ratelimit

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
    # PROPOSED / NOT YET VERIFIED - the staging Cloudflare listener is
    # capped at a third of the global ceiling per window of its own (at
    # most 2 x 20 inside one unaligned global window), so staging traffic
    # alone cannot exhaust the production vhosts served by the same process.
    "cp-loopback": 20,
}

SELF_SCOPE_LIMITS = {
    # PROPOSED / NOT YET VERIFIED - the same value as the bootstrap class
    # ceiling, not derived from measured traffic. Every Xray connect
    # confirmation and every relayed-session watchdog probe (one per 20 s,
    # android XrayCoreController) on this gateway lands here, so 20 / 10 s
    # is about 40 concurrently watched relayed sessions (computed, not
    # measured), less whatever connect confirmations use.
    CLASS_BOOTSTRAP: 20,
}


def _limiter(max_requests, clock):
    return ratelimit.RateLimiter(max_requests, WINDOW_SECONDS, clock=clock)


class AdmissionControl:
    def __init__(self, clock, global_limiter):
        self.global_limiter = global_limiter
        self.class_limiters = {name: _limiter(limit, clock) for name, limit in CLASS_CEILINGS.items()}
        self.per_client_limiters = {name: _limiter(limit, clock) for name, limit in PER_CLIENT_LIMITS.items()}
        self.edge_limiters = {edge: _limiter(limit, clock) for edge, limit in EDGE_CEILINGS.items()}
        self.self_scope_limiters = {name: _limiter(limit, clock) for name, limit in SELF_SCOPE_LIMITS.items()}

    def admit(self, identity, endpoint_class):
        if endpoint_class not in self.class_limiters:
            raise ValueError(f"unknown endpoint class: {endpoint_class}")
        self_scope = self.self_scope_limiters.get(endpoint_class)
        if identity.client == client_identity.GATEWAY_SELF and self_scope is not None:
            if not self_scope.allow(identity.limiter_key(endpoint_class)):
                return False
            if not self._edge_allows(identity):
                return False
            return self.global_limiter.allow("global")
        per_client = self.per_client_limiters.get(endpoint_class)
        if per_client is not None and not per_client.allow(identity.limiter_key(endpoint_class)):
            return False
        if not self._edge_allows(identity):
            return False
        if not self.class_limiters[endpoint_class].allow(endpoint_class):
            return False
        return self.global_limiter.allow("global")

    def _edge_allows(self, identity):
        edge_limiter = self.edge_limiters.get(identity.edge)
        return edge_limiter is None or edge_limiter.allow(identity.edge)
