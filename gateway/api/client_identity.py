"""B57 - client identity for the API's per-client rate limits.

Pure functions, no I/O. The API binds 127.0.0.1 only, so it never sees a
client's address on the socket: every request arrives from the local edge
nginx. Identity therefore comes from two headers that EVERY API proxy
location in gateway/edge/ sets itself with `proxy_set_header`, which
replaces any client-sent value:

    X-Real-IP      $remote_addr (after real_ip, on the cp-loopback listener)
    X-Pocvpn-Edge  a constant per server block (KNOWN_EDGES)

Neither header is a security boundary against local processes (anything
on the host can reach 127.0.0.1:8443 directly with arbitrary headers);
they only let the API tell remote clients apart. Anything missing,
duplicated, malformed, or loopback maps to UNATTRIBUTED / EDGE_UNKNOWN -
a single, still-limited bucket, never "no limit".

Never derived from `Host` (a client chooses it on a default_server) or
from X-Forwarded-For (`$proxy_add_x_forwarded_for` appends to whatever
the client sent).
"""
import ipaddress
from dataclasses import dataclass

EDGE_CP_LOOPBACK = "cp-loopback"
EDGE_PUBLIC_443 = "public-443"
EDGE_UNKNOWN = "unknown"
KNOWN_EDGES = frozenset({EDGE_CP_LOOPBACK, EDGE_PUBLIC_443})

UNATTRIBUTED = "unattributed"

IPV6_PREFIX_LENGTH = 64

# Longest valid textual address is an IPv6 address with an embedded IPv4
# suffix (45 chars); anything longer is rejected before parsing.
_MAX_ADDRESS_CHARS = 45


@dataclass(frozen=True)
class ClientIdentity:
    edge: str
    client: str

    def limiter_key(self, endpoint_class):
        return f"{self.edge}|{self.client}|{endpoint_class}"


def normalize_edge(values):
    """`values` is every X-Pocvpn-Edge header value present (headers.get_all
    result, or None). Exactly one, exactly matching a known edge; anything
    else is EDGE_UNKNOWN."""
    if not values or len(values) != 1:
        return EDGE_UNKNOWN
    value = values[0]
    return value if value in KNOWN_EDGES else EDGE_UNKNOWN


def normalize_client(values):
    """`values` is every X-Real-IP header value present. Returns a stable
    client key: IPv4 as /32, IPv6 as its /64, IPv4-mapped IPv6 as the
    IPv4 address. Missing, duplicated, malformed, scoped, loopback or
    unspecified addresses return UNATTRIBUTED."""
    if not values or len(values) != 1:
        return UNATTRIBUTED
    raw = values[0].strip()
    if not raw or len(raw) > _MAX_ADDRESS_CHARS or "%" in raw:
        return UNATTRIBUTED
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return UNATTRIBUTED
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback or address.is_unspecified:
        return UNATTRIBUTED
    if address.version == 4:
        return f"{address}/32"
    network = ipaddress.ip_network(f"{address}/{IPV6_PREFIX_LENGTH}", strict=False)
    return str(network)


def from_header_values(real_ip_values, edge_values):
    return ClientIdentity(edge=normalize_edge(edge_values), client=normalize_client(real_ip_values))
