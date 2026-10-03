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

Gateway self-connect: Xray's connect confirmation and the relayed-session
watchdog (android XrayCoreController: `https://<gateway>/v1/manifest`) leave
the gateway's own Xray `freedom` outbound and dial the gateway's own public
address, so nginx sees the gateway itself as the client - one address for
every user of that gateway. When X-Real-IP is EXACTLY one of the operator-
configured `self_addresses` (AppConfig.gateway_self_addresses), the client
is GATEWAY_SELF, a separate admission scope (admission.py), never an
ordinary client bucket and never UNATTRIBUTED. No request header can claim
this scope: on the public vhosts X-Real-IP is the TCP peer, which no remote
client can set to the gateway's own address. Any traffic that egresses
this gateway's own Xray exit towards its own address (including a VPN
user's tunnelled request) does land in this scope - it is "traffic from
this host", not "trusted traffic", and stays limited.
"""
import ipaddress
from dataclasses import dataclass

EDGE_CP_LOOPBACK = "cp-loopback"
EDGE_PUBLIC_443 = "public-443"
EDGE_UNKNOWN = "unknown"
KNOWN_EDGES = frozenset({EDGE_CP_LOOPBACK, EDGE_PUBLIC_443})

UNATTRIBUTED = "unattributed"
GATEWAY_SELF = "gateway-self"

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


def parse_address(raw):
    """One textual IP address -> ipaddress object (IPv4-mapped IPv6 as
    IPv4), or None for anything malformed, scoped or over-long."""
    raw = raw.strip()
    if not raw or len(raw) > _MAX_ADDRESS_CHARS or "%" in raw:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address


def normalize_client(values, self_addresses=frozenset()):
    """`values` is every X-Real-IP header value present. Returns a stable
    client key: GATEWAY_SELF for an exact match in `self_addresses` (a set
    of parse_address() results), else IPv4 as /32, IPv6 as its /64,
    IPv4-mapped IPv6 as the IPv4 address. Missing, duplicated, malformed,
    scoped, loopback or unspecified addresses return UNATTRIBUTED."""
    if not values or len(values) != 1:
        return UNATTRIBUTED
    address = parse_address(values[0])
    if address is None or address.is_loopback or address.is_unspecified:
        return UNATTRIBUTED
    if address in self_addresses:
        return GATEWAY_SELF
    if address.version == 4:
        return f"{address}/32"
    network = ipaddress.ip_network(f"{address}/{IPV6_PREFIX_LENGTH}", strict=False)
    return str(network)


def from_header_values(real_ip_values, edge_values, self_addresses=frozenset()):
    return ClientIdentity(
        edge=normalize_edge(edge_values),
        client=normalize_client(real_ip_values, self_addresses),
    )
