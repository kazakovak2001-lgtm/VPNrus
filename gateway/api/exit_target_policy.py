"""Exit Target ACL - the ONE canonical list of destination networks VPN exit
traffic must never reach. Consumed by:

- xray_config_renderer: explicit `finalRules` block on the `freedom`
  outbound (enforced by Xray at dial time, AFTER it resolves a domain and
  against the exact IP it then dials - see that module's docs).
- gateway/nftables/pocvpn.nft.template: the `exit_blocked_v4/v6` sets the
  AWG forward chain rejects (host/network layer, before masquerade). The
  template cannot import Python, so test_exit_target_policy.py asserts its
  sets equal the tuples below exactly.

The B46-4P.3 Hysteria2 server config (PR #132, application layer) carries its
own list for the same destination classes; the model is defense in depth,
application ACL -> host/network ACL, neither replacing the other.

Why each class is blocked - a VPN exit must be an Internet proxy, never a
proxy into the gateway host, its cloud VPC, or special-purpose space:
"""
import ipaddress

BLOCKED_IPV4_CIDRS = (
    "0.0.0.0/8",        # "this network" (RFC 1122); 0.0.0.0 reaches local listeners
    "10.0.0.0/8",       # RFC 1918 private (also the AWG tunnel 10.77.0.0/24)
    "100.64.0.0/10",    # RFC 6598 shared/CGNAT space
    "127.0.0.0/8",      # loopback - the API (8443-8446), Xray 2100, auth backends
    "169.254.0.0/16",   # link-local, incl. the EC2 metadata endpoint 169.254.169.254
    "172.16.0.0/12",    # RFC 1918 private - includes the AWS VPC 172.31.0.0/16
    "192.0.0.0/24",     # IETF protocol assignments (RFC 6890)
    "192.0.2.0/24",     # TEST-NET-1 documentation
    "192.88.99.0/24",   # deprecated 6to4 relay anycast (RFC 7526)
    "192.168.0.0/16",   # RFC 1918 private
    "198.18.0.0/15",    # benchmarking (RFC 2544)
    "198.51.100.0/24",  # TEST-NET-2 documentation
    "203.0.113.0/24",   # TEST-NET-3 documentation
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved, incl. limited broadcast 255.255.255.255
)

# NEVER ::ffff:0:0/96 (IPv4-mapped): Go's net.IPNet.Contains normalizes it
# to 0.0.0.0/0 and would match EVERY IPv4 address (found in B46-4P.3).
# IPv4-mapped destinations are matched by the IPv4 list above instead.
BLOCKED_IPV6_CIDRS = (
    "::/128",           # unspecified
    "::1/128",          # loopback
    "64:ff9b::/96",     # NAT64 well-known prefix - embeds IPv4 (e.g. metadata)
    "64:ff9b:1::/48",   # local-use NAT64 (RFC 8215)
    "100::/64",         # discard-only (RFC 6666)
    "2001:db8::/32",    # documentation
    "fc00::/7",         # unique local (ULA)
    "fe80::/10",        # link-local
    "fec0::/10",        # deprecated site-local
    "ff00::/8",         # multicast
)

EC2_METADATA_IPV4 = "169.254.169.254"

BLOCKED_NETWORKS = tuple(ipaddress.ip_network(c) for c in BLOCKED_IPV4_CIDRS + BLOCKED_IPV6_CIDRS)


def is_blocked(address):
    """True if [address] (str or ip_address) is in the blocked space. An
    IPv4-mapped IPv6 address is judged by its embedded IPv4 address."""
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in net for net in BLOCKED_NETWORKS if net.version == ip.version)


XRAY_BLOCK_OUTBOUND_TAG = "exit-acl-block"


def xray_routing_block_rule():
    """Xray-core routing field rule: literal blocked-IP destinations -> the
    blackhole outbound (infra/conf/router.go `ip` CIDR list)."""
    return {
        "type": "field",
        "ip": list(BLOCKED_IPV4_CIDRS + BLOCKED_IPV6_CIDRS),
        "outboundTag": XRAY_BLOCK_OUTBOUND_TAG,
    }


def xray_freedom_final_rules():
    """Xray-core `freedom.settings.finalRules` (pinned v26.7.28,
    infra/conf/freedom.go FreedomFinalRuleConfig): one block rule, every
    network (no "network" key = all), every port."""
    return [{"action": "block", "ip": list(BLOCKED_IPV4_CIDRS + BLOCKED_IPV6_CIDRS)}]
