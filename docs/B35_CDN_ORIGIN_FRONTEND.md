# B35 CDN origin frontend

Status: **STOCKHOLM DEPLOYED / SERVER-SIDE RELAY VERIFIED / NOT ANDROID OR RUSSIA-VERIFIED**. See [B35 Stockholm rollout](B35_STOCKHOLM_XHTTP_ROLLOUT_2026-09-14.md).

The origin path is intentionally split into three authorities:

1. `controlPlaneHostname` — signed Android provisioning authority.
2. `clientFacingHostname:443` — signed CDN data-plane edge Android dials.
3. `originTlsServerName` / `originHostHeader` — operator-controlled CDN-to-origin TLS/HTTP authority.

None may be inferred from another.

## Origin boundary

The nginx frontend terminates CDN-to-origin TLS on public 443. Only the
dedicated `/nova-xhttp/` subtree is proxied to Xray on `127.0.0.1:2100`.
The Xray renderer itself hard-codes the backend listener to loopback and
routes that inbound only to the authenticated relay EXIT; it never renders a
`freedom` outbound for the ingress role.

The nginx route is a **prefix** because pinned Xray-core v26.7.28 places
session and sequence components in the request path by default. An exact
`location = /nova-xhttp/` would reject real packet-up traffic.

## Host and path contract

At provider deployment time all of these values must agree:

- signed profile `xhttp.path` = `/nova-xhttp/`;
- `NOVA_INGRESS_XHTTP_PATH` = `/nova-xhttp/`;
- nginx `location ^~ /nova-xhttp/`;
- signed profile `requests.originHostHeader`;
- `NOVA_INGRESS_XHTTP_HOST`;
- nginx `proxy_set_header Host ...`.

The incoming CDN request Host is never trusted as backend authority.

## Caching and buffering

The tunnel location disables nginx proxy cache, request buffering, and
response buffering and sends `Cache-Control: no-store`. This is necessary
but not sufficient evidence about an external CDN. The CDN provider's cache
and streaming behavior must still pass the B35 end-to-end data-plane test.

## Exposure rule

TCP/2100 is private loopback plumbing. Do not add a cloud firewall,
security-group, nftables, or public nginx listener for it.

Public TCP/443 also requires an origin-access boundary for the tunnel path.
`/nova-xhttp/` must accept requests only from the selected CDN's current,
official origin-source CIDRs, or from an equivalent authenticated-origin
mechanism supported by that provider. The example nginx configuration is
fail-closed: it contains `REPLACE_WITH_CDN_SOURCE_CIDR` followed by
`deny all;`. Duplicate the `allow` directive for every required provider
source range before deployment. Do not substitute client/eyeball address
ranges for CDN origin-source ranges.

## Truth boundary

A successful nginx syntax check, DNS resolution, TLS handshake, TCP/443
connection, or origin health response does **not** make `CHAIN_CDN` verified.
Verification requires the full Android -> CDN -> origin -> XHTTP -> ingress
-> authenticated EXIT -> Internet path from the intended restricted network.
