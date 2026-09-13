# B35 CDN Origin Deployment Preflight

Status: **FOUNDATION / NOT DEPLOYED / NOT RUSSIA-VERIFIED**.

This gate validates one operator-controlled CDN/XHTTP origin deployment before
any Android runtime selection of `XRAY_XHTTP` is allowed.

It complements `gateway/tools/ingress_preflight.py`; it does not replace the
existing ingress-role preflight or the existing end-to-end relay proof.

## Command

Run on the deployed ingress/origin host:

    sudo python3 gateway/tools/cdn_origin_preflight.py --env-file /etc/pocvpn/ingress.env --nginx-config /etc/nginx/sites-enabled/pocvpn-cdn-origin.conf

For repository/static validation without live nginx/listener/DNS checks:

    python3 gateway/tools/cdn_origin_preflight.py --env-file /path/to/ingress.env --nginx-config /path/to/pocvpn-cdn-origin.conf --static-only

## What PASS means

The preflight fails closed unless all applicable invariants hold:

- ingress kind is explicitly `cdn_fronted`;
- the complete B35 XHTTP env group exists;
- the first executable mode is `packet-up`;
- the nginx XHTTP location exactly matches `NOVA_INGRESS_XHTTP_PATH`;
- nginx proxies only to the configured `127.0.0.1:<XHTTP_SERVER_PORT>`;
- the fixed backend Host matches `NOVA_INGRESS_XHTTP_HOST`;
- the tunnel route is restricted to explicit globally-routable CIDRs and
  terminates its top-level access rules with `deny all`;
- `satisfy any` cannot bypass that source-network boundary;
- only the first-slice GET/POST request shape is admitted;
- caching/request buffering/response buffering are disabled;
- nginx's request-body ceiling is not smaller than
  `NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES`;
- client IP forwarding headers are not passed to Xray;
- no `REPLACE_WITH_*` placeholder survives in the deployed config.

The live/default mode additionally checks:

- `nginx -t` succeeds;
- the supplied config file is actually loaded by `nginx -T`;
- Xray is listening on the configured IPv4 loopback backend and not on a
  non-loopback TCP address for that port;
- the client-facing CDN hostname resolves;
- a direct local request to the protected XHTTP path returns HTTP 403.

## What PASS does NOT mean

The tool does not prove that the selected provider owns the configured source
CIDRs. Operators must obtain those ranges from the provider's current official
documentation.

It does not prove CDN edge reachability, CDN cache/streaming compatibility,
XHTTP acceptance through the external CDN, ingress-to-EXIT relay success,
Internet data-plane success through the full chain, or Russian
restricted-network/hard-whitelist bypass.

Those claims require the separate full-chain test:

`Android -> CDN edge -> origin nginx -> XHTTP ingress -> authenticated EXIT -> Internet`

The final censorship-resistance claim still requires testing from the intended
restricted Russian network.

## Runtime boundary

`XRAY_XHTTP` remains `NOT_IMPLEMENTED` in the live Android transport registry
until a real CDN deployment has passed this preflight and the full external
data-plane gate. This document does not authorize enabling Smart Connect
selection.
