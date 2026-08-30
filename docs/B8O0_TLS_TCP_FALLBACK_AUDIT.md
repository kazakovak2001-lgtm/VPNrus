# B8O0 - TLS/TCP fallback runtime audit

Research-only slice, mirroring B8K0's own scope discipline. **No Android or
gateway source changed.** `TransportKind.TLS_TCP` remains unregistered
(`TransportRegistry` never emits a descriptor for it - `SmartConnectDecisionEngine`'s
own `PREFERRED_ORDER` already names it, but nothing today can select it).
`docs/ROADMAP.md`'s `TLS/TCP fallback` row is unchanged (`PLANNED`, "No
code") - this document does not begin runtime implementation, which stays
blocked by the roadmap's own sequencing rule ("no new transport before B10
is complete on a real VPS") pending a deliberate exception decision, the
same way Xray/REALITY's was made only after that transport was already
built and physically verified.

Every claim below citing xray-core internals is pulled from the ACTUAL
pinned source (`github.com/xtls/xray-core`, commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, tag `v26.7.28` - the exact same
commit already cited in `docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md`), fetched and
read directly for this audit - nothing here is guessed or remembered from
general knowledge of the TLS/REALITY spec.

## The central finding: TLS/TCP fallback is a config variant of the EXISTING Xray runtime, not a new transport stack

`infra/conf/transport_internet.go`'s `StreamConfig.Build()` switches on the
`security` JSON field:

```go
switch strings.ToLower(c.Security) {
case "", "none":
case "tls":
    tlsSettings := c.TLSSettings
    ...
case "reality":
    ts, err := c.REALITYSettings.Build()
    ...
case "xtls":
    return nil, errors.PrintRemovedFeatureError(...) // removed, irrelevant here
default:
    return nil, errors.New(`Unknown security "` + c.Security + `".`)
}
```

`"tls"` is a first-class, already-supported sibling of `"reality"` - not
something that needs new xray-core code, a new wrapper, or a new pinned
dependency. `infra/conf/vless.go`'s outbound config (user id/encryption/flow)
is completely independent of which security mode is chosen - the SAME
`"vless"` outbound protocol, the SAME user-id-based auth model, works with
either `security: "reality"` or `security: "tls"`. `flow` (the
`xtls-rprx-vision` optimization this app's REALITY config already uses) is
accepted empty (`""`) by the same validation - a plain TLS fallback simply
omits it, it is not REALITY/XTLS-exclusive at the config-parsing layer.

This means every piece of Android-side infrastructure already built and
physically verified for B8I6-B8I8 is protocol-agnostic and directly
reusable, unchanged:

- `NovaXrayVpnService` (the `VpnService` subclass, TUN ownership, lifecycle
  invariants) - has no REALITY-specific logic anywhere in it.
- `XrayCoreController`/`LibXrayCoreRuntime` (the AndroidLibXrayLite
  wrapper boundary) - takes a config JSON string; does not care what
  `streamSettings.security` says.
- The self-UID `addDisallowedApplication` socket-protection mechanism
  (`docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md` §3/§4) - unrelated to security mode.
- `XrayProfileStore`/`XrayProfileRepository` persistence pattern,
  `XrayProfileProvisioner`, the `/v1/xray-profile` activation flow shape.
- `VpnController`'s conditional-registration pattern
  (`supportedKinds`/`xrayProfileRepository`-gated) - the exact same shape
  would gate `TransportKind.TLS_TCP`.

## What TLS/TCP fallback specifically needs that does NOT exist yet

1. **A TLS-mode config type**, client-side - either a new
   `XrayVlessTlsConfig` sibling of `XrayVlessRealityConfig`, or a shared
   base with a REALITY-specific and a TLS-specific variant. Per
   `infra/conf/transport_security.go`'s `TLSConfig` struct (fetched for
   this audit, same pinned commit):

   ```go
   type TLSConfig struct {
       AllowInsecure bool             `json:"allowInsecure"`
       Certs         []*TLSCertConfig `json:"certificates"`
       ServerName    string           `json:"serverName"`
       ALPN          *StringList      `json:"alpn"`
       Fingerprint   string           `json:"fingerprint"`
       // ... (13 more fields, all optional with safe defaults)
   }
   ```

   A minimal, correct config needs only `serverName` (SNI) - every other
   field has a safe default (`allowInsecure` defaults false; normal
   platform/system CA trust is used, matching this app's own existing "never
   pinned, never trust-all" discipline for `HttpsGatewayReachabilityProbe`).
   No `realityPublicKey`/`shortId`/REALITY key-pair material is needed at
   all - a materially SIMPLER client credential shape than REALITY's.

2. **A renderer branch**, client-side - `XrayConfigRenderer` (currently
   REALITY-only per its own docs: "Deliberately excludes... non-REALITY
   security") needs a second `streamSettings` shape:
   `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"..."}}`
   instead of `{"network":"tcp","security":"reality","realitySettings":{...}}`.
   The `outbounds[0].protocol`/`settings.vnext` block is unchanged (per the
   vless.go finding above).

3. **A real, publicly-trusted TLS certificate on the gateway** for
   whatever hostname/IP the client's `serverName` targets. This is the one
   genuinely NEW *infrastructure* dependency, but it is **already
   satisfied**: `gateway/edge/nginx-pocvpn.conf` already terminates real
   TLS for the control-plane API using
   `ssl_certificate /etc/letsencrypt/live/152.70.43.1/fullchain.pem` -
   already provisioned, already the exact cert this app's own physically
   verified B8I8 failover test exercised over HTTPS. A TLS/TCP Xray inbound
   could reuse those same certificate files directly - no new ACME/cert
   workflow needed.

4. **A gateway-side Xray inbound** (a second inbound alongside the
   existing VLESS+REALITY one, or a config toggle) serving VLESS+TLS on
   its own port, plus the parallel provisioning/activation plumbing
   `gateway/api/xray_activation.py`/`xray_provisioning.py`/
   `xray_config_renderer.py` already do for REALITY - the same shape of
   work, a second code path through already-existing modules, not new
   modules.

5. **Client registration wiring** - a `VlessTlsTransport` (or an extended
   `VlessRealityTransport`) registering under `TransportKind.TLS_TCP` in
   `VpnController`/`MainViewModel.buildTransportRegistry()`, mirroring
   B8I6/B8I7's exact pattern for `XRAY_REALITY`.

6. **Physical end-to-end verification** on the real VPS, the same
   discipline B8I8 already proved for AWG->Xray/REALITY failover - nothing
   here may be claimed IMPLEMENTED/VERIFIED without that evidence.

## Relative scope estimate (not a commitment, not a schedule)

Meaningfully SMALLER than the original Xray/REALITY build: no new native
library, no new `VpnService`, no new TUN/socket-protection design, no new
gomobile build pipeline - all of that is reused unchanged. The remaining
work is comparable in shape to B8K2-B8K5 (gateway activation/provisioning)
plus B8I6-B8I8 (client registration/wiring/failover) for a SECOND Xray
config variant, minus the B8K0/B8K1 foundational research those needed
(this document covers the equivalent ground for TLS/TCP already). Still a
genuine multi-slice effort, not a single PR - not smaller than "several
slices," just smaller than "a second whole transport stack."

## Recommended first real slice, when/if this is unblocked

The lowest-risk starting point is the config-and-renderer layer only
(item 1+2 above): a pure `XrayVlessTlsConfig`/`XrayConfigRenderer` TLS
branch, unit-tested exactly like the existing REALITY validation/rendering
code, with `TransportKind.TLS_TCP` still NOT registered in
`TransportRegistry` afterward (mirroring B8K1B's own "isolated adapter
shell, not yet wired" discipline) - testable, reviewable, zero runtime/
gateway risk, before any gateway-side or VpnController wiring begins.

## Open items this audit did NOT resolve

- Whether `xray-core`'s TLS inbound (server side, not the client-side
  code audited above) needs anything beyond the existing cert files - not
  independently verified against `infra/conf/transport_internet.go`'s
  server-side `TLSConfig` handling (only the client-side path was read for
  this audit, since that's what `XrayConfigRenderer` emits).
- Whether serving VLESS+REALITY and VLESS+TLS on the SAME gateway
  simultaneously requires two separate listening ports/xray-core inbound
  entries, or can share one - not verified against `infra/conf/xray.go`'s
  `InboundDetourConfig` multi-inbound handling.
- No `TLSConfig`-side field beyond `serverName` was evaluated for whether
  Nova should ever set it (e.g. `fingerprint` for uTLS-style client
  fingerprinting, matching REALITY's own `fingerprint` field) - deferred
  to whoever picks up the config-and-renderer slice above.
