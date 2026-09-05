# B36 - bootstrap tunnel before registration (PoC slice)

**Nothing in this document's server-side section has been executed. Do not
add any server-side peer/firewall rule without the repository owner's
explicit go-ahead, per this repository's merge/infra-safety rule.**

## Problem

A real Russia field test found that a fully unactivated Nova installation
(no persisted profile for any gateway) could not reach either gateway's
control-plane directly:

- Frankfurt's control-plane was not reachable.
- Stockholm's control-plane was not reachable.
- Stockholm's transport ports were also not observed reaching the server.

Since `POST /v1/activate` today requires reaching a gateway's public HTTPS
edge directly, a network that blocks that specific traffic blocks
registration before Nova has any VPN of its own to route around it.

## Approach

```
APK (unactivated)
  -> establish a RESTRICTED bootstrap AmneziaWG tunnel (Frankfurt or Stockholm)
  -> perform the EXISTING /v1/activate + /v1/xray-profile flow THROUGH it
  -> obtain the real, device-specific profile (unchanged persistence/apply)
  -> tear the bootstrap tunnel down
  -> reconnect using the normal provisioned Nova profile (unchanged)
```

The bootstrap tunnel is never the user's actual VPN profile - it exists
only to get one non-technical HTTPS round trip (activation) past a network
that blocks the gateway's public IP directly.

## Why AmneziaWG, not Xray (the actual architectural constraint)

This was the one genuine blocker Phase 1 had to resolve before writing any
code. `net.pocvpn.client.vpn.xray.NovaXrayVpnService.establishInterface`
always calls `builder.addDisallowedApplication(BuildConfig.APPLICATION_ID)`
(`buildXrayVpnPlan`'s own `disallowedApplications` field) - "recursion
prevention" because the pinned AndroidLibXrayLite AAR exposes no
`VpnService.protect()`/fd-callback hook of its own (confirmed: no
`protect`/`ProtectFd` reference anywhere in this repository's Xray
integration). Disallowing the whole app UID is what stops Xray's own
outbound socket from looping back into its own tun - but it ALSO excludes
every other socket that UID opens, including `ProvisioningClient`'s plain
`HttpsURLConnection` activation calls, which run in the SAME app process.
This is the exact same class of bug `docs/PROJECT_ARCHITECTURE.md`'s "B33
relay follow-up, round 2" section already found and fixed for
`HttpRelayEndToEndProbe` - a diagnostic HTTP call made from Nova's own
(VPN-excluded) process never actually traverses a tunnel Nova itself
established, no matter how the tunnel is configured.

`net.pocvpn.client.vpn.AmneziaWgTransport` (`GoBackend`, the upstream
WireGuard-for-Android library) never calls `addDisallowedApplication` for
itself at all - confirmed by reading that file and `VpnController` end to
end: there is no self-exclusion code anywhere in the AWG path. This is
standard WireGuard-Android architecture: `GoBackend` protects only its own
outbound WireGuard UDP socket internally (a JNI-level protect callback),
which is why the normal AWG tunnel already carries the whole device's
traffic, Nova's own process included. This makes AWG the ONLY transport
this codebase already has where a bootstrap tunnel can genuinely carry
`ProvisioningClient`'s own in-process activation traffic - not a
preference, a structural requirement given today's Xray integration.

**Fixing Xray's own exclusion (e.g. wiring a real protect-fd callback into
the pinned AAR) was considered and rejected for this slice** - it would
mean either a different AAR/build of Xray-core or invasive native-bridge
work, real risk for a POC whose whole point is proving the concept exists
at all. If a future slice wants Xray-backed bootstrap (e.g. once XHTTP/CDN
compatibility work from B35 needs it), that AAR-level gap must be closed
first and documented as its own architectural change - not something this
slice attempts.

## Client-side design

- `net.pocvpn.client.bootstrap.BootstrapCatalog` - the deterministic
  Frankfurt -> Stockholm fallback order (no Smart Connect scoring, per task
  scope).
- `net.pocvpn.client.bootstrap.BootstrapIdentity` - the shared, PUBLIC
  bootstrap AWG keypair (placeholder value - see "Trust boundary" below)
  and this peer's own fixed tunnel address.
- `net.pocvpn.client.bootstrap.buildBootstrapAwgConfig`/`bootstrapControlPlaneHost` -
  pure functions building the restricted `AwgConfig` for one gateway:
  `allowedIps = ["<gateway's own public control-plane IP>/32"]` (never
  `0.0.0.0/0`), no app exclusion. `bootstrapControlPlaneHost(gateway)`
  returns EXACTLY the host `ProvisioningClient.activate(...)`/
  `ControlPlaneOriginSetBuilder.forGateway(...)` already dial for that same
  gateway - reusing that one value (never a second, separately-maintained
  literal) is what proves the existing, UNMODIFIED activation call
  genuinely routes into this tunnel.
- `net.pocvpn.client.bootstrap.BootstrapState` - `Idle -> Connecting ->
  Connected -> TearingDown -> Idle`, or `-> Unavailable` once every
  candidate has failed. A separate, small state machine from
  `net.pocvpn.client.vpn.VpnController`'s own `TransportState` - see
  `BootstrapState`'s own docs for why `VpnController` cannot safely own
  this (it is only reachable from Home, which requires a provisioned
  profile).
- `net.pocvpn.client.bootstrap.BootstrapTunnelController` - the ONE owner
  of bootstrap transport lifecycle: builds a fresh transport per candidate
  attempt, awaits a genuinely fresh handshake (reusing
  `net.pocvpn.client.vpn.isFreshHandshake`, the SAME predicate
  `VpnController.awaitFreshHandshake` already uses - never "interface up"
  alone), advances to the next candidate on failure, stops after the known
  set, tears down on request.
- `net.pocvpn.client.bootstrap.BootstrapActivationOrchestrator` - the
  single top-level owner (task requirement 8) composing the tunnel
  controller with `MainViewModel.performActivation` (see below) and
  producing a closed `BootstrapActivationOutcome` (Success /
  AlreadyProvisioned / BootstrapUnavailable / Unauthorized / Revoked /
  Expired / DeviceLimitReached / NetworkOrProvisioningError /
  ProfilePersistFailed).
- `net.pocvpn.client.MainViewModel.performActivation` - the EXACT body
  `activateDevice()` already executed, extracted verbatim (behavior-
  preserving refactor, not a rewrite) into an awaitable private suspend
  function so the orchestrator can call it directly and observe the real
  terminal `ProvisioningUiState` (persistence, Xray/TLS provisioning,
  gateway-identity cross-check, diagnostics - all of it) before deciding to
  tear the bootstrap tunnel down. `activateDevice()` itself is now a thin,
  behaviorally-identical wrapper - the B15 additional-gateway activation
  path keeps calling it directly, unaffected.
- `net.pocvpn.client.MainViewModel.activateDeviceViaBootstrap` - the new
  entry point the mandatory first-run `ActivationScreen` call site now uses
  instead of `activateDevice` directly (same screen, same
  `[activation code] [Activate]` UX - no new UI surface). Skips bootstrap
  entirely (delegates straight to `activateDevice`) whenever ANY gateway is
  already provisioned (task requirement 9's case F).
- `net.pocvpn.client.provisioning.ProvisioningUiState.BootstrapUnavailable` -
  a new, distinct terminal state, with its own non-technical copy, so a
  pure "we could not even reach the network" failure is never shown as
  "Invalid activation" (see the error-taxonomy fix below).
- `net.pocvpn.client.bootstrap.BootstrapDiagnosticsRecorder` - a small,
  separate, equally-sanitized recorder (reuses the existing
  `DiagnosticEvent`/`DiagnosticEventType` shape) for the bootstrap-specific
  event set requirement 11 asks for. Kept separate from
  `SupportDiagnosticsRecorder` because that recorder's session model
  requires a live network/restriction-classifier snapshot that does not
  exist yet at the point bootstrap runs (see that class's own docs).

## Error-taxonomy fix (task requirement 10)

`net.pocvpn.client.ui.ProductFlowPresentation.toActivationErrorText` had a
real, pre-existing bug: its `Error` branch mapped EVERY
`ProvisioningUiState.Error` other than the literal string "service
temporarily unavailable" to `"Invalid activation"` - collapsing a plain
network timeout, a malformed response, or a bad request into the exact same
text as a real HTTP 401 credential rejection. Fixed: `Error` now reads as a
generic, non-technical connectivity sentence; only the real `Unauthorized`
state is ever labeled "Invalid activation". The new `BootstrapUnavailable`
state gets its own third, distinct sentence.

## Trust boundary (task requirement 3/14 - explicit, not assumed)

**The bootstrap config is public bootstrap material, not a secret.**
Every APK ships the exact same AmneziaWG keypair
(`BootstrapIdentity.PLACEHOLDER_PRIVATE_KEY_BASE64`) - anyone can extract
it, exactly like every gateway's own AWG public key in
`ProductionGatewayCatalog` is already treated as non-secret. Security must
come from restricting what this identity can reach/do server-side, never
from assuming the APK cannot be decompiled. The normal, device-specific
profile is still issued only after a real, successful activation - nothing
about this slice changes who can obtain a working per-device profile.

**The checked-in keypair is a locally-generated PLACEHOLDER** (32 random
bytes each for the "private"/"public" fields, not a real derived Curve25519
pair) - it exists only so the client-side types/tests compile and exercise
real-shaped data. It cannot complete a real handshake against either
gateway today, which is intentional: no server-side peer exists yet, and
this PR does not add one. Before any real server-side work, the repository
owner must generate a genuine keypair with the same tooling already used
for every other AWG identity in this codebase, and replace the placeholder.

## Server-side prerequisite (NOT deployed by this PR - task requirement 13)

**Minimal, reuses 100% existing primitives - no new binary, no new
listener, no new certificate.**

The key insight: if the bootstrap peer's own client-side `AllowedIPs` (and
the matching server-side peer entry) is restricted to exactly
`<gateway's own public IP>/32`, a bootstrap-tunneled HTTPS request to that
SAME public IP is a **hairpin/local-delivery case** on the server - the
Linux kernel delivers a packet destined to one of the box's own addresses
locally regardless of which interface it arrived on. It reaches the
ALREADY-RUNNING `nginx` vhost on port 443 (`listen 443 ssl default_server`,
confirmed in both `gateway/edge/nginx-pocvpn.conf` and
`gateway/edge/nginx-pocvpn-stockholm.conf` - no specific bind IP, so this
already works for any locally-delivered packet) through the exact same
`/v1/activate`/`/v1/xray-profile` routes and the exact same already-valid
Let's Encrypt certificate the public internet path already uses. **No
DNAT/REDIRECT trick, no new nginx vhost, no new TLS certificate, no
loopback (`127.0.0.1:8443`/`8444`) exposure of any kind is required or
proposed.**

Per gateway (Frankfurt AND Stockholm), once the owner approves:

1. **Generate one real bootstrap AWG keypair** (`awg genkey | tee
   bootstrap.key | awg pubkey`, the same tooling already used for every
   other AWG identity here) - replacing this PR's placeholder client-side.
2. **Add one new WireGuard peer** on that gateway's existing AWG interface
   (the SAME UDP port 51820 every other peer already uses - WireGuard
   multiplexes many peers over one listening port by public key, nothing
   new to open) for the bootstrap public key, with a small, fixed
   `AllowedIPs` (e.g. `10.77.0.250/32`) - exactly the same shape every
   other peer entry already has.
3. **Add a narrow firewall rule scoped to that one peer's source tunnel
   IP**: allow it to reach ONLY `<this gateway's own public IP>:443`
   (`iptables -A INPUT -i <wg-iface> -s 10.77.0.250/32 -p tcp --dport 443
   -j ACCEPT`, followed by a default DROP for that same source to
   everything else - `iptables -A INPUT -i <wg-iface> -s 10.77.0.250/32 -j
   DROP`). No forwarding/NAT/masquerade rule is added for this source at
   all - it never needs to reach anything other than the box itself, so
   general internet access is denied by omission, not by a special-case
   block rule.
4. **Verify, from a second host, that the bootstrap peer's tunnel cannot
   reach anything else** (a quick `curl`/`nc` test to a few other
   destinations through the tunnel should time out or be refused) before
   considering this gateway's bootstrap peer live.
5. **Rotation** (future APK release, task requirement 12): generate a NEW
   bootstrap keypair, add it as an ADDITIONAL peer on both gateways
   (keep the old one live), ship the new public key in a new APK release,
   and only remove the old peer entry once adoption is sufficient - never a
   single atomic swap that would strand already-installed APKs.

**Explicitly not required by this plan:** no new service/systemd unit, no
new public port, no new certificate, no change to `pocvpn-api`'s own
loopback binding (`8443`/`8444` stay loopback-only, per this repository's
existing rule), no Xray/ingress changes at all.

## What this PR does NOT do

- Does not deploy anything to Frankfurt or Stockholm - no peer added, no
  firewall rule applied, no infrastructure touched.
- Does not generate or ship a real, usable bootstrap keypair - the checked-
  in value is an inert placeholder.
- Does not implement CDN_FRONTED/B35 work of any kind.
- Does not change `activateDevice()`'s observable behavior for any
  existing caller (the B15 additional-gateway path, every existing test).
- Does not verify Russia hard-whitelist bypass or bootstrap reachability on
  a real restricted network - **remains UNVERIFIED**. Every test in this
  slice runs against fakes/stubs on the JVM, never a real device or a real
  gateway.

## Remaining steps before a real APK field test

1. Repository owner approves the server-side plan above (or an amended
   version of it).
2. Generate a real bootstrap keypair; replace `BootstrapIdentity`'s
   placeholder constants.
3. Apply the peer/firewall changes on Frankfurt AND Stockholm (a real
   operator action, out of scope for this PR).
4. Physically verify, from a real device on a real network, that a
   bootstrap tunnel handshakes, that `/v1/activate` genuinely completes
   through it (not directly), and that the resulting profile persists and
   the app reaches Home normally.
5. Only then attempt the actual restricted-Russia-network field test this
   task exists to eventually support.
