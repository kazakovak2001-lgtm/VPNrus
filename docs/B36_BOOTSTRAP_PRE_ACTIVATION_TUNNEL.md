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
  bootstrap AWG keypair (a real, freshly generated Curve25519 keypair - see
  "Trust boundary" below) and this peer's own fixed tunnel address.
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
(`BootstrapIdentity.BOOTSTRAP_PRIVATE_KEY_BASE64`) - anyone can extract
it, exactly like every gateway's own AWG public key in
`ProductionGatewayCatalog` is already treated as non-secret. Security must
come from restricting what this identity can reach/do server-side, never
from assuming the APK cannot be decompiled. The normal, device-specific
profile is still issued only after a real, successful activation - nothing
about this slice changes who can obtain a working per-device profile.

**The checked-in keypair is now a REAL, freshly generated Curve25519/X25519
keypair** (generated locally via Python's `cryptography` library, RFC 7748
raw scalar/point encoding - the same wire shape `awg genkey`/`awg pubkey`
produce), not a placeholder. It STILL cannot complete a real handshake
against either gateway today, because no matching server-side peer exists
yet - this slice ships the client-side plumbing plus the exact,
not-yet-applied server-side plan (`docs/B36_SERVER_DEPLOYMENT_PLAN.md`),
never an automatic deployment. The private key value is committed only in
the Android source (where it is intentionally public/shipped) and in
`gateway/config/bootstrap.env` (public key only) - never printed in any
report or command output.

## Server-side prerequisite (NOT deployed by this PR - task requirement 13)

**Superseded by the exact, command-level plan in
[`docs/B36_SERVER_DEPLOYMENT_PLAN.md`](B36_SERVER_DEPLOYMENT_PLAN.md)** -
that document is now authoritative for the server-side design; this
section is kept short and summarizes it. (History note: an earlier version
of this section sketched the restriction using `iptables`. The repository's
actual gateway firewall - confirmed from `gateway/provision.sh` and
`gateway/nftables/pocvpn.nft.template`, not assumed - is **nftables**, one
table `inet pocvpn`. The deployment plan uses nftables throughout, adding a
second, additive table rather than editing the existing one.)

**Minimal, reuses 100% existing primitives - no new binary, no new
listener, no new certificate, no new public port.** The key insight: a
bootstrap-tunneled HTTPS request to the gateway's OWN public IP is a
**hairpin/local-delivery case** (INPUT hook, not FORWARD) - it reaches the
already-running `nginx` vhost on port 443 through the exact same
`/v1/activate`/`/v1/manifest`/`/v1/xray-profile` routes and the exact same
already-valid certificate the public path already uses. No DNAT/REDIRECT,
no new vhost, no loopback (`127.0.0.1:8443`/`8444`) exposure.

Per gateway (Frankfurt AND Stockholm), once the owner approves,
`gateway/scripts/install-bootstrap-peer.sh` (added by this slice, NOT run):

1. Adds the ONE shared, public bootstrap AWG peer via the EXISTING
   `add-peer.sh` (never a second peer-mutation mechanism).
2. Applies a new, ADDITIVE nftables table (`pocvpn_bootstrap`, from
   `gateway/nftables/pocvpn-bootstrap.nft.template`) that DROPs the
   bootstrap peer's own source IP in the `forward` hook (denying general
   Internet access - the existing `pocvpn` table's own forward/NAT rules
   are scoped by interface/subnet, not by peer, so this exclusion must be
   explicit) and allows it ONLY `tcp/443` in the `input` hook - never
   touching the existing `pocvpn` table.
3. Installs a small systemd unit (`nftables-pocvpn-bootstrap.service`) so
   the restriction survives a reboot.

A real bootstrap keypair has ALREADY been generated for this slice (Phase
2 of the server-deployment task) and is committed as
`BootstrapIdentity.BOOTSTRAP_PRIVATE_KEY_BASE64`/`BOOTSTRAP_PUBLIC_KEY_BASE64`
- one shared identity, used on both gateways (see the deployment plan's
own "one identity, not two" reasoning). Rotation procedure, exact commands,
and rollback are all in `docs/B36_SERVER_DEPLOYMENT_PLAN.md`.

## What this PR does NOT do

- Does not deploy anything to Frankfurt or Stockholm - no peer added, no
  firewall rule applied, no infrastructure touched. The install/uninstall
  scripts and nftables template exist in the repository but have not been
  run against either host.
- A real bootstrap keypair now exists and is committed client-side, but it
  is not yet USABLE - no matching server-side peer has been added to
  either gateway, so it cannot complete a real handshake today.
- Does not implement CDN_FRONTED/B35 work of any kind.
- Does not change `activateDevice()`'s observable behavior for any
  existing caller (the B15 additional-gateway path, every existing test).
- Does not verify Russia hard-whitelist bypass or bootstrap reachability on
  a real restricted network - **remains UNVERIFIED**. Every test in this
  slice runs against fakes/stubs on the JVM, never a real device or a real
  gateway.

## Remaining steps before a real APK field test

1. Repository owner approves `docs/B36_SERVER_DEPLOYMENT_PLAN.md` (or an
   amended version of it).
2. Run `gateway/scripts/install-bootstrap-peer.sh` on Frankfurt, then on
   Stockholm (a real operator action, out of scope for this PR) - the
   bootstrap keypair itself is already generated and committed, nothing to
   regenerate.
3. Physically verify, from a real device on a real network, that a
   bootstrap tunnel handshakes, that `/v1/activate` genuinely completes
   through it (not directly), and that the resulting profile persists and
   the app reaches Home normally.
4. Only then attempt the actual restricted-Russia-network field test this
   task exists to eventually support.
