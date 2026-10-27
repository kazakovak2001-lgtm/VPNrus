# Relay Readiness / Protected Gating + Ingress Provisioning Control Plane (B25) - FOUNDATION

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

Closes every remaining CLIENT/control-plane blocker B24 named - still
**FOUNDATION**, no real RU ingress deployed, **Russia hard-whitelist bypass
remains UNVERIFIED**.

- **Typed session identity**: `net.pocvpn.client.relay.VpnAttemptContext`
  (`Direct`/`Relayed(plan)`) is pinned once per attempt onto
  `TransportOrchestrator.Resolution.Resolved.attemptContext` (default
  `Direct`) and carried into `VpnController.pendingAttemptContext` - never
  guessed from transport kind/endpoint name.
- **Real Protected gating**: `net.pocvpn.client.vpn.VpnSessionHealth`
  (pure `computeSessionHealth(state, attemptContext, relayStage)`),
  exposed as `VpnController.sessionHealth`/`MainViewModel.sessionHealth`
  and read by `ProductFlowPresentation`'s new `VpnSessionHealth` overloads
  in `AppRoot`'s Home screen instead of the raw `TransportState` ones.
  Direct: `DirectProtected` fires under the exact same condition
  `TransportState.Connected` always did (byte-for-byte unaffected).
  Relayed: `TransportState.Connected` alone (ingress handshake) is
  `RelayHandshake`, NEVER `RelayProtected`, until
  `RelayReadinessStage.END_TO_END_DATA_PLANE_OK` is reported via
  `VpnController.reportRelayStage` - which only ever happens after a real
  `RelayEndToEndProbe` success.
- **Real end-to-end proof contract**: `RelayEndToEndProbe`
  (`HttpRelayEndToEndProbe` - a real authenticated HTTPS GET to
  `IngressClientProfile.endToEndProbeUrl`, over whatever route the OS
  resolves, i.e. genuinely through the just-established tunnel; fail-closed
  `NotConfiguredRelayEndToEndProbe` is the production default).
  `MainViewModel.armFailoverWatch`'s relay branch calls this probe on a
  real ingress-handshake `Connected` observation: `Success` promotes
  `END_TO_END_DATA_PLANE_OK` (the only way `RelayAttemptOutcome.Success` is
  ever constructed) and leaves the session Connected/`RelayProtected`;
  `Failure` records the typed category under the full `historyPathId` and
  advances `attemptCombined()` - no stale Connected/Protected UI can
  survive a failed probe, since `_relayStage` never advances past
  `INGRESS_HANDSHAKE_OK` on that path. No real server-side relay-health
  endpoint exists yet on any EXIT for this probe to call - see the closing
  paragraph below.
- **Path-history ownership fixed**: `VpnController`'s generic
  `recordConnectionOutcome`/`recordPathHistory` (the connect()-throw catch
  block - the only place that could still fire for a relayed attempt) now
  skip entirely when `pendingAttemptContext is VpnAttemptContext.Relayed` -
  the single-hop write B24 documented as a known, harmless gap is closed.
  `MainViewModel.recordRelayOutcome` remains the ONE writer for a relayed
  attempt, always under the full composite `historyPathId`.
- **Typed persisted ingress profile**:
  `net.pocvpn.client.relay.IngressClientProfile` (endpoint/binding/
  transport-scoped, wraps the EXISTING `XrayProfile`/`XrayTlsProfile`
  shapes, plus version/validity-window/probe coordinates; structurally
  excludes the ingress's own REALITY private key, the upstream relay uuid,
  and the signing key - those fields do not exist on this type), persisted
  via `FileIngressProfileStore` (its own AndroidKeyStore alias/file, one
  per ingress endpoint id).
- **Real `RelayIngressResolverImpl`**: loads the endpoint-scoped profile,
  validates `IngressClientProfile.matches(plan)` and non-expiry (typed
  `PROFILE_NOT_PROVISIONED`/`PROFILE_MISMATCH`/`PROFILE_EXPIRED`
  `RelayFailureCategory` additions), writes the matched credential into the
  SAME per-endpoint `XrayProfileRepository`/`XrayTlsProfileRepository`
  `VlessRealityTransport`/`VlessTlsTransport` already read from, and
  returns `RelayIngressResolution.Resolved(transport, kind, profile)` -
  never starts/owns VPN state. `VpnController` gained a separate, additive
  `relayXrayProfileRepositoryResolver`/`relayXrayTlsProfileRepositoryResolver`
  pair (consulted only when `pendingAttemptContext is Relayed`; also fixed
  `supportedKinds` to widen for a relay-only composition root, a real gap
  found during this slice). `NotProvisionedRelayIngressResolver` remains
  the ONLY resolver wired into production (no real ingress deployment
  exists to activate against).
- **Control-plane**: `POST /v1/ingress-profile`
  (`gateway/api/handler.py`, gated by an additive
  `ProvisioningServer.ingress_config`, `None`/zero-behavior-change for
  every ordinary gateway) reuses `activations.py`'s entitlement decision
  and `xray_provisioning.provision_and_activate_identity` VERBATIM via the
  new `gateway/api/ingress_activation.py` (renders through
  `xray_ingress_config_renderer.render_ingress_server_config`, never
  `xray_config_renderer`'s freedom-outbound path). Own env-var-driven
  config (`gateway/api/ingress_config.py`, `NOVA_INGRESS_*`, absent by
  default, all-or-nothing) - a separate deployment instance, never a field
  on the shared `AppConfig`. Response is client-safe only.
- **Ingress->exit relay identity contract**:
  `xray_config_renderer.render_server_config` gained an additive
  `static_clients=()` parameter - entries authorized on an EXIT
  unconditionally, deliberately never cross-referenced against
  `activations_data`/revocation (an infra-level host-to-host trust
  relationship, not a per-user entitlement), redacted like any other
  client uuid. `gateway/tools/provision_relay_upstream_identity.py` mints
  the identity and writes two secret-handling output files (never
  stdout/logs) for the ingress host and the EXIT operator respectively -
  applying the EXIT-side fragment to a live host remains a deliberate,
  human-reviewed, unautomated step.
- **Deployment tooling**: `gateway/systemd/nova-xray-ingress.service` (a
  reviewed template, not installed), `gateway/tools/ingress_reconcile.py`,
  `gateway/tools/ingress_status.py` (read-only, secret-safe).

**Remaining condition to exercise any of this physically, in order**: (1) a
real ingress host (DIRECT_IP first) running the ingress-role
`pocvpn-api`/Xray-core pair this slice built; (2) a real per-device
activation against it via `POST /v1/ingress-profile`, populating a real
`IngressProfileStore` entry on a real device; (3) a real
`RelayIngressResolverImpl` wired into that device's composition root; (4) a
real server-side relay-health endpoint on the EXIT for
`HttpRelayEndToEndProbe` to call - not built this slice, the named
remaining gap; (5) the dedicated ingress->exit relay identity actually
applied to a live EXIT's own activation wiring via `static_clients` (a
deliberate, human-reviewed step, not automated). None of these five exist
yet - no new infrastructure was purchased or deployed by this slice.
