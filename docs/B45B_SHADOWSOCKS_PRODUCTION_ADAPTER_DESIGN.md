# B45B - Shadowsocks-rust Production Adapter Design

**Status: DESIGN ONLY. No production code written. Not implemented.**

This document is the design/integration boundary for turning the B45A
spike (`docs/B45A_SHADOWSOCKS_RUST_SPIKE.md` - **FEASIBILITY PROVEN**,
Q1-Q6/Q8 PASS, Q5 PASS with real TCP+UDP proof, Q7 deferred) into a
production transport candidate. It reuses VPNrus's existing transport,
Smart Connect, and diagnostics authorities - it does not create a second
architecture.

## 1. Production TransportKind

New enum value: **`TransportKind.SHADOWSOCKS_2022`** in
`android/app/src/main/java/net/pocvpn/client/transport/TransportKind.kt`.

Not a generic `SHADOWSOCKS` - the pinned protocol is specifically AEAD-2022
(`2022-blake3-aes-256-gcm`), which has a materially different key/session
model from legacy AEAD Shadowsocks (password+KDF vs. raw 32-byte key,
no salt reuse window, BLAKE3-derived per-session subkeys). A future legacy-
AEAD or different-cipher variant, if ever needed, would be a distinct
`TransportKind` value, not a flag on this one - matching this enum's own
existing pattern (`XRAY_REALITY` vs `XRAY_XHTTP` vs `TLS_TCP` are already
separate values for materially different wire behavior, not one
parameterized "Xray" kind).

## 2. TransportCapabilities

A new factory function `TransportCapabilities.shadowsocks2022AdapterShell()`,
following the exact pattern of `xrayRealityAdapterShell()` /
`xrayXhttpAdapterShell()` (adapter-shell capabilities describe what the
*code* does once it exists, never a Smart Connect eligibility claim - that
gate stays with `TransportRegistry`'s own maturity status):

```kotlin
fun shadowsocks2022AdapterShell(): TransportCapabilities = TransportCapabilities(
    usesUdp = true,                    // B45A Section 35: physically proven
    usesTcp = true,                    // B45A: physically proven
    supportsPort443 = true,            // server-configurable port; no protocol constraint pins it to 28388
    supportsObfuscation = false,       // plain AEAD-2022 over TCP/UDP; no TLS-mimicry/CDN-fronting layer (unlike XRAY_XHTTP)
    suitableForRestrictiveNetworks = false, // UNVERIFIED - no censorship-resistance testing performed (B45A explicitly out of scope)
    supportsRoaming = false,           // Q7 UNVERIFIED - see Section 16
    supportsFullTunnel = true,         // B45A's own default-route TUN config
    supportsSplitRouting = false,      // B45A never exercised per-app exclusion; production would need its own proof
    supportsIpv6 = false,              // B45A's TUN never configured an IPv6 address/route (known, documented gap)
    supportsTrafficStatistics = false, // not proven this round
    supportsProbing = false,           // no probe() implementation proposed in the first slice (Section 25)
    maturity = TransportMaturity.EXPERIMENTAL,
)
```

Every `true` here traces to a specific B45A round's physical evidence
(Section 35 of the spike doc); every `false` is either a known gap or
simply unproven, never assumed - matching this file's own documented
convention.

## 3. VpnService/TUN ownership in production

**Reuse the "one VpnService owner" pattern** `NovaXrayVpnService` already
establishes for `XRAY_REALITY`/`TLS_TCP` - not `B45ASpikeVpnService`
verbatim. A new production `ShadowsocksVpnService : VpnService` becomes
the production TUN owner for this transport, following exactly the same
shell `NovaXrayVpnService` uses (single `VpnService.Builder.establish()`
call, self-UID exclusion via `addDisallowedApplication(packageName)` -
B45A's spike shell **never did this**, a gap that must close before
production, see Section 7 of `B45ASpikeVpnService`'s absence of it in
`tun-routing-audit.txt`). VPNrus does not gain a second "who owns the TUN"
model - whichever transport is `TransportOrchestrator`'s active transport
at a given moment owns the single system VPN slot, exactly as today.

## 4. Reusing the proven debug TUN-fd/protect bridge

**Yes, with hardening - the mechanism is proven, the debug packaging and
observability are not production-grade.** See Section 6 for the
per-class classification. The `SCM_RIGHTS` fd-handoff protocol and the
Unix-domain-socket `protect()` bridge protocol are both real, physically
proven mechanisms (B45A Q3/Q4 PASS) - re-implementing them from scratch
would throw away verified work for no benefit. What changes for
production: no debug-only Activity/Log-based observability, binary
resolution moves off a debug-only jniLibs path (Section 20), and error
handling moves from "typed error shown in a debug TextView" to "typed
error fed into B29 diagnostics" (Section 15).

## 5. Lifecycle contract

Reuse `VpnTransport`'s existing contract exactly as defined
(`android/app/src/main/java/net/pocvpn/client/vpn/VpnTransport.kt`):
`preparePermissionIntent()` / `connect(config)` / `disconnect()` /
`observeState(): Flow<TransportState>`, with `probe()`/`stats()` left at
their default `Unsupported` in the first slice (Section 25) since B45A
never exercised either. No new lifecycle interface, no second state
machine - `ShadowsocksTransport` becomes one more `VpnTransport`
implementation `TransportOrchestrator` already knows how to drive.

## 6. Underlying-network change: IN_PLACE or RESTART_SESSION?

**Not chosen yet - `UnderlyingNetworkRecovery.RESTART_SESSION` is the
working assumption, but Q7 stays UNVERIFIED until physically tested**
(per this round's own instruction not to claim handover support). B45A
never exercised a network handover at all (Q7 BLOCKED/deferred in every
round). Reasoning for the working assumption, not a claim: `sslocal`'s own
outbound sockets go through `VpnService.protect()`, which binds them to
whatever network was current when `protect()` was called - a network
switch invalidates those bindings in a way `sslocal`'s local-tun process
has no built-in mechanism to recover from (unlike e.g. AmneziaWG's own
handshake-based reconnect). `RESTART_SESSION` (tear down and re-establish
the whole `sslocal` process + TUN + protect bridge) is the safer default
until a physical handover test proves `IN_PLACE` viable. This must be
physically tested (Wi-Fi <-> cellular, both directions) before Q7 can move
off BLOCKED - explicitly scoped as its own future slice (Section 25), not
assumed here.

## 7. TransportOrchestrator integration

`ShadowsocksTransport : VpnTransport` is registered wherever
`TransportOrchestrator` currently resolves the set of known transports
(the same registration point `VlessRealityTransport`/`VlessTlsTransport`
already use) - no new orchestration surface. `TransportOrchestrator`
continues to own connect/disconnect sequencing, active-transport tracking,
and reconnect triggering exactly as it does today; this adapter adds one
more case to switch on, not a parallel decision path.

## 8. Candidate selection without modifying Smart Connect authority

`AutoGatewaySelector`/`PathScorer`/`PathCandidateBuilder`/`PathHistoryStore`
(all under `android/app/src/main/java/net/pocvpn/client/reachability/` and
`.../smartconnect/`) remain the **only** scoring/selection authority.
`ShadowsocksTransport` participates by exposing accurate
`TransportCapabilities` (Section 2) and honest `TransportState`/
`ProbeResult` - Smart Connect's existing scoring logic consumes those the
same way it already consumes every other transport's. No Shadowsocks-
specific branch is added inside `AutoGatewaySelector` or `PathScorer`;
this transport is just one more scored candidate.

## 9. Endpoint provisioning

Reuses the existing endpoint/credential repository model (whatever
currently provisions `AmneziaWG`/Xray endpoints - `EndpointTransportBinding`
and its repository, per `SignedTransportProfile`'s own code, Section 12)
rather than inventing a second provisioning path. A Shadowsocks endpoint
is one more `EndpointTransportBinding` with `kind = TransportKind.SHADOWSOCKS_2022`.

## 10. Public/signed metadata vs. secret/device-local config

**Public (safe for the signed `EndpointManifest`/B42 profile, Section 14):**
- transport kind (`SHADOWSOCKS_2022`)
- endpoint id
- host/IP reference
- port
- cipher/method identifier (`2022-blake3-aes-256-gcm`)
- a capability/schema-version identifier (so an older client can reject an
  unsupported future variant safely, matching `SignedTransportProfileReadResult.Unsupported`'s
  existing pattern)

**Secret/device-local (never in the manifest, never signed, never logged):**
- the raw AEAD-2022 key
- any per-device rotation/session state

This is the same public/secret split `SignedTransportProfile.Legacy` vs.
whatever already carries AmneziaWG's own key material follows - not a new
split invented for this transport.

## 11. AEAD-2022 key provisioning and rotation

**Reuse the existing identity/credential storage authority** -
`android/app/src/main/java/net/pocvpn/client/identity/`
(`AndroidKeystoreAesGcmEncryptor`, `IdentityFileStore`,
`ClientKeyRepositoryFactory`) already provides Keystore-backed,
device-local, encrypted-at-rest secret storage for other credential
material in this app. The Shadowsocks AEAD-2022 key becomes one more
secret stored through that same authority, keyed by endpoint id - not a
new encryption/storage mechanism. Rotation: a new key value overwrites the
stored one for that endpoint id (server-side rotation, as already proven
manually in B45A Sections 32/35, becomes a provisioning-flow operation
instead of an ad hoc SSH session). Revocation: deleting the stored secret
for an endpoint id is sufficient (the same delete-to-revoke pattern
`IdentityFileStore` already supports for other identity material).
`b45a-dataplane.properties` (the debug-only, gitignored spike mechanism)
is explicitly **not** carried into production - Section 6's classification
marks `B45ADataPlaneConfig` DEBUG-ONLY / DISCARD for exactly this reason.

## 12. Secret hygiene: argv/logcat/support-export boundaries

The key must never appear as a bare CLI argument the way B45A's spike
passes it (`-k <key>` directly on `sslocal`'s command line - fine for a
disposable spike credential, explicitly rejected for production per this
round's requirements). Production options, to evaluate during
implementation (not decided here):
- `sslocal` also accepts a config file path (`-c <path>`); a
  process-private, `MODE_PRIVATE` config file written just before spawn
  and deleted/overwritten immediately after (or piped via a fd rather than
  a path) keeps the key out of `/proc/<pid>/cmdline` - directly closing
  the exact exposure class B45A's own credential-rotation rounds (Sections
  32/35) had to react to once already.
- Never log the resolved key (already B45A's own discipline throughout,
  per every round's "never printed" credential handling - carry that
  discipline forward unchanged).
- `DiagnosticSanitizer`/`SupportBundle`
  (`android/app/src/main/java/net/pocvpn/client/diagnostics/support/`)
  must treat this transport's config the same way it already redacts
  other transports' secrets - no new sanitizer, just coverage.

## 13. B42 signed transport profile integration

**Design only - do not activate live consumption yet**, per instruction.
`SignedTransportProfile` gains a new case (following `CdnXhttp`'s own
pattern):

```kotlin
data class Shadowsocks2022(
    override val endpointId: EndpointId,
    val method: String,       // "2022-blake3-aes-256-gcm", pinned/validated, never freeform
    val schemaVersion: Int,
) : SignedTransportProfile {
    override val transportKind: TransportKind = TransportKind.SHADOWSOCKS_2022
}
```

No key material in this type, matching this file's own explicit "no
credential-bearing material" invariant. `signedTransportProfile()`'s
`when` gains one more arm once real profile data exists server-side -
until then, an endpoint of this kind reads as `Legacy` (today's fallback
behavior for a binding whose profile isn't recognized), same as any other
not-yet-profiled transport.

## 14. Diagnostics taxonomy (truthful, typed, no fabrication)

Following `DiagnosticTypes.kt`'s own typed-signal discipline - every
signal here must be something the Android client can actually observe,
never inferred from an exception string, never a fabricated server-side
claim:

**Observable (client-side, real):**
- native runtime spawn failure (`ProcessBuilder` throw - B45A's own
  `B45ASpikeError.SpawnFailed`)
- native runtime unexpected exit + exit code (B45A's own
  `ProcessExitedUnexpectedly`)
- TUN fd handoff failure/timeout (B45A's own `TunFdHandoffFailed`/
  `TunFdHandoffTimedOut`)
- protect() failure (B45A's own protect-bridge failure counters)
- config/credential validation failure (B45A's own `InvalidTestCredential`,
  generalized)
- TCP data-plane proof failure (an app-level reachability probe times out
  or gets no response - **only if** a production probe/health-check
  mechanism is actually implemented; not claimed until Section 25's
  relevant slice exists)
- UDP data-plane proof failure (same caveat)

**NOT observable from the Android client - must remain UNKNOWN, never
fabricated:**
- *why* the server rejected a connection (auth failure vs. server-side
  bug vs. rate limit) - the client sees only "no successful response",
  never a truthful reason code, unless `ssserver` is changed to signal one
  (out of scope here)
- server-side resource exhaustion, crash, or restart
- whether a dropped UDP packet was dropped by the network path vs. by the
  server - the client can observe "no reply", never "why no reply",
  without packet-level server telemetry it does not have access to

This mirrors B45A's own diagnostic-pass discipline (Sections 33/34: "Do
not infer from exception strings... Do not fabricate server-side failures
the Android client cannot observe" was already this project's rule before
B45B; B45B keeps it as a permanent typed-signal contract, not a one-off
diagnostic-session courtesy).

## 15. Data-plane proof design (production)

Not decided in this document - flagged as its own implementation slice
(Section 25) once the adapter shell exists. B45A's own UDP/TCP proof
mechanism (`B45AUdpEchoProbe`, a controlled external echo endpoint) is
explicitly a **spike-only, temporary, owner-provisioned test fixture** -
production cannot depend on a disposable Frankfurt echo port. A
production-appropriate mechanism (e.g. a lightweight reachability check
against the configured `ssserver` itself, not a separate echo target)
needs its own design pass; this document intentionally does not invent
one here.

## 16. PathHistory identification

`PathHistoryStore` records history per candidate; a Shadowsocks-2022
candidate is identified the same way every other candidate already is
(endpoint id + `TransportKind`) - no new identification scheme. Once
`TransportKind.SHADOWSOCKS_2022` exists, `PathHistoryStore`/`PathScorer`
need no code change to represent it, since neither hardcodes the existing
transport kinds a new enum value into (confirmed by their signatures
during this review's grep - a per-kind branch would have been a design
smell for this section to flag; none exists).

## 17. Coexistence with AMNEZIA_WG / XRAY_REALITY / TLS_TCP / XRAY_XHTTP

No special-casing needed - `TransportOrchestrator` already owns "exactly
one active transport at a time" regardless of how many `TransportKind`
values exist. Smart Connect's scoring already treats each transport as an
independent, comparably-scored candidate. `SHADOWSOCKS_2022` becomes a
fifth candidate in that same pool, not a parallel system.

## 18. Independent failure domain added

A `sslocal` process crash/hang is a failure mode none of the existing
transports have (they're all in-process Xray/WireGuard implementations or
kernel WireGuard, not a separate spawned executable). This is a genuinely
new failure class B45B's lifecycle/cleanup design (Section 21) and
diagnostics (Section 14) must account for explicitly - not something the
existing transports' error handling already covers for free.

## 19. Shared runtime/core dependencies

None beyond what's already shared: standard `VpnService`/`ConnectivityManager`
Android framework APIs, the existing identity/credential storage authority
(Section 11), the existing diagnostics/support-bundle authority (Section
14), and `TransportOrchestrator`/Smart Connect themselves. The pinned
`shadowsocks-rust` binary is a wholly separate, self-contained native
executable with no shared Rust/native code with any existing transport
(Xray is a separate Go-derived binary already; AmneziaWG uses the kernel
module / `wg-quick` path).

## 20. APK/runtime cost impact

**Not measured yet (B45A Q9 remains PARTIAL)** - carried forward as an
open item, not resolved by this design. The native `sslocal` binary
(ARM64, from B45A's own build) adds real APK size; production packaging
(Section 21) needs an actual measurement pass (APK size delta, binary
size itself, memory/CPU under a real session) before this can move to
PASS/PARTIAL-with-evidence.

## 21. License/supply-chain obligations

**Not resolved yet (B45A Q10 remains PARTIAL)** - shadowsocks-rust's own
license (needs confirming per-crate, not assumed here) and this
project's own obligations from bundling a third-party compiled binary
(attribution, source-availability where the license requires it) need a
dedicated review pass, not invented in this design document.

## 22. Release packaging - how the native runtime ships safely

**Not a debug-only jniLibs path anymore** - B45A's own packaging
(`android/app/src/debug/jniLibs/arm64-v8a/libsslocal_spike.so`, debug-
build-type only) was deliberately spike-scoped. Production packaging
needs its own decision (standard `jniLibs` in the release `sourceSet`
with normal AGP packaging vs. a download-on-demand/Play Feature Delivery
model to control the size cost from Section 20) - flagged as an open
question for the relevant implementation slice (Section 25), not decided
here. Whatever is chosen, the existing release-isolation discipline this
whole project already enforces (debug-only code never reaching a release
manifest/APK - proven for B45A itself in every round's build-gate check)
must hold for whatever the production packaging path becomes, verified
the same way (APK content inspection, manifest diff) every time.

## 23. Native process crash handling

Reuse B45A's own proven mechanism: `B45ARuntime`'s `onProcessExitedUnexpectedly`
(process exit callback -> typed `ProcessExitedUnexpectedly` state, protect
bridge torn down, ownership cleared - never left "falsely RUNNING"). This
is REUSABLE WITH HARDENING (Section 6): the state-machine logic itself is
already unit-tested and physically proven; production hardening means
feeding that same signal into `TransportState`/B29 diagnostics (Section
14) instead of a debug status `TextView`, and triggering
`TransportOrchestrator`'s existing reconnect/failover path instead of
requiring a manual "B45A Start" tap.

## 24. Cleanup after failed start

Reuse B45A's own proven discipline: protect bridge stopped, process
reference cleared, typed failure status set, all on every failure branch
in `B45ARuntime.start()` (verified: `BinaryMissing`, `InvalidTestCredential`,
`ProtectListenerFailed`, `SpawnFailed` each clean up what was already
started before failing). Production hardening: also guarantee the TUN
itself (`VpnService.Builder.establish()`'s returned `ParcelFileDescriptor`)
is closed on every failure path - B45A's spike shell's exact handling of
this was not itself re-audited in this design pass and should be
explicitly checked during implementation, not assumed clean by analogy.

## 25. Rollback path if production integration fails

Because `ShadowsocksTransport` is additive (a new `VpnTransport`
implementation and a new `TransportKind` value, not a modification to any
existing transport's code), rollback is: do not register it with
`TransportOrchestrator`/Smart Connect, or gate its registration behind a
feature flag/remote config the existing `TransportRegistry`
maturity-status mechanism already supports (`NOT_IMPLEMENTED` /
`EXPERIMENTAL` / `STABLE`). No existing transport's code path needs to be
touched to disable this one - the same safety property `XRAY_XHTTP`'s own
adapter-shell-but-not-yet-`STABLE` status already demonstrates.

## Component classification (spike -> production)

| B45A component | Classification | Why |
|---|---|---|
| `B45ANativeBinaryResolver` | REWRITE FOR PRODUCTION | Debug-only `nativeLibraryDir` resolution logic; production packaging path is undecided (Section 22), and resolution must work under whatever that path turns out to be |
| `B45ATunNetworkConfig` | REUSABLE WITH HARDENING | The CIDR/MTU/default-route constants and the "one source of truth shared between Kotlin and the sslocal CLI arg" pattern are sound; needs an IPv6 story and split-routing/self-UID-exclusion additions before production (Sections 2-3) |
| `B45ARuntime` | REUSABLE WITH HARDENING | State machine, unit tests, and process-lifecycle logic are proven (Sections 4, 23, 24); needs the `-U` fix (already applied, Section 35), a non-argv credential path (Section 12), and wiring into `TransportState`/B29 instead of its own bespoke `B45ASpikeStatus` |
| `B45ASpikeVpnService` | REWRITE FOR PRODUCTION | Debug-only shell without self-UID exclusion or split-routing (Section 3); production needs the `NovaXrayVpnService`-pattern shell, not this class verbatim |
| `B45AVpnProtectBridge` (+ `RealB45AVpnProtectBridge`) | REUSABLE WITH HARDENING | Protocol and implementation are physically proven (Q4 PASS every round); production hardening is observability wiring only (Section 4) |
| `B45ATunFdBridge` (+ `RealB45ATunFdBridge`) | REUSABLE WITH HARDENING | Same reasoning as the protect bridge - proven mechanism (Q3 PASS), needs production observability wiring only |
| `B45ADataPlaneConfig` | DEBUG-ONLY / DISCARD | Reads the gitignored `b45a-dataplane.properties` file directly - the entire point of Section 11's redesign is to replace this with the real credential-repository integration; nothing here survives as-is |
| `B45AUdpEchoProbe` | TEST UTILITY ONLY | A deliberately spike-only, controlled-external-endpoint proof mechanism (Section 15); has no production role, but may inform a future integration-test harness |
| `B45ASpikeState` | REUSABLE WITH HARDENING | The pure, dependency-free state-machine types (`B45ARuntimePhase`, bridge states, `B45ASpikeTransitions`) are exactly the kind of unit-tested core logic worth keeping; would likely be renamed off the `B45ASpike*` prefix and re-homed under the transport's own package once production naming is decided (not decided here) |
| `B45ASpikeActivity` | DEBUG-ONLY / DISCARD | A manual test UI with Start/Stop/UDP-probe buttons; has no production equivalent - production control flow goes through `TransportOrchestrator`, not a tap on a debug screen |

The production adapter is expected to be smaller than the spike: the
debug UI (`B45ASpikeActivity`), the property-file credential reader
(`B45ADataPlaneConfig`), and the UDP test probe
(`B45AUdpEchoProbe`) all have no production equivalent at all, while the
state machine, process lifecycle, and both bridges carry over with
targeted hardening rather than a rewrite.

## Test strategy

- Keep the existing B45A unit-test coverage's *shape* (pure state-machine
  tests against fakes, no real process/socket in unit tests) for whatever
  of `B45ARuntime`/`B45ASpikeState` survives into production naming -
  this was already the right pattern or this document wouldn't be
  reusing it.
- New unit tests needed once real code exists: credential-repository
  integration (config resolution reads from the Keystore-backed store,
  not a properties file), `SignedTransportProfile.Shadowsocks2022`
  parsing (mirroring `CdnXhttp`'s own existing tests), and
  `TransportCapabilities.shadowsocks2022AdapterShell()`'s values
  (mirroring the other adapter-shell factories' own tests, if any exist -
  not confirmed in this pass).
- Physical-device proof strategy for the first production slice: reuse
  B45A's own proven TCP+UDP methodology (real browser navigation / a
  controlled echo target) as an integration-test checkpoint, not as the
  production data-plane proof mechanism itself (Section 15 already flags
  that as a separate, undecided design question).
- Release-isolation check: the same APK-content-inspection method already
  used for every B45A build gate, re-run against whatever the real
  production packaging path becomes (Section 22).

## Proposed implementation slices (B45B / B45C / ...)

Explicitly NOT implemented by this document. Proposed breakdown for
future, individually-approved slices:

1. **B45B-1**: `TransportKind.SHADOWSOCKS_2022` +
   `TransportCapabilities.shadowsocks2022AdapterShell()` + the
   `SignedTransportProfile.Shadowsocks2022` type (Sections 1, 2, 13) -
   pure additive types, no runtime behavior, smallest possible first cut.
2. **B45B-2**: credential-repository integration (Section 11/12) - move
   AEAD-2022 key storage onto the existing identity/Keystore authority,
   independent of any VpnService work, unit-testable without a device.
3. **B45B-3**: `ShadowsocksTransport`/`ShadowsocksVpnService` adapter
   shell (Sections 3-5, 23-24) - the hardened production port of
   `B45ARuntime`/the two bridges, registered but not yet wired into
   `TransportOrchestrator`/Smart Connect (an isolated adapter shell,
   exactly like `VlessRealityTransport`'s own history per
   `xrayRealityAdapterShell()`'s doc comment).
4. **B45B-4**: `TransportOrchestrator`/Smart Connect registration
   (Section 7-9) - the slice that actually makes this transport reachable
   by real users, gated behind `TransportMaturity.EXPERIMENTAL` per
   Section 25's rollback design.
5. **B45B-5 (or later, separately scoped)**: Q7 network-handover physical
   testing (Section 6) - determines `IN_PLACE` vs `RESTART_SESSION` with
   evidence, not assumption.
6. **Separately scoped, not numbered here**: release packaging decision +
   APK-size/runtime-cost measurement (Sections 20, 22), license/supply-
   chain review (Section 21), and the production data-plane proof
   mechanism (Section 15) - each independent enough to review on its own
   before B45B-4 goes live for real users.

## Exact first implementation slice after approval

**B45B-1** (Section above): add `TransportKind.SHADOWSOCKS_2022`,
`TransportCapabilities.shadowsocks2022AdapterShell()`, and
`SignedTransportProfile.Shadowsocks2022`, each with focused unit tests
mirroring the existing patterns for the other transport kinds/profiles.
Zero runtime behavior, zero VpnService code, zero credential handling -
purely additive types that every later slice depends on. Does not touch
`TransportOrchestrator`, Smart Connect, or any existing transport's code.
