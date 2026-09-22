# B46-4P: Hysteria2 Production Deployment Gate

## Status

**IN PROGRESS - NOT PRODUCTION-COMPLETE.** This is the explicit deployment gate B46-4A deliberately deferred to. B46-4A itself is a completed *implementation* phase (PR #111, draft) - not production-complete. Nothing in this document claims production readiness for any item marked below anything other than DONE with real evidence.

No AWS/security-group/server changes have been made. No Xray/AWG lab infrastructure (B46-3C) has been reused as production infrastructure. `EndpointManifestRepository` remains the sole trust authority - nothing in this slice bypasses it. B46-3C PR #110 is untouched.

## Checklist (audited against actual repo state, not assumed)

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Live `/v1/hysteria-profile` route + AppConfig fields | **DONE** | `gateway/api/handler.py` (`_PATH_HYSTERIA_PROFILE`, `_handle_hysteria_profile[_inner]`), `gateway/api/config.py` (`hysteria2_store_path`/`hysteria2_lock_path`/`hysteria2_server_port`/`hysteria2_sni`, fail-closed completeness group). Reuses the SAME activation store `/v1/activate`/`/v1/xray-profile` already use - never a second activation system. Still git-only: no systemd unit, no firewall rule, no live process serving this route yet. |
| 2 | Backend Hysteria2 provisioning/API dispatch | **DONE** (as of item 1) | `hysteria_provisioning.provision_hysteria_identity`/`verify_hysteria_auth` (already existed, B46-4A) are now actually reachable through the route above. |
| 3 | Stockholm UDP production-port audit/choice | **NOT STARTED** (design candidates only) | Requires inspecting real Stockholm host state (`ss`/`iptables`/Security Group on the live server) - no server access available in this environment (confirmed: no working SSH credential - see the prior read-only audit). `gateway/hysteria/README.md`'s own "Port choice" section lists technical candidates only; historical `34443` was a temporary test port, since removed, never a production decision. |
| 4 | Production TLS/certificate handling | **NOT STARTED** (design ready) | Live audit (this pass, read-only `openssl s_client`): Stockholm's existing port-443 cert is issued for the bare IP only, not a DNS hostname - unusable as a real Hysteria2 SNI target. `gateway/hysteria/README.md`'s own "TLS / SNI" section documents this finding and recommends (does not create) a new subdomain under the already-owned `aknova.pp.ua` zone. No DNS record created, no certificate issued. |
| 5 | systemd/service lifecycle | **IMPLEMENTED - NOT DEPLOYED** | `gateway/systemd/nova-hysteria2.service` is a real, `systemd-analyze verify`-clean unit template (mirrors `nova-xray.service`'s hardening exactly, re-justified per-directive, not copy-pasted) - not installed/enabled/started on any host. The loopback auth-backend listener this unit's config depends on is a SEPARATE, still-open design question (Option A: extend `pocvpn-api.service`; Option B: a new unit) - see `gateway/hysteria/README.md`'s "Auth backend listener" section - neither is implemented yet. |
| 6 | Native binary packaging | **PARTIAL - split into two independent tracks** | **Server-side supply chain: IMPLEMENTED - NOT DEPLOYED.** `gateway/hysteria/fetch-hysteria-server.sh` + `VERSION` (real, verified pinned commit/tag/checksum - cross-checked this pass against a genuine download, not fabricated) now exist, mirroring `gateway/xray/`'s own pattern; a GAP was found and documented (the official binary appears to link GPL-3.0-or-later `sing-tun` even in server mode - see VERSION/README's own "Licensing decision required" section) - not resolved, owner decision needed before install. **Android native binary packaging: still NOT STARTED**, unchanged from before this slice - `libnovahysteriachild.so`/`libnovatun2sockschild.so` remain in their B46-3B/B46-3C research locations, not touched this pass (Android was explicitly out of scope for this slice). |
| 7 | Signed production manifest binding | **NOT STARTED** (preparation documented) | No `EndpointTransportBinding(HYSTERIA2, ...)` has been signed into any manifest artifact - confirmed empirically absent from the LIVE manifest (fetched and byte-scanned in the prior audit pass). This pass documents (does not execute) exactly what the offline signing ceremony (`gateway/tools/manifest_signing.py`) will need - see "Manifest signing preparation" below. |
| 8 | Client/server facts come from trusted signed topology, never blindly taken from the provisioning response | **DONE (verified this pass)** | `Hysteria2ProfileProvisioner.provision` (`android/app/src/main/java/net/pocvpn/client/provisioning/Hysteria2ProfileProvisioner.kt:53-78`) resolves the trusted `SignedTransportProfile.Hysteria2` FIRST and fails closed (`NoTrustedBinding`) before ever dialing the network; once resolved, the response's own `server_address`/`server_port`/`sni`/`obfuscation_mode` are cross-checked against that pinned profile and rejected (`Mismatched`) on any disagreement - the control-plane response is authority for SECRET material only. `MainViewModel`'s manual-connect path (`MainViewModel.kt:2932`) re-resolves the SAME `trustedTransportBindingFor` call at execution time, so a manually forced HYSTERIA2 selection gets no shortcut around the trusted signed binding either. No code change was needed for this item - already correct from B46-4A. |
| 9 | Normal UI flow for Hysteria2 selection/activation | **DONE (this pass)** | `DiagnosticsDialog.kt` now has a "Force HYSTERIA2 on next connect" button, the same `onSetTransportForce`/`debugSetTransportPreference`/`isDebugBuild`-gated plumbing every existing Force button (including SHADOWSOCKS_2022's) already uses - never a second selection mechanism, never a bypass of `isHysteria2AvailableFor`'s eligibility gate. `AppRoot.kt`'s diagnostics lines now also surface the ALREADY-EXISTING `MainViewModel.hysteria2ProfileProvisioningState` (wired since B46-4A's Finding 5, never previously displayed anywhere), giving the automatic post-activation provisioning attempt's success/failure outcome real UI visibility for the first time - no new state mechanism was introduced. |
| 10 | Physical validation on OPPO CPH2173 | **BLOCKED** | Cannot proceed until items 3-7 and 9 are genuinely green - no physical test against fabricated/incomplete backend infrastructure will be performed or represented as validation, per this project's own evidence discipline. |

## What changed this pass (item 1)

- [`gateway/api/config.py`](../gateway/api/config.py): `hysteria2_store_path`, `hysteria2_lock_path`, `hysteria2_server_port`, `hysteria2_sni` fields on `AppConfig`, with a fail-closed all-or-nothing completeness group (mirrors `xray_partially_configured`'s own convention) plus a check that `ACTIVATION_STORE_PATH` is configured before Hysteria2 can be enabled (it reuses that store, never a second one).
- [`gateway/api/handler.py`](../gateway/api/handler.py): `_PATH_HYSTERIA_PROFILE = "/v1/hysteria-profile"`, dispatched POST-only, `_handle_hysteria_profile`/`_handle_hysteria_profile_inner` calling `hysteria_provisioning.provision_hysteria_identity` (already existed, B46-4A) and mapping its outcomes to the SAME status codes `/v1/xray-profile` already uses (401 unauthorized, 403 revoked/expired/device_not_bound, 503 not-configured/store-unavailable). Response fields match Android's `parseHysteria2ProfileSuccessBody` exactly (`profile_version`, `server_address`, `server_port`, `auth_secret`, `sni`, `obfuscation_mode`, `obfuscation_secret`). `obfuscation_mode` is a hardcoded `"NONE"` literal and `obfuscation_secret` is always `null` - B46-4A's Finding 8 already established no per-device Salamander secret is ever minted server-side.
- Tests: [`gateway/api/tests/test_config.py`](../gateway/api/tests/test_config.py) (Hysteria2 completeness-group cases), [`gateway/api/tests/test_hysteria_profile_endpoint.py`](../gateway/api/tests/test_hysteria_profile_endpoint.py) (new - live HTTP-level route tests: success shape, retry rotation, unauthorized/revoked/device-not-bound, not-configured 503, no raw secret in the durable store, malformed body, missing bearer token), plus `_fixtures.py`/`_http.py` fixture helpers (`make_hysteria2_app_config`, `post_hysteria_profile`) mirroring the existing Xray equivalents.

No production infrastructure was touched: no systemd unit started, no firewall opened, no manifest signed/deployed, no credential provisioned against a real server. This is git-only, additive work, exactly as B46-4A's own "API code path" section anticipated it.

## Machine verification (this pass)

- `python3 -m pytest gateway/api/tests/test_config.py gateway/api/tests/test_hysteria_profile_endpoint.py gateway/api/tests/test_hysteria_provisioning.py gateway/api/tests/test_hysteria_auth_backend.py gateway/api/tests/test_xray_profile_endpoint.py` (WSL Ubuntu, real `fcntl`) - **107 passed, 0 failed**.
- Full gateway suite (`gateway/api/tests/`, same environment) - **505 passed, 1 pre-existing failure** (`test_edge_deployment_config.py::StockholmNginxExposesIngressProfileTests::test_ingress_profile_proxies_to_ITS_OWN_loopback_8444_never_the_exit_roles_8443`), confirmed present and unrelated on the unmodified branch tip before this pass's changes (reverted working tree, reran the same test in isolation, same failure) - an existing nginx-config-vs-test drift this slice's diff does not touch (no nginx/edge-deployment files were edited).
- Android build/tests were **not** re-run this pass - this slice touches only `gateway/api/` (Python), zero Android source changes.

## What is verified vs. not verified after this pass

**Verified:**
- The live route exists, is reachable, and behaves correctly under real HTTP requests (success, retry-rotation, unauthorized/revoked/expired/device-not-bound, not-configured) - proven by a real running `ProvisioningServer` instance in tests, not just unit-level function calls.
- The route never leaks the raw secret into its own durable store (only the salted hash persists - reusing `hysteria_provisioning.py`'s existing, already-tested storage discipline).
- The route reuses the existing activation store/credential system - no second activation/token system was introduced.
- Client-side trust discipline (item 8) was independently re-inspected this pass and confirmed already correct from B46-4A - no regression, no change needed.

**Not verified (explicitly, not silently):**
- No real Stockholm UDP port, TLS certificate, systemd unit, native-binary production packaging, or signed manifest binding exists yet (items 3-7).
- No UI entry point exists yet for a human to actually select Hysteria2 through the normal app (item 9).
- No physical device test has been run against this route (item 10) - doing so before items 3-7/9 are real would only produce a misleading result against non-production infrastructure.
- This pass's Python-only changes have not been re-validated against a live production-like WSGI/systemd deployment - only the in-process `ProvisioningServer` test harness.

## Item 9 slice: Hysteria2 in the Diagnostics UI

**Audit finding (before implementing anything):** the Android side already had a complete, tested Hysteria2 eligibility/selection/provisioning pipeline from B46-4A - `MainViewModel.isHysteria2AvailableFor`, the manual-connect path's `trustedTransportBindingFor` re-resolution (`MainViewModel.kt:2932`), and the automatic post-AWG-activation provisioning call (`MainViewModel.kt:2530-2550`) that already writes its outcome into a public `hysteria2ProfileProvisioningState: StateFlow<Hysteria2ProvisioningOutcome?>`. None of that needed to be rebuilt. The ONLY genuinely missing piece was UI surface area: `DiagnosticsDialog.kt`'s Force-Transport button list had no HYSTERIA2 entry (SHADOWSOCKS_2022's own equivalent button already established this exact pattern for a transport with no other production UI entry point yet), and `hysteria2ProfileProvisioningState` was wired but never read anywhere in the UI - not even for Xray's equivalent `xrayProfileProvisioningState`, confirmed absent there too.

**Why no separate "provision now" trigger/loading spinner was added:** provisioning is event-driven (fires automatically inside `activateDevice()`, once, right after a successful AWG activation - never a manual per-transport network call anywhere in this app, not for Xray, not for Shadowsocks2022, not for Hysteria2). Building a new manual "Provision Hysteria2 now" button with its own loading state would have been a NEW mechanism this project does not otherwise have for any transport - explicitly out of scope per this slice's own instructions ("do not invent a new state-management mechanism just for Hysteria2"). The existing generic re-activation entry point (`onReactivateGermany` → `ActivationScreen` → `activateDevice()`) already re-runs Hysteria2 provisioning like every other transport's; that flow's own loading/error handling is untouched, pre-existing, and out of this slice's scope.

**What changed:**
- [`android/app/src/main/java/net/pocvpn/client/ui/screens/DiagnosticsDialog.kt`](../android/app/src/main/java/net/pocvpn/client/ui/screens/DiagnosticsDialog.kt): added a "Force HYSTERIA2 on next connect" `TextButton`, directly below the existing SHADOWSOCKS_2022 button, using the exact same `onSetTransportForce(TransportKind.HYSTERIA2)` call every other Force button already uses.
- [`android/app/src/main/java/net/pocvpn/client/ui/AppRoot.kt`](../android/app/src/main/java/net/pocvpn/client/ui/AppRoot.kt): added one new diagnostics line, `"Hysteria2 provisioning: ${viewModel.hysteria2ProfileProvisioningState.value ?: "-"}"`, mirroring the existing `lastManifestRefreshLine`'s "-" = never-attempted convention. Reads an existing `StateFlow` only - no new state was added.
- [`android/app/src/main/res/values/strings.xml`](../android/app/src/main/res/values/strings.xml): one new string, `diagnostics_force_hysteria2`, following the exact naming/wording convention of `diagnostics_force_shadowsocks`.

**Tests:**
- `:app:compileDebugKotlin` - **BUILD SUCCESSFUL**.
- `:app:compileDebugUnitTestKotlin` - **BUILD SUCCESSFUL**.
- `:app:testDebugUnitTest --tests "*Hysteria2*" --tests "*TransportRegistry*" --tests "*SmartConnectDecisionEngine*"` - **BUILD SUCCESSFUL** (targeted re-check of every test suite this slice could plausibly affect).
- `:app:testDebugUnitTest` (full suite) - **1842 tests, 1 failure** - the SAME pre-existing `EffectiveConfigDiffTest > real BuildConfigGatewaySource now yields full-tunnel AllowedIPs` `ClassCastException` B46-4A's own doc already baselines (a missing machine-local `gateway-dev.properties`, unrelated to Hysteria2/UI, present before this slice's changes) - no new failure, no regression.
- `:app:assembleDebug` - **BUILD SUCCESSFUL** (proves the new string resource resolves and the dialog/AppRoot changes compile and package cleanly).
- No Compose UI test exists for `DiagnosticsDialog` in this repo (confirmed by search) - per this slice's own instructions, no new UI test framework was introduced; correctness was verified by compile + full unit suite + manual code-path tracing of the reused `onSetTransportForce`/`hysteria2ProfileProvisioningState` wiring, all of which already have their own coverage from B46-4A (`MainViewModelHysteria2SelectionTest`, `MainViewModelHysteria2ProvisioningCompositionTest`).

**What is verified vs. not verified after this pass:**
- Verified: the button exists, compiles, and calls the exact existing, already-tested `onSetTransportForce`/`debugSetTransportPreference(Manual(HYSTERIA2))` path; the new diagnostics line reads the exact existing, already-tested `hysteria2ProfileProvisioningState`; the whole app still compiles and assembles; the full unit suite has zero new failures.
- Not verified: no physical device has tapped this button or observed this line on a real screen (this pass was a Kotlin/Compose source change with automated build/test verification only, not an interactive UI session); this UI still leads nowhere useful in practice until items 3-7 (real server, TLS, signed manifest) exist, since `isHysteria2AvailableFor`'s eligibility gate keeps HYSTERIA2 `NOT_IMPLEMENTED` without them.

## Git-only server infrastructure slice (items #5/#6 + design prep for #3/#4/#7)

Strict scope: **no server was connected to, no production deployment performed.** Everything below is a reviewable git artifact only. See `gateway/hysteria/README.md` for the full technical detail; this section summarizes what belongs to which bucket, per this slice's own instruction to never call a design a production completion.

### Git-only ready (this pass)

- `gateway/hysteria/VERSION` - real, verified pinned Hysteria2 commit/tag/release-asset/checksum (cross-checked this pass against a genuine download - not fabricated), plus a newly-found, explicitly documented GPL-`sing-tun`-in-server-binary licensing GAP.
- `gateway/hysteria/fetch-hysteria-server.sh` - reproducible fetch/verify/install script, fail-closed on a missing/malformed checksum or commit mismatch, never floats to "latest". A real bug (tag names containing `/`, e.g. `app/v2.12.3`, broke the install-directory creation) was found and fixed by this slice's own test suite before merge - not shipped broken.
- `gateway/hysteria/render_server_config.py` - deterministic, fail-closed Hysteria2 server `config.yaml` renderer. No dynamic per-device re-render (architecturally correct per Hysteria2's own `auth.type: http` design - see README). No `obfs:`/secret material ever embedded.
- `gateway/systemd/nova-hysteria2.service` - a real, `systemd-analyze verify`-clean unit template, hardening directives individually re-justified against what this specific binary needs (not copy-pasted from `nova-xray.service` wholesale - e.g. `AF_NETLINK` was added with a stated, QUIC-specific reason).
- 26 new Python tests (`gateway/hysteria/tests/`), all passing.

### Waiting on a production decision (owner, not this pass)

- **#3 Port**: which UDP port Hysteria2 actually listens on publicly. Candidates only documented, no decision made, no real-host audit possible (no SSH access in this environment).
- **#4 Hostname/TLS**: a new DNS hostname (recommended shape only) and a real certificate for it. Nothing created.

### Waiting on server deployment (owner + explicit approval, not this pass)

- Installing the fetched Hysteria2 binary on Stockholm.
- Installing/enabling/starting `nova-hysteria2.service`.
- Deciding AND implementing the auth-backend-listener architecture (Option A vs B - see README) - this is still an open DESIGN question, not merely a deployment step; the code for either option does not exist yet.
- Redeploying `pocvpn-api.service` with the (already-existing, from the prior slice) `HYSTERIA2_*` env vars actually set.
- Opening the chosen UDP port on the firewall/Security Group.
- Issuing the DNS record and TLS certificate once #3/#4 are decided.

### Waiting on signing (owner, offline ceremony, not this pass)

- **#7 Signed manifest binding.** Exact fields the ceremony will need, verified this pass against the real `gateway/tools/manifest_signing.py` schema and the real Android `Hysteria2ProfileMetadata.kt` contract (not guessed):
  - `Endpoint.id` - the existing `"stockholm"` endpoint id (unchanged - confirmed present in the live manifest scan).
  - A new `TransportBinding` on that endpoint: `kindOrdinal = 6` (HYSTERIA2 - confirmed appended last in `TransportKind`, machine-verified by `TransportKindOrdinalCompatibilityTest` in B46-4A), `host` (Stockholm's address - already known), `port` (from #3, NOT YET DECIDED), `metadata = {"hysteria2Profile": "{\"version\":1,\"sni\":\"<from #4, NOT YET DECIDED>\",\"obfuscationMode\":\"NONE\"}"}` - the exact JSON shape `Hysteria2ProfileMetadata.withHysteria2Profile`/`.hysteria2Profile()` require (closed key-set, version=1, NONE-only obfuscation for this slice).
  - No other Hysteria2-specific manifest field exists in the schema - confirmed by reading `Hysteria2ProfileMetadata.kt` directly (only `sni`/`obfuscationMode` beyond the binding's own `host`/`port`).
  - **Signing itself was NOT performed.** No live manifest was read-written, no private signing key was touched, no new manifest artifact was produced.

### Waiting on physical test (item #10, unchanged, still BLOCKED)

Cannot proceed until #3/#4/#5/#6(deployment)/#7 are genuinely green.

## Decision gate

**Do not call this MERGE READY or production-deployed.** Items 1, 2, 8, and 9 of the B46-4P checklist are done and tested. Item 5 (systemd) and the server-side half of item 6 (native binary packaging) are now **IMPLEMENTED - NOT DEPLOYED** (real, tested, reviewable git artifacts; zero live infrastructure change). Items 3 and 4 have real audit findings and technical design recommendations but remain **NOT STARTED** as production decisions - no port was chosen, no hostname/certificate was created. Item 7 remains **NOT STARTED** - preparation only, no signing performed. Item 10 remains **BLOCKED**. A newly-found GPL-licensing question for the server-side Hysteria2 binary (see `gateway/hysteria/VERSION`) also awaits an explicit owner decision, independent of B46-2B/2C's own still-open client-side equivalent. B46-4A's PR #111 remains draft.
