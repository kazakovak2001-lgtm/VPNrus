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
| 5 | systemd/service lifecycle | **IMPLEMENTED - NOT DEPLOYED** | `gateway/systemd/nova-hysteria2.service` is a real, `systemd-analyze verify`-clean unit template (mirrors `nova-xray.service`'s hardening exactly, re-justified per-directive, not copy-pasted) - not installed/enabled/started on any host. The loopback auth-backend listener this unit's config depends on is now RESOLVED as Option A (extend `pocvpn-api.service`) - see "Auth backend architecture" below - and actually implemented in `gateway/api/handler.py` (`POST /internal/hysteria-auth`), real-tested (9 new tests), but not yet deployed (requires a `pocvpn-api.service` redeploy). |
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

## Architecture-gates slice: licensing audit, auth backend decision, endpoint contract

Strict scope, same as every prior B46-4P pass: **no SSH, no DNS, no AWS changes, no firewall, no TLS issuance, no systemd install, no signing, no live manifest update.** This pass closes two open architectural questions with real evidence and one implementation, and produces a precise, git-only contract for the three items (#3/#4/#7) that still require a production decision or a live deployment.

## Licensing decision gate

Full technical audit performed against upstream source/release/API at the exact pinned commit (`e1366b173ccf5706e1e4630fe8aa654a4b574085` / `app/v2.12.3`) - see `gateway/hysteria/README.md`'s own "Licensing decision gate" section for the complete evidence table (Hysteria2's `app` module is MIT; `apernet/sing-tun` - the module actually linked - is GPL-3.0-or-later, verified by fetching its `LICENSE` file directly at its pinned pseudo-version commit; the dependency is statically linked into one monolithic binary regardless of which subcommand runs, confirmed via `file` and a direct byte-scan for `sing-tun.*` symbols; `app/cmd/server.go`'s own import list does NOT reference `tun`/`sing-tun` at the source level - only `app/cmd/client.go` does, with no build tag gating it out of the binary; no official server-only release variant exists).

**This remains a technical evidence report, not a legal conclusion.** The repository owner/legal must decide: whether running this exact statically-linked multi-command binary (with only the `server` subcommand ever invoked, and Nova's own server-side Python code entirely separate and never linked into it) triggers GPLv3's own distribution/copyleft obligations for the surrounding proprietary deployment - and, if so, whether to invest in a stripped server-only rebuild instead. **Status: BLOCKED - licensing review**, not resolved by this or any prior pass.

## Auth backend architecture

**Decided and implemented this pass: Option A** (extend `pocvpn-api.service`, not a separate unit).

| Criterion | Option A (extend `pocvpn-api.service`) | Option B (separate `nova-hysteria-auth.service`) |
|---|---|---|
| Security - network exposure | Inherits the SAME hardcoded `127.0.0.1`-only bind `server.py` already enforces for every route - no new listener, no new attack surface to reason about. | Would need its own bind-host decision, own review of whether it could ever be misconfigured to listen elsewhere - a new surface. |
| Security - secret handling | Reuses the SAME `hysteria_store.py`/`activations.py` file access `/v1/hysteria-profile` already has - no new file permission model. | Would need its OWN read access to the identical two stores - no actual isolation gained, since both processes would need to reach the SAME files. |
| Isolation / blast radius | A compromise of `pocvpn-api.service` already reaches the Hysteria2 store today (via `/v1/hysteria-profile`) - Option A adds no NEW data this process couldn't already reach. | Would only meaningfully reduce blast radius if the new process held a secret `pocvpn-api` does NOT already have - it does not (same stores). No real isolation benefit found. |
| Reliability - restart behavior | A `pocvpn-api.service` restart (`Restart=on-failure`, `RestartSec=2`) briefly interrupts NEW Hysteria2 connection attempts only - existing QUIC sessions are unaffected (Hysteria2 authenticates once per connection, not per packet). | New connection auth would survive a `pocvpn-api.service` restart - a real, small reliability edge, but for a ~2s window on a low-frequency endpoint. |
| Reliability - dependency ordering | None needed - same process, same lifecycle, already running before Hysteria2 would ever start (existing `pocvpn-api.service` predates any Hysteria2 deployment). | Would need explicit `After=`/`Requires=` ordering against a new unit - one more thing to get right and keep right. |
| Operational complexity | Zero new units, zero new env files, zero new log streams/monitoring targets - the existing `pocvpn-api` observability (`_log_request`, rate limiters) already covers the new route. | One more systemd unit, one more env file, one more log stream, one more thing to monitor/alert on/document in runbooks - for a route with no isolation benefit over Option A. |
| Existing architecture fit | Matches this project's own established pattern exactly: `/v1/xray-profile`, `/v1/hysteria-profile`, and (on the ingress host) `/v1/ingress-profile` are ALL served by the same kind of single `pocvpn-api`-shaped process per role - never a dedicated per-feature listener. | Would be the FIRST exception to that pattern in this codebase, with no evidence-backed reason found for why Hysteria2's auth callback specifically needs one. |
| Performance | Auth is a low-frequency, per-connection-establishment event (not per-packet) - `ThreadingHTTPServer`'s existing per-request-thread model already handles this with no changes needed. | Same low frequency - a dedicated process would not measurably improve latency/throughput here; not a real differentiator. |

**Evidence-based conclusion**: Option A is the correct architecture. No security/isolation dimension favors Option B once the actual data-access overlap is accounted for (both options reach the identical two stores; Option B's usual isolation argument - the one that DOES justify `nova-xray-ingress.service` being separate from `nova-xray.service`, namely a distinct REALITY private key per gateway role - does not apply here, since there is no per-role secret split for the Hysteria2 auth backend). Option A also has a real, if small, reliability trade-off (new-connection auth is briefly unavailable during a `pocvpn-api.service` restart) - accepted as the correct trade against Option B's real operational-complexity cost and its complete absence of an offsetting security benefit.

**Implemented this pass** (git-only, not deployed): `gateway/api/handler.py`'s `POST /internal/hysteria-auth`, wired to the already-existing `gateway/api/hysteria_auth_backend.handle_auth_request` + `hysteria_provisioning.verify_hysteria_auth`. 9 new end-to-end tests (`gateway/api/tests/test_hysteria_auth_endpoint.py`) prove the full chain against a real running server: issuance → provisioning → auth success, wrong-secret rejection, live revocation (auth stops working immediately, zero Hysteria2 server reload - the entire point of choosing `auth.type: http`), retry-safe-rotation invalidating the old secret, malformed-body handling, no-Authorization-header operation (this route authenticates via the presented wire secret in the body, never an activation credential), and not-configured fail-closed behavior. **Status: DESIGN COMPLETE AND IMPLEMENTED - NOT DEPLOYED** (real code, zero live server change - `pocvpn-api.service` on Stockholm still runs the old code until an operator redeploys it).

## Production endpoint contract

**Correction carried in this pass**: `gateway/api/handler.py`'s `_handle_hysteria_profile_inner` was found to return `server_address: cfg.endpoint_host` (the SAME shared bare-IP value every other transport uses) instead of the dedicated Hysteria2 hostname this contract requires - a real bug that would have made every real device reject its own provisioning response the moment a manifest ever named the dedicated hostname below (Android's `Hysteria2ProfileProvisioner` cross-checks `server_address` against the manifest-pinned `host` and fails closed on any mismatch). **Fixed**: `server_address` is now `cfg.hysteria2_sni` - the same single value also used for the `sni` field, the future manifest's `hysteria2Profile.sni`, and the DNS hostname once minted - one source of truth. Covered by an updated, regression-proof assertion in `gateway/api/tests/test_hysteria_profile_endpoint.py`.

| Field | Status | Value / finding |
|---|---|---|
| Hostname | **NOT DECIDED** (design ready, proposal formalized) | Neither existing Stockholm hostname is reusable: `edge-sthlm.aknova.pp.ua` is a Cloudflare-fronted HTTPS/TCP origin for the XHTTP ingress role (wrong protocol shape for raw UDP/QUIC); `control.aknova.pp.ua` (a real, live, working hostname+cert found this pass by direct probe - NOT represented in any nginx file tracked in this repository, a documentation-drift finding) is this gateway's own control-plane/API identity, and reusing it for an unrelated protocol would be a confusing identity overload. **Formalized proposal**: `NOVA_HYSTERIA2_HOSTNAME=hysteria-sthlm.aknova.pp.ua` (mirrors the existing `<role>-sthlm.aknova.pp.ua` convention `edge-sthlm`/`origin-sthlm` already establish) - re-checked this pass, still currently unclaimed (DNS `NXDOMAIN`). **Not created. Final production approval remains an explicit, separate decision gate.** |
| UDP port | **NOT DECIDED** (Variant 2 - explicit deployment decision, per this slice's own instruction) | No project convention names a specific port for a new UDP transport (AWG's `51820` is its own historical/protocol-specific choice; Xray's TCP `2053` was a one-off "avoid known ports" decision documented in `gateway/xray/README.md` - neither generalizes to a rule). Historical `34443` was a temporary test port, since closed - not a precedent. **Formalized as an explicit, un-hardcoded placeholder**: `NOVA_HYSTERIA2_LISTEN_PORT` (already the real env var name `gateway/hysteria/render_server_config.py` reads - no number is baked in anywhere in git). |
| SNI | **NOT DECIDED** | Follows directly from Hostname above - whatever hostname is minted becomes the SNI value in both the Hysteria2 server's own TLS cert and the signed manifest's `hysteria2Profile.sni` field. |
| TLS cert path | **NOT DECIDED** (mechanism proven, specific paths not) | `render_server_config.py`'s `tls_cert_file`/`tls_key_file` fields are real, validated (absolute-path, fail-closed on blank/relative), and env-driven (`NOVA_HYSTERIA2_TLS_CERT_FILE`/`_KEY_FILE`) - no path is hardcoded. The actual files do not exist yet (no cert issued). |
| Certificate ownership | **Convention decided, not yet applied** | Same Let's Encrypt-via-certbot lifecycle this gateway already uses for its other certs (the bare-IP vhost's own 160h-renewal automation, `gateway/edge/pocvpn-cert-check.service`) - `control.aknova.pp.ua`'s own cert (found live, 90-day validity) proves normal-hostname Let's Encrypt issuance already works on this exact host, whatever the exact issuance mechanism (not tracked in this repo). |
| Renewal mechanism | **NOT VERIFIED for a new hostname** | `control.aknova.pp.ua`'s cert is currently valid and mid-lifecycle (`2026-09-14`..`2026-12-13`) - proves SOME renewal automation exists for it live, but its exact mechanism/hook is not tracked in this repository and was not reverse-engineered this pass. A new Hysteria2 hostname would need its own renewal hook confirmed working after issuance - a post-deployment verification item (see checklist below). |
| Hysteria2 server config expectation | **Implemented, env-driven, fail-closed** | `render_server_config.py`'s `HysteriaServerConfig` dataclass has no default for any of these four fields - a deploy-time render with any one missing/malformed raises `HysteriaServerConfigRenderError` before any file is written. |

## TLS contract

Explicit, to avoid ever silently overclaiming readiness:

- **What already exists**: this project's Let's Encrypt/certbot renewal automation is proven working, live, TWICE on this exact host (Stockholm's bare-IP cert AND `control.aknova.pp.ua`'s hostname cert, both currently valid) - the MECHANISM is not a risk. `Hysteria2ChildRuntime`'s hard `insecure=false` production gate (B46-4A) already refuses to start without a real, valid TLS setup - this cannot be silently weakened to make a test connection "work".
- **What must be created (owner + explicit approval, not this pass)**: a new DNS record for the chosen hostname, pointed directly at Stockholm's IP (no Cloudflare fronting - Hysteria2 needs a genuine UDP/QUIC path to the origin); a new Let's Encrypt certificate for that hostname; a renewal hook covering it; read permission for the `nova-hysteria2` service account on the resulting `privkey.pem` (Let's Encrypt's own default is root-only - flagged, not resolved, in `gateway/hysteria/README.md`'s own "Certificate file permissions" note).
- **What must be verified after deployment (not claimed here)**: the issued cert's SAN actually matches the chosen hostname; `openssl s_client -connect <host>:<port>` (adapted for QUIC/UDP, which `s_client` itself cannot directly probe - a real Hysteria2 client-side connection attempt is the actual proof) succeeds with `insecure=false`; the cert renews automatically before its first real expiry with no manual step; the `nova-hysteria2` process can actually read the key file under its own non-root UID at start time.

## Manifest contract

Exact model for the future (NOT executed) signing ceremony, verified this pass directly against the real, live `gateway/tools/manifest_signing.py` schema and `gateway/tools/production_manifest_2026-09-20_v4.json` (the real, currently-live manifest's own tracked JSON source - confirmed this pass to carry `signingKeyId="prod-manifest-key-2026-09-14"`, matching the live-fetched manifest exactly, and confirmed the `stockholm` endpoint's current `transports` list is `[0, 1, 3]` = `AMNEZIA_WG`/`XRAY_REALITY`/`TLS_TCP` only - no `5` (`SHADOWSOCKS_2022`) or `6` (`HYSTERIA2`) yet):

```text
server identity            -> Stockholm's own IP/host (already known, unchanged)
    |
hostname                   -> NEW, NOT YET MINTED (see "Production endpoint contract")
    |
UDP port                   -> NOT YET DECIDED (NOVA_HYSTERIA2_LISTEN_PORT placeholder)
    |
TLS/SNI                    -> depends on hostname above; cert NOT YET ISSUED
    |
Hysteria2 server            -> gateway/hysteria/ (fetch/config/systemd - IMPLEMENTED, NOT DEPLOYED)
    |
signed manifest             -> gateway/tools/manifest_signing.py (offline ceremony - NOT RUN)
    |                          adds ONE new TransportBinding to the EXISTING "stockholm" endpoint:
    |                            kindOrdinal = 6           (HYSTERIA2 - confirmed last-appended ordinal)
    |                            host        = <Stockholm's existing address>
    |                            port        = <from UDP port decision above>
    |                            metadata    = {"hysteria2Profile":
    |                                            "{\"version\":1,\"sni\":\"<from hostname decision>\",\"obfuscationMode\":\"NONE\"}"}
    |                          (no other Hysteria2-specific field exists in the schema -
    |                           confirmed by reading Hysteria2ProfileMetadata.kt directly)
    |
Android trusted binding      -> EndpointManifestRepository.trusted() + Ed25519ManifestVerifier
    |                          (existing mechanism, unchanged, untouched by this slice)
    |
credential provisioning      -> POST /v1/hysteria-profile (live in code since the prior B46-4P slice)
    |                          -> POST /internal/hysteria-auth (live in code as of THIS slice)
    |
Hysteria2 eligibility         -> MainViewModel.isHysteria2AvailableFor (existing, unchanged, B46-4A)
```

Each arrow's source of truth is a single, distinct artifact - no step is inferred from another. **No live manifest was read-written this pass. No signing was performed. No new manifest artifact was produced.**

## Pre-deployment checklist

- [ ] licensing review completed (owner/legal - see "Licensing decision gate" above)
- [ ] auth architecture fixed - **DONE this pass** (Option A, implemented, tested; not yet deployed)
- [ ] production hostname selected
- [ ] UDP port selected
- [ ] DNS ready
- [ ] TLS certificate ready
- [ ] server binary checksum verified - **DONE** (`gateway/hysteria/VERSION`, cross-checked against a genuine download)
- [ ] systemd unit reviewed - **DONE this pass** (`gateway/systemd/nova-hysteria2.service`, `systemd-analyze verify`-clean)
- [ ] firewall rule prepared
- [ ] API deployment prepared - **partially DONE** (`gateway/api/handler.py`/`config.py` code is ready; the actual `pocvpn-api.service` redeploy is not performed)
- [ ] manifest generated
- [ ] manifest signature verified
- [ ] Android trusted binding verified
- [ ] physical OPPO test performed

## Deployment readiness checklist (detailed sequence)

Nothing below has been executed. **Do not begin item 1 until the licensing gate above has an explicit owner/legal decision recorded.** Sequenced so each item's prerequisites are already satisfied by the item before it.

1. **DNS** - create `hysteria-sthlm.aknova.pp.ua` (or the owner's final chosen hostname) as an A record pointed directly at Stockholm's IP, no Cloudflare proxying.
2. **UDP firewall/security group** - open the chosen `NOVA_HYSTERIA2_LISTEN_PORT` inbound on Stockholm's Security Group, source `0.0.0.0/0` (or a narrower soft-launch CIDR, mirroring `gateway/xray/README.md`'s own documented option for its own port).
3. **Hysteria2 listener** - run `gateway/hysteria/fetch-hysteria-server.sh` on the real host (only after the licensing gate is resolved - see VERSION's own GAP), render `config.yaml` via `render_server_config.py` with the real port/cert paths/auth-backend URL.
4. **TLS certificate** - issue a real Let's Encrypt certificate for the hostname from step 1 (same mechanism `control.aknova.pp.ua`'s already-live cert evidently uses); grant the `nova-hysteria2` service account read access to the resulting `privkey.pem`.
5. **Auth backend** - redeploy `pocvpn-api.service` with this branch's code (adds `POST /internal/hysteria-auth`, live in code since this pass) and the `HYSTERIA2_*`/new hostname-derived env vars actually set in `/etc/pocvpn/api.env`.
6. **Hysteria2 credential store** - initialize `hysteria_store.py`'s store file at the configured `HYSTERIA2_STORE_PATH` on the real host (mirrors `xray_provisioning.init_store`'s own one-time setup step).
7. **systemd service** - install `gateway/systemd/nova-hysteria2.service`, create the `nova-hysteria2` user/group, `systemctl daemon-reload`, `enable --now`.
8. **Health check** - confirm the process is actually listening on the chosen UDP port (`ss -lun`) and that `journalctl -u nova-hysteria2` shows no startup error (esp. the `insecure=false` TLS gate and the `auth.http.url` loopback reachability).
9. **Manifest generation** - add the ONE new `TransportBinding` to the `stockholm` endpoint in a new `production_manifest_<date>_v5.json` (mirrors the existing `_v3`/`_v4` file naming already tracked in `gateway/tools/`), following the exact schema in "Manifest contract" above.
10. **Manifest signing** - run the existing offline `gateway/tools/manifest_signing.py` ceremony against the new JSON, using the SAME production signing key/process already used for `_v4` - never a manual binary edit.
11. **Client provisioning** - confirm a real device's `POST /v1/hysteria-profile` call succeeds against the redeployed server and the response's `server_address`/`sni` match the signed manifest's `host`/`hysteria2Profile.sni` exactly (this is the exact cross-check "Corrections this pass" fixed - verify it holds for real, not just in tests).
12. **Revoke/rotate** - confirm revoking the test activation immediately stops `POST /internal/hysteria-auth` from authenticating it (no Hysteria2 server reload), and that a second `/v1/hysteria-profile` call rotates to a new secret that invalidates the old one - both already proven in `gateway/api/tests/test_hysteria_auth_endpoint.py`, re-confirm against the REAL deployed server, not just the test harness.
13. **External IP test** - confirm a real Hysteria2 connection's egress IP matches Stockholm's known public IP (same style of check `docs/B10_LEAK_VALIDATION_PLAN.md` and B46-3C's own physical validation already used for other transports).
14. **Rollback plan** - know in advance how to revert step 5 (redeploy the PRIOR `pocvpn-api.service` code/env, since HYSTERIA2 stays `NOT_IMPLEMENTED` client-side without a trusted binding regardless) and how to remove the manifest binding (re-sign a version without it) if anything in steps 1-13 needs to be undone.

See [`B46_4P_OPPO_PHYSICAL_ACCEPTANCE_TEST_PLAN.md`](B46_4P_OPPO_PHYSICAL_ACCEPTANCE_TEST_PLAN.md) for the detailed physical test plan to run only after all 14 steps above are green.

## Decision gate

**Do not call this MERGE READY or production-deployed.** Items 1, 2, 8, and 9 of the B46-4P checklist are done and tested. Item 5 (systemd + auth backend) is now **DESIGN COMPLETE AND IMPLEMENTED - NOT DEPLOYED** (the auth-backend architecture question is RESOLVED this pass, Option A, with real working code and tests). The server-side half of item 6 (native binary packaging) is **IMPLEMENTED - NOT DEPLOYED**; the licensing question found alongside it remains **BLOCKED - licensing review**, an explicit, separate gate from deployment readiness. Items 3 and 4 have a precise, git-only-decided contract (env var names, validation, technical recommendations) but remain **NOT STARTED** as production decisions - no port was chosen, no hostname/certificate was created (a real, previously-untracked hostname+cert precedent, `control.aknova.pp.ua`, was found live on Stockholm this pass, raising confidence that minting a new one is low-risk, but nothing was minted). Item 7 remains **NOT STARTED** - the exact manifest diff the future signing ceremony will need is now fully specified, but no signing was performed. Item 10 remains **BLOCKED**. B46-4A's PR #111 remains draft.
