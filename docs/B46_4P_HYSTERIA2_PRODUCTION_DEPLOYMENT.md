# B46-4P: Hysteria2 Production Deployment Gate

## Status

**IN PROGRESS - NOT PRODUCTION-COMPLETE.** This is the explicit deployment gate B46-4A deliberately deferred to. B46-4A itself is a completed *implementation* phase (PR #111, draft) - not production-complete. Nothing in this document claims production readiness for any item marked below anything other than DONE with real evidence.

No AWS/security-group/server changes have been made. No Xray/AWG lab infrastructure (B46-3C) has been reused as production infrastructure. `EndpointManifestRepository` remains the sole trust authority - nothing in this slice bypasses it. B46-3C PR #110 is untouched.

## Checklist (audited against actual repo state, not assumed)

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Live `/v1/hysteria-profile` route + AppConfig fields | **DONE** | `gateway/api/handler.py` (`_PATH_HYSTERIA_PROFILE`, `_handle_hysteria_profile[_inner]`), `gateway/api/config.py` (`hysteria2_store_path`/`hysteria2_lock_path`/`hysteria2_server_port`/`hysteria2_sni`, fail-closed completeness group). Reuses the SAME activation store `/v1/activate`/`/v1/xray-profile` already use - never a second activation system. Still git-only: no systemd unit, no firewall rule, no live process serving this route yet. |
| 2 | Backend Hysteria2 provisioning/API dispatch | **DONE** (as of item 1) | `hysteria_provisioning.provision_hysteria_identity`/`verify_hysteria_auth` (already existed, B46-4A) are now actually reachable through the route above. |
| 3 | Stockholm UDP 34443 production-port/deployment audit | **NOT STARTED** | Requires inspecting real Stockholm host state (`ss`/`iptables` on the live server) - no server access performed in this slice, per the "no AWS/server intervention without approval" constraint. |
| 4 | Production TLS/certificate handling | **NOT STARTED** | Requires a real certificate/SNI provisioned against the live Hysteria2 UDP listener. `Hysteria2ChildRuntime`'s hard `insecure=false` gate (B46-4A) already refuses to start without it - fail-closed behavior preserved, not weakened. |
| 5 | systemd/service lifecycle | **NOT STARTED** | Proposed unit shape documented in B46-4A's own doc (`Server deployment proposal`); no unit file written or installed this slice. |
| 6 | Production packaging of the Hysteria2 native binary for supported ABI | **NOT STARTED** | `libnovahysteriachild.so`/`libnovatun2sockschild.so` remain in their B46-3B/B46-3C research locations; moving them into `src/main/jniLibs/arm64-v8a/` and re-verifying the SHA-256 is unchanged from B46-4A's own "Remaining B46-4P work" item 5. |
| 7 | Signed production manifest binding | **NOT STARTED** | No `EndpointTransportBinding(HYSTERIA2, ...)` has been signed into any manifest artifact. Requires the existing offline manifest-signing ceremony (`gateway/tools/manifest_signing.py`) - never a manual edit. |
| 8 | Client/server facts come from trusted signed topology, never blindly taken from the provisioning response | **DONE (verified this pass)** | `Hysteria2ProfileProvisioner.provision` (`android/app/src/main/java/net/pocvpn/client/provisioning/Hysteria2ProfileProvisioner.kt:53-78`) resolves the trusted `SignedTransportProfile.Hysteria2` FIRST and fails closed (`NoTrustedBinding`) before ever dialing the network; once resolved, the response's own `server_address`/`server_port`/`sni`/`obfuscation_mode` are cross-checked against that pinned profile and rejected (`Mismatched`) on any disagreement - the control-plane response is authority for SECRET material only. `MainViewModel`'s manual-connect path (`MainViewModel.kt:2932`) re-resolves the SAME `trustedTransportBindingFor` call at execution time, so a manually forced HYSTERIA2 selection gets no shortcut around the trusted signed binding either. No code change was needed for this item - already correct from B46-4A. |
| 9 | Normal UI flow for Hysteria2 selection/activation | **NOT STARTED** | `MainViewModel`'s eligibility/registry/manual-selection wiring for HYSTERIA2 already exists (B46-4A), but `DiagnosticsDialog.kt`'s Force-Transport button list - the established "normal app UI" entry point this project already uses for a new transport's physical validation (see its own B45B-4P comment for SHADOWSOCKS_2022) - has no HYSTERIA2 entry yet. Small, additive, same `onSetTransportForce`/`isDebugBuild` plumbing every existing button already uses; not started this pass. |
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

## Decision gate

**Do not call this MERGE READY or production-deployed.** Item 1 of the B46-4P checklist is done and tested; items 2 and 8 were audited and found already satisfied by existing B46-4A code (verified fresh this pass, not assumed from the old doc); items 3-7, 9, and 10 remain genuinely outstanding and require either server-side deployment work (explicit owner approval required before any AWS/security-group/server change) or additional git-only Android UI work (item 9) not yet done. B46-4A's PR #111 remains draft.
