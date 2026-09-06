# Russia field-test build (FIELD_TEST_ONLY) - disposable diagnostic APK

**Nothing server-side in this document has been applied.** This build exists
to answer exactly one question: can the existing Nova VPN AWG data plane
connect from a real restricted Russian network with registration/
provisioning/activation completely removed from the equation? It is not a
production feature, does not touch B36, and is never merged as-is into a
release build.

## What this is

- A dedicated Gradle **build type**, `fieldTest` (see `android/app/build.gradle.kts`)
  - NOT a product flavor - a build type keeps every existing task name
    (`compileDebugKotlin`, `assembleDebug`, `assembleRelease`, ...) exactly
    as it is; it only adds `compileFieldTestKotlin`/`assembleFieldTest`
    alongside them.
  - `applicationIdSuffix = ".fieldtest"` - installs side by side with the
    normal app, never overwrites it.
  - `versionNameSuffix = "-FIELD_TEST_ONLY"`.
  - `signingConfig = signingConfigs.getByName("debug")` - no dedicated
    release-signing mechanism exists in this repository (no
    `signingConfigs` block, no committed keystore), so this reuses the
    existing debug signing config, exactly like any other debug build.
- A dedicated source set, `android/app/src/fieldTest/java/net/pocvpn/client/fieldtest/`
  - `FieldTestActivity`/`FieldTestViewModel`/`FieldTestTunnelController`/
    `FieldTestIdentity`/`FieldTestAwgProfile`/`FieldTestDiagnostics` -
    these classes do not exist in the `debug`/`release` compile at all
    (not merely unreachable behind a flag).
  - `android/app/src/fieldTest/AndroidManifest.xml` overrides the launcher
    activity for this build type only (`FieldTestActivity`, not
    `MainActivity`) and the app label (`Nova VPN Field Test`, via
    `android/app/src/fieldTest/res/values/strings.xml`).
- Unit tests in `android/app/src/testFieldTest/java/...` (field-test-only)
  and one isolation proof in `android/app/src/testDebug/java/...`
  (`FieldTestIsolationTest` - proves the normal debug build's
  `BuildConfig.FIELD_TEST_ONLY` stays `false`).

## UX

Install → open → **Connect**. Nothing else. No activation screen, no
activation code, no provisioning, no registration, no account creation, no
bootstrap API, no profile download, no technical setup screen.

## Routing

Deterministic: Frankfurt (`GERMANY` in `ProductionGatewayCatalog`) first,
Stockholm on failure - reusing the existing production `AmneziaWgTransport`
implementation verbatim (`FieldTestTunnelController` mirrors
`net.pocvpn.client.bootstrap.BootstrapTunnelController`'s own real-fresh-
handshake proof, never a fake success from transport state alone). This
build's own peer is a NORMAL, full-tunnel AWG peer (`AllowedIPs = 0.0.0.0/0,
::/0`) - no B36 restricted-bootstrap semantics are created or reused here.

## Field-test identity

A dedicated, disposable Curve25519/X25519 keypair - **not** the B36
bootstrap identity, **not** any real user's production profile, **not**
another test device's identity (`android/app/src/fieldTest/java/net/pocvpn/client/fieldtest/FieldTestIdentity.kt`):

```
FIELD_TEST_PRIVATE_KEY_BASE64 = 4FItbS5xOT2BnyNcnGV/5QA6FA7d6NsCbScbboSJk00=
FIELD_TEST_PUBLIC_KEY_BASE64  = MWF0412X2xLalQD1BrW39z/yCPW/Hy3z1O19WvTIbSs=
CLIENT_TUNNEL_ADDRESS_CIDR    = 10.77.0.251/32
```

**Trust boundary, explicit**: this key is embedded in a disposable APK and
must be considered public/extractable. Acceptable for this one-off
diagnostic only. Never reuse it for anything beyond this field test.

## Server-side peer setup (NOT YET APPLIED - requires owner approval)

Reuses the existing `gateway/scripts/add-peer.sh` verbatim - the same
tooling `install-bootstrap-peer.sh`/manual provisioning already use. A
**normal** peer, full Internet access, no firewall change, no B36 table, no
Xray/nginx/control-plane change, no other peer touched.

### Frankfurt (`152.70.43.1`)

```bash
cd /opt/pocvpn/gateway
sudo ./scripts/add-peer.sh MWF0412X2xLalQD1BrW39z/yCPW/Hy3z1O19WvTIbSs= 10.77.0.251 field-test-russia
```

### Stockholm (`16.170.208.231`)

```bash
cd /opt/pocvpn/gateway
sudo ./scripts/add-peer.sh MWF0412X2xLalQD1BrW39z/yCPW/Hy3z1O19WvTIbSs= 10.77.0.251 field-test-russia
```

Verify on either host: `sudo awg show awg0 peers` (the public key above
should be listed).

### Rollback (either host, once the field test is done)

```bash
cd /opt/pocvpn/gateway
sudo ./scripts/remove-peer.sh MWF0412X2xLalQD1BrW39z/yCPW/Hy3z1O19WvTIbSs=
```

## Diagnostics / reporting

`FieldTestDiagnosticsRecorder` (mirrors
`net.pocvpn.client.bootstrap.BootstrapDiagnosticsRecorder`'s own "separate,
purpose-built recorder" reasoning) records a bounded, sanitized event
timeline for every attempt. `FieldTestReport` (built by
`FieldTestViewModel`) always includes: build label (`FIELD_TEST_ONLY`), app
version/build variant, timestamp, network type, routing mode
(`FULL_VPN`), the real `RestrictionClassifier` classification (reusing the
app's own pure classification function, no fabricated pipeline), gateways
attempted, final gateway/transport, outcome, failure category, and the
sanitized event list - never a private key, credential, raw profile,
device secret, UUID/token, payload, or destination URL (defense-in-depth
pass via the existing `DiagnosticSanitizer`, same as
`buildSupportBundle`).

- If the VPN connects, the report is passed to `FieldTestReportUploader
  .uploadThroughTunnel` (an interface point for a future real upload
  server - no diagnostics-upload endpoint exists anywhere in this codebase
  today, so the shipped implementation, `NoOpFieldTestReportUploader`,
  correctly returns `false`, which drives the existing local-report
  fallback rather than fabricating a fake success).
- Either way (success or failure), the report is kept locally and can
  always be shared manually via `FieldTestActivity`'s "Share report"
  button - the exact same `Intent.ACTION_SEND` / `application/json`
  pattern `net.pocvpn.client.ui.AppRoot`'s own "Export diagnostics" button
  already uses.
- A report/upload failure never tears down or fails an otherwise healthy
  VPN session - see `FieldTestViewModelTest`'s own reporting tests.

## What this explicitly does NOT do

- Does not solve production activation.
- Does not continue B36 bootstrap work, does not modify/merge PR #60.
- Does not redesign the architecture.
- Does not change the production/manual-activation build (verified: the
  `fieldTest` source set is compiled only for that one build type; see
  `FieldTestIsolationTest`).
- Does not touch normal peers, activation stores, Xray infrastructure,
  nginx, or the control-plane on either gateway.
- Does not deploy anything server-side by itself - the commands above are
  reported only, per this repository's merge/infra-safety rule.
