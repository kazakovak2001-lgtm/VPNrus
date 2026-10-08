# Nova VPN — Beta Acceptance Report

> **Historical snapshot (written 2026-09-20/22, preserved 2026-10-09 from an uncommitted worktree).** Facts here describe that date; current status lives in `docs/ROADMAP.md`.

Status as of Day 5 of the 7-day Beta sprint. No marketing language - every
line below is either a physically observed fact, a test result, or an
explicitly labeled external dependency. See
[`NOVA_VPN_BETA_CUT.md`](NOVA_VPN_BETA_CUT.md) for the Day 1 branch/PR
triage this report builds on.

## Build

```text
Branch:      beta/0.1.0-beta1
Worktree:    C:/Users/akaza/Downloads/VPN-BETA-CUT
Base:        main @ 75cb4b249da24dc5d13197b0cc016147d79e0a81
Current HEAD: 77d2e0b (support: finalize beta contact flow)
```

## SHA256

```text
CURRENT (release, since Day 4 Support fix - re-verified Day 5 via a
         clean rebuild from the same HEAD, byte-identical):
432c3290220cd1e172fd68b73972e8b3795122e1014355d553587decb4fa12d8

Debug QA artifact (reproducible - built Day 3 and Day 5, byte-identical
         both times, from the same HEAD's source):
e382f17d9a08e6f0d8105d973a5fd17fff2e6a2bb4e29af066e3805bb7099f2b

Superseded (Day 3, pre Support-choice fix - do not use):
0bcd095911eb9bf26a443a983a32dc53afad591bbabde498a8b19f5053af2ae0

Superseded (Day 2, pre signing-wiring fix - do not use):
e2b55fa220f6b21b47f6155022afa96293c6c7c40cb4aea36995c4f5ce9f8ca1
```

Only the CURRENT (release) hash above is installed on the physical test
device as of this report. Day 5 re-ran both `assembleRelease` and
`assembleDebug` from a clean output directory against unchanged HEAD
`77d2e0b1d35a10e5e12bec16ce4c06636b2ef666`, specifically to confirm
reproducibility (not assumed) - both hashes matched their prior builds
exactly.

## Version

```text
versionName: 0.1.0-beta1
versionCode: 2
applicationId: net.pocvpn.client
minSdk: 26
targetSdk: 35
```

## Signing

```text
Mechanism: android/app/build.gradle.kts signingConfigs.release, reading
           android/app/keystore.properties (gitignored) or NOVA_RELEASE_*
           env vars - falls back to unsigned if neither present (no
           regression to a plain checkout)
Keystore:  android/app/nova-vpn-beta.jks - generated locally this sprint,
           gitignored, never committed, password never printed/logged
apksigner: Verifies=true, v2 scheme, 1 signer (re-verified against the
           CURRENT hash above)
debuggable: false (confirmed via aapt2 dump badging on the built artifact,
           not just source review)
```

## Device

```text
Model:    OPPO CPH2173
Android:  14
SDK:      34
ABI:      arm64-v8a
Connection: adb, authorized ("device" state)
```

## Tests

```text
Debug unit suite: 1738 passed, 1 failed
Known pre-existing failure: EffectiveConfigDiffTest > "real
  BuildConfigGatewaySource now yields full-tunnel AllowedIPs" -
  ClassCastException, missing machine-local gateway-dev.properties.
  Documented repeatedly across this project's history; confirmed present
  on unmodified main before any Beta work began; not touched.
New failures introduced this sprint: NONE
assembleRelease: PASS (x3 - Day 2 initial, Day 2 signing fix, Day 4
  Support fix - each rebuild re-verified end to end)
assembleDebug (QA variant): PASS, reproducible from current HEAD
```

## Physical QA

| Area | Status | Evidence |
|---|---|---|
| App launch (cold start) | **PASS** | No crash, `topResumedActivity` = MainActivity |
| Background -> foreground | **PASS** | Same activity instance restored |
| Process kill -> relaunch | **PASS** | `am force-stop` + relaunch, clean state, no crash |
| Screen rotation | **BLOCKED** | ColorOS shell denies `WRITE_SETTINGS` to `com.android.shell` - a device/OEM tooling restriction, not an app defect |
| Activation - empty input | **PASS** | Activate button correctly disabled |
| Activation - invalid credential | **PASS** | Clean "Invalid activation" message, no crash, no secret logged |
| Activation - network unavailable | **PASS** (app stability); **NOTED** (UX) | No crash; error text identical to "invalid credential" case - doesn't distinguish network failure (P2, not fixed this sprint - see Known Limitations) |
| Real activation | **BLOCKED — external** | No SSH access to the production gateway in this environment to mint an accepted credential (see External Dependencies) |
| AWG (real traffic) | **BLOCKED** | Activation-gated |
| Xray (real traffic) | **BLOCKED** | Activation-gated; additionally requires either a genuine AWG failure or the debug QA build, since the release build has no manual transport selector (by design - see Known Limitations) |
| Shadowsocks (real traffic) | **BLOCKED** | Activation-gated; same testability note as Xray |
| AWG->Xray failover | **source-audited, unit-tested; NOT physically verified** | `AwgXrayFailoverPolicy.kt` read in full and matches its own test suite (`AwgXrayFailoverPolicyTest.kt`); fires only on a genuine terminal AWG failure during an AUTO (non-manual) attempt |
| Xray->Shadowsocks "failover" | **confirmed NOT to exist** | Source fact, not a gap: `AwgXrayFailoverPolicy` is the only failover-policy class in this codebase and never references Shadowsocks |
| Disconnect/reconnect | **BLOCKED** | Activation-gated |
| Network change recovery | **BLOCKED** | Activation-gated |
| App restart during a live VPN session | **BLOCKED** | Activation-gated |
| B53 - static/on-device manifest checks | **PASS** | `allowBackup=false`, backup/extraction rules correctly packaged and referenced, only `MainActivity` exported, no debug-only classes in the release manifest, `run-as` correctly refused ("package not debuggable") - all confirmed on the actual installed artifact |
| B53 - live-session checks (VPN permission flow, foreground service, live redaction, Shadowsocks stdout/stderr draining) | **BLOCKED** | Activation-gated |
| Pre-activation network access | **PASS** | Small, explainable traffic volume (manifest fetch + this sprint's own test attempts) - no suspicious background activity |
| Full-session secret scan (logcat) | **PASS** | Zero credential/key/token values found across the complete captured log for the app process |
| Support - UI reachable, button visible, correct position | **BLOCKED (reachability)** | Confirmed by reading `AppRoot.kt`'s navigation logic: Settings/Diagnostics/Contact Support are only reachable from Home, which requires activation |
| Support - include/exclude diagnostics choice | **implemented, compiled, unit-suite-clean; NOT physically exercised** | New this pass (commit `77d2e0b`) - a small `AlertDialog` on the existing Contact Support button; not a second screen. Cannot be tapped physically until Home is reachable. |
| Support - mailto/fallback | **NOT TESTED** | Activation-gated |
| Support - redaction | **test-suite evidence only** | `DiagnosticSanitizerTest`/`SupportBundleTest` green; no fresh physical bundle generated this sprint |

## Known Limitations

1. **Release build has no manual transport selector.** Confirmed in
   source: the entire Diagnostics dialog (containing every "Force
   <transport>" control, `DiagnosticsDialog.kt`) is gated by
   `isDebugBuild = BuildConfig.DEBUG`, `false` for any release build. A
   fresh install's `GatewaySelectionMode` defaults to `MANUAL_MANAGED`,
   whose fixed preference order always tries AmneziaWG first.
   Consequence: on a healthy network, the signed release APK will only
   ever demonstrate AWG; Xray is reachable only via a genuine AWG failure
   (`AwgXrayFailoverPolicy`), and Shadowsocks is not part of any
   release-path failure cascade at all (confirmed NOT IMPLEMENTED BY
   CURRENT ARCHITECTURE, not merely untested - `AwgXrayFailoverPolicy` is
   the only failover-policy class in the codebase and never mentions
   Shadowsocks). **This is a deliberate, pre-existing architecture
   choice, not a defect introduced this sprint** - documented here as a
   QA/testability limitation for Beta, not fixed (adding a production
   transport-override control is a separate product decision, explicitly
   out of this sprint's scope).
   **Mechanism precision (checked Day 5, corrects an earlier
   simplification)**: `DiagnosticsDialog.kt` itself lives in the `main`
   source set, not `src/debug/` - unlike `XrayDiagnosticsActivity`, which
   IS truly absent from the release APK via source-set isolation. The
   transport-selector's exclusion from release is instead a
   compile-time-constant runtime gate: `BuildConfig.DEBUG` is a `public
   static final boolean` baked in at compile time (`false` for release,
   confirmed - `isMinifyEnabled = false` so R8 does not additionally
   strip this dead branch, but it is provably unreachable regardless,
   since the constant can't change at runtime). Functionally identical
   result (no user can reach it in release), different mechanism - worth
   recording precisely rather than implying source-set isolation applies
   uniformly to every debug-only surface in this app.
2. **Network-unavailable activation shows a generic "Invalid activation"
   message**, identical to an actually-invalid credential. Cosmetic
   (P2/P3) - not fixed this sprint per the timebox rule (only real
   release blockers, security issues, build/signing problems, and
   crashes were in scope for a same-day fix).
3. **`support@aknova.pp.ua` is an unverified placeholder.**
   `SUPPORT CONTACT CONFIGURATION: OWNER VERIFICATION REQUIRED` - the
   repository owner must confirm a real, monitored mailbox exists at
   this address (or supply a different one) before Beta ships. Not
   claimed as operational anywhere in this report or in the app itself.
4. **Screen-rotation testing is blocked by this specific OEM's shell
   restrictions** (`WRITE_SETTINGS` denied to `com.android.shell` on this
   ColorOS build), not by the app. Not re-attempted via a different
   mechanism this sprint (out of timebox).

## External Dependencies

```text
PRODUCTION CREDENTIAL REQUIRED

Host:      Frankfurt production gateway
Command:   sudo -u pocvpn-api python3 gateway/tools/activation_tokens.py \
             --store /var/lib/pocvpn-activation/activations.json \
             issue --max-devices 1 --expires-in-days 1
Required access: operator SSH key (confirmed absent in this environment -
           ssh ubuntu@152.70.43.1 -> Permission denied (publickey))
Purpose:   unblocks activation, AWG/Xray/Shadowsocks physical validation,
           recovery/failover testing, B53 live-session checks, and
           Support flow physical testing - i.e., everything in the
           "BLOCKED" rows of the table above
Expected lifetime: 1 day
Security:  must not be committed, documented, printed into any test
           artifact, screenshotted, or included in a diagnostic bundle;
           revoke via `activation_tokens.py revoke <activation_id>` after
           testing if desired
```

## Final Release Gate

```text
BLOCKED — EXTERNAL ACCESS (production activation credential)
```

Everything within this environment's reach has been done: signed build,
correct version/packaging, B53 static/on-device hardening confirmed on
the real artifact, minimal Support flow implemented and unit-tested
(including the Day 4 include/exclude-diagnostics fix), debug QA build
reproducible for the day the credential arrives. No P0 or P1 code defect
remains open. The single remaining step to a real PASS/FAIL verdict on
AWG/Xray/Shadowsocks/recovery/B53-live/Support-live is the production
credential above.
