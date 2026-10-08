# Nova VPN — Beta Cut (Day 1 execution)

> **Historical snapshot (written 2026-09-20/22, preserved 2026-10-09 from an uncommitted worktree).** Facts here describe that date; current status lives in `docs/ROADMAP.md`.

Produced against `kazakovak2001-lgtm/VPNrus`. Follows
`docs/NOVA_VPN_7_DAY_BETA_RELEASE_PLAN.md`'s own Day 1 track. This document
answers one question before any merge happens: **which of the 20 open
PRs actually need to land for Beta, and which do not.**

## 1. Beta Base

```text
Branch: main
HEAD:   75cb4b249da24dc5d13197b0cc016147d79e0a81
Merge pull request #98 from validation/b46-2p-hysteria-android-physical
(2026-09-20)
```

This is the last point at which `main` is known-clean per the prior
7-day audit — AWG, Xray/REALITY, Shadowsocks-2022, automatic failover,
adaptive routing, and the B29 diagnostics foundation are all present and
merged here.

## 2. All 20 open PRs — full triage

| PR | Branch | HEAD | Purpose | Current state | Tests | Dependencies | Changes | Beta relevance | Risk | Recommended action |
|---|---|---|---|---|---|---|---|---|---|---|
| #111 | `feature/b46-4a-hysteria2-production-integration` | `53fa0999` | Hysteria2 production wiring/provisioning (server config, auth backend route, systemd unit, Android diagnostics hook) | Draft, mergeable | Not independently re-verified this pass (prior B46-4P passes report full gateway suite green) | None on other Beta PRs | 46 files, +6304/-18 | None — Hysteria2 is legal-gated, not a Beta transport | Low technical risk, but 46-file footprint is large for a feature not shipping in Beta | **POST-BETA** |
| #110 | `research/b46-3c-hysteria-process-isolated-dataplane` | `7680501f` | Hysteria2 process-isolation research | Draft, mergeable | Research-scope, not re-verified | None | 21 files, +3623/-1 | None | Low (isolated, research-labeled) | **POST-BETA** |
| #109 | `research/b46-3b-hysteria-process-isolation` | `1c8140b9` | Hysteria2 tun2socks bridge research | Draft, mergeable | Research-scope, not re-verified | None | 20 files, +3009/-1 | None | Low | **POST-BETA** |
| #108 | `feature/b54-restricted-network-field-validation` | `7fb80966` | Evidence-taxonomy/validator framework for future restricted-network field tests | Draft, mergeable | Documented in-PR corrections, not re-verified this pass | None | 5 files, +447/-1 | None — a research/evidence tool, not a user-facing capability | Low | **POST-BETA** |
| #107 | `security/b53-android-device-exposure-hardening` | `5de9abec` | Android component/storage/Keystore/backup/logging/diagnostics exposure hardening | Draft, mergeable | 1734/1735 unit tests pass; release APK/DEX/manifest inspected clean; PR's own gate: "AUDIT COMPLETE / PHYSICAL DEVICE VALIDATION PENDING" | None on other Beta PRs (touches shared Android surfaces — see section 4) | 8 files, +389/-21 | **Directly required** — closes real device-exposure gaps in the exact release build Beta ships | Low code risk, **medium process risk** (physical validation still outstanding, PR explicitly says "Do not merge: draft security milestone PR") | **MERGE FOR BETA** (after section 4's own check, and after its physical validation — see Day 2 entry criteria) |
| #106 | `research/b52-offline-outage-mode` | `02a84606` | Offline/outage mode research | Draft, mergeable | Research-scope | None | 2 files, +375/-1 | None | Low | **POST-BETA** |
| #105 | `research/b51-authorized-non-datacenter-endpoints` | `38d3b014` | Non-datacenter endpoint research | Draft, mergeable | Research-scope | None | 2 files, +222/-1 | None | Low | **POST-BETA** |
| #104 | `feature/b50-provider-asn-survivability-score` | `1a5c15fb` | Provider/ASN survivability scoring research | Draft, mergeable | Research-scope | None | 4 files, +477/-1 | None | Low | **POST-BETA** |
| #103 | `feature/b49-chaos-simulation-framework` | `326f5efa` | Deterministic censorship chaos-simulation framework | Draft, mergeable | Research-scope | None | 6 files, +366/-1 | None | Low | **POST-BETA** |
| #102 | `research/b48-active-probing-resistance-audit` | `4b4861cd` | Active-probing resistance audit | Draft, mergeable | Research-scope | None | 2 files, +435/-1 | None | Low | **POST-BETA** |
| #101 | `research/b47-1p-android-capture-baseline` | `88af782a` | Android packet-capture baseline (stacked on #100) | Draft, mergeable, **base = PR #100, not `main`** | Research-scope | **Depends on #100** | 3 files, +472/-1 | None | Low, but stacked (must merge #100 first if ever merged) | **POST-BETA** |
| #100 | `research/b47-traffic-fingerprint-audit` | `4e5ad508` | Traffic fingerprint audit | Draft, mergeable | Research-scope | None (is itself #101's dependency) | 2 files, +412/-1 | None | Low | **POST-BETA** |
| #99 | `research/b46-3a-hysteria-native-coexistence` | `2af88aed` | Hysteria2 native tun2socks coexistence research | Draft, mergeable | Research-scope | None | 23 files, +2260/-1 | None | Low | **POST-BETA** |
| #62 | `field-test/b37-awg31-upgrade` | `198c6170` | AWG field-test stack upgrade to real AmneziaWG 3.1 (Russia diagnostics) | Open, mergeable | Field-test-scoped, own build type | None (isolated `fieldTest` source set/build type per `PROJECT_ARCHITECTURE.md`'s own "Production vs debug boundary" invariant) | 32 files, +5566/-8 | None — never touches the normal `debug`/`release` build by construction | Low (architecturally isolated), but **out of scope for this audit per explicit instruction not to touch B37** | **POST-BETA / PARALLEL FIELD TEST** (not evaluated further — B37 is untouched by this pass, per instruction) |
| #61 | `field-test/russia-diagnostic-apk` | `4d36da2c` | Disposable Russia field-test build (`FIELD_TEST_ONLY`) | Open, mergeable | Field-test-scoped | Related to #62's build-type work | 15 files, +1798/-0 | None — separate disposable APK, not the Beta release build | Low (isolated) | **POST-BETA / PARALLEL FIELD TEST** |
| #60 | `feature/b36-bootstrap-pre-activation-tunnel` | `48a4a6ac` | Client-side AmneziaWG bootstrap tunnel so an unactivated device can reach `/v1/activate` from a network that blocks direct gateway access (real Russia field-test finding) | Open, **CONFLICTING** (needs rebase against current `main`) | Not re-verified this pass | Touches `MainViewModel.activateDevice()` (shared, high-traffic file) | 30 files, +3336/-8 | Conditional — only matters if the Beta cohort includes users on networks that block direct gateway access; the 3 core transports already work for a normal-network Beta cohort | **Medium** — merge conflict must be resolved, and it touches the shared activation path used by every transport | **HOLD** — owner decision on target market required; if Beta cohort is not primarily restricted-network, **POST-BETA** |
| #58 | `feature/russia-field-test-zero-touch-enrollment` | `de59e82d` | Bounded, per-device zero-touch enrollment for Russia field test | Open, **CONFLICTING** | Field-test-scoped | Likely overlaps #60/#61 | 35 files, +2834/-35 | None for a general Beta cohort | Medium (conflicting, large diff) | **POST-BETA / PARALLEL FIELD TEST** |
| #49 | `fix/b31-deploy-script-preserve-host-env` | `e23a5556` | Fixes `deploy-backend-update.sh` overwriting a live host's own hand-customized `config/*.env` on deploy (found live during the real B31 Germany deployment) | Open, mergeable | Not independently re-verified this pass; PR describes the exact live incident it fixes | None — isolated to one deploy script | 1 file, +49/-1 | **Real production-safety value**: reduces risk of an accidental config overwrite during any backend deploy this Beta week (e.g. if B53 or other changes require a gateway redeploy) | **Very low** — single file, narrowly scoped, describes a real bug already found in production | **MERGE FOR BETA** |
| #35 | `feature/b21-quic-transport` | `dc522840` | QUIC transport/fallback foundation | Open, **CONFLICTING** | Foundation-scope, roadmap marks QUIC PLANNED/no-code elsewhere | Large, touches many shared files | 48 files, +2725/-45 | None — QUIC is not needed; 3 transports already suffice | High (conflicting, 48 files, foundation-only) | **POST-BETA** |
| #22 | `docs/b8o2-ops-tls-tcp-physical-verification` | `f857f677` | Documents that TLS/TCP fallback was deployed to production (`152.70.43.1`, port 2083) and physically verified; updates roadmap status FOUNDATION→IMPLEMENTED | Open, **CONFLICTING** | Docs+ops only, describes a real completed physical verification | None — docs-only | 5 files, +110/-1 | Informational only — the underlying TLS/TCP fallback is **already live in production** regardless of whether this doc PR merges; merging it just makes `main`'s docs accurate | Very low (docs-only) once rebased | **MERGE IF NEEDED** (safe, low-value-to-fix-now; does not block Beta functionality either way — the feature it documents is already live) |

**Total: 2 MERGE FOR BETA, 1 MERGE IF NEEDED, 1 HOLD, 15 POST-BETA (7 of
which are explicitly research-labeled by their own branch names).** This
is the minimal cut, not "merge everything that's ready."

## 3. Minimal Beta cut — reconstruction

```text
main @ 75cb4b2
  +
#107 (B53 security hardening) — after physical validation
  +
#49  (deploy-script host-env safety fix)
  +
minimal Support addition (new, this week — not yet a PR, see section 5)
  +
release signing configuration (this pass, see section 6)
  +
version bump (this pass, see section 7)
  =
NOVA VPN BETA
```

| Added | Why required | User-facing capability | What breaks without it | Dependencies | Risk |
|---|---|---|---|---|---|
| #107 B53 | Closes real Android device-exposure gaps (exported components, backup/D2D rules, Keystore, logging) in the exact build Beta ships | Nothing new user-visible — a security floor, not a feature | Beta ships with known, already-identified exposure gaps left open | None on other Beta PRs (see section 4 for the specific overlap check) | Low code risk; physical validation still outstanding |
| #49 deploy-script fix | Prevents a real, already-observed production incident class (overwriting a live host's hand-customized env file) from recurring during any deploy this week | None directly — an operational safety net | A backend redeploy this week (e.g. for any gateway-side change) could silently corrupt a live host's Xray config exactly as it already did once on Germany | None | Very low |
| Minimal Support addition | Beta's own exit criteria require a way to reach a human when something breaks | "Contact Support" reachable from the existing Report/Diagnostics surface | Users with a broken connection have no path to help beyond the existing bare diagnostic export | Builds on existing `SupportBundle`/share-sheet plumbing (B29, already on `main`) | Low — additive UI only |
| Release signing | No Beta APK/AAB can be distributed as a properly signed artifact without it | None visible to the end user, but a hard precondition for any distribution channel | Beta cannot ship at all | None | Low — scaffolding only, fails safe to today's unsigned behavior if unconfigured (see section 6) |
| Version bump | `0.1-poc`/`versionCode 1` is not a Beta identity | Visible in diagnostics/about screens | Cosmetic only, but undermines confidence and blocks future Play Store versionCode monotonicity | Confirmed not used for any activation/backend/manifest compatibility check (see section 7) | None |

Everything else (all 15 POST-BETA rows in section 2) is explicitly
**not** part of this cut. None of them provide a capability Beta's own
exit criteria (per `docs/NOVA_VPN_7_DAY_BETA_RELEASE_PLAN.md` section 11)
actually require.

## 4. B53 — dedicated audit

```text
PR:            #107
Branch:        security/b53-android-device-exposure-hardening
HEAD:          5de9abec61782990407a5400de4b87f22a74754b
Base:          main (mergeable, no conflicts against current main tip)
Changed files: 8 (+389/-21)
```

**Scope, per its own summary**: audits Android component/storage/
Keystore/backup/D2D/Intent/VPN-service/subprocess/logging/diagnostics/
sharing/UI/release-package exposure; protects the exported debug Xray
profile importer with a shell-held `android.permission.DUMP`; adds
explicit deny-all legacy backup and API 31+ cloud/device-transfer
extraction rules; drains production Shadowsocks stdout/stderr without
forwarding third-party output to logcat.

**Tests (as reported by the PR itself, not independently re-run this
pass — see section 9 for why)**: 3/3 focused B53 regression tests;
1,734/1,735 debug JVM suite (the one known failure is the pre-existing,
unrelated `EffectiveConfigDiffTest` baseline failure this audit's prior
pass already documented); release APK assembly and lint passed; release
merged manifest and DEX inspected — confirmed absent: Nova debug classes
and B45A secret BuildConfig fields; staged-diff check, local-property/
build-input check, and secret-pattern scan all passed.

**Collision check against the rest of this Beta cut**: #107 touches 8
files, none of which overlap `android/app/build.gradle.kts` (this pass's
own edit target — see section 6), `android/app/keystore.properties*`
(new this pass), or `deploy-backend-update.sh` (#49's target). **No file-
level collision found** between #107 and the other two items in this
cut. (A byte-for-byte merge simulation was not run this pass — this is a
path-overlap check, not a guaranteed conflict-free merge; run an actual
merge/rebase before Day 2 to confirm.)

**Is it safe to merge?** Code-wise, yes — the PR's own evidence is
thorough and the file-overlap check above is clean. **Process-wise, not
yet**: the PR's own decision gate is explicit —
`DEVICE-EXPOSURE BASELINE HARDENED / AUDIT COMPLETE / PHYSICAL DEVICE
VALIDATION PENDING` — and its description header says "Do not merge:
draft security milestone PR." Per this pass's own instruction ("NEPROVÁDĚJ
ještě merge, pokud nejdřív není hotový Beta cut"), **no merge was
performed this pass**. The recommended sequence (section 8) is: merge
after this Beta Cut document is accepted, then run its physical-device
validation before Day 2 closes.

**What must be physically verified**: the PR's own gate names this
directly — device-exposure hardening claims (exported components,
backup/extraction denial, Keystore access boundaries, log redaction)
have automated/static evidence only; none of it has touched the one real
test device (OPPO CPH2173) yet.

## 5. Support Minimum — exact scope for Beta

Per the prior audit (`docs/NOVA_VPN_7_DAY_BETA_RELEASE_PLAN.md` section
10), the current state is unchanged since that pass — verified again
this pass by reading `PROJECT_ARCHITECTURE.md`'s B29 section directly
(not re-deriving from memory):

```text
Existing (main, B29):  DiagnosticSession/DiagnosticEvent capture,
                        structural + pattern-based redaction (tested with
                        real sentinel-secret proofs), local share-sheet
                        export (ACTION_SEND), Settings → Diagnostics
                        section with "Export diagnostics"/"Clear
                        diagnostics".
Missing for Beta:      A visible "Contact Support" entry point that
                        pre-fills a real, monitored destination (e.g. a
                        mailto: intent to a real support address) rather
                        than leaving the share-sheet target fully
                        open-ended.
Explicitly NOT Beta:   Backend ticket endpoint, ticket history, chat —
                        all POST-BETA, unchanged from the prior audit.
```

```text
Report
  ↓
Contact Support   (NEW — one entry point, reuses the existing button/
                    section, does not add a second parallel surface)
  ↓
optional diagnostic bundle   (EXISTING — SupportBundle.toJson(), already
                               sanitized/tested)
  ↓
safe external/contact fallback   (mailto: intent; if no mail app is
                                    configured, Android's own share-sheet
                                    already provides the fallback — no
                                    new fallback mechanism needs building)
```

This shape is deliberately compatible with a future full Support Center:
the "Contact Support" entry point can later be repointed at a real
backend ticket-creation call without changing the diagnostic-capture or
redaction layers at all — those stay exactly as they are.

**Not implemented this pass** (this is a Day 2 implementation item, per
this pass's own instruction to prioritize release signing/Beta cut
first): this pass only documents the exact minimal shape above; no
Kotlin/Compose change was made for it yet, matching the plan's own Day 2
placement in `docs/NOVA_VPN_7_DAY_BETA_RELEASE_PLAN.md`.

## 6. Release Signing — audit + this pass's change

### Audit (before this pass's change)

```text
Current applicationId:  net.pocvpn.client
Current versionName:    0.1-poc
Current versionCode:    1
Build system:           Gradle Kotlin DSL (android/app/build.gradle.kts),
                        Gradle 8.10 wrapper
Signing config:         NONE for `release`. Only `debug` (implicit
                        Android default debug keystore) and `fieldTest`
                        (explicitly reuses `signingConfigs.getByName
                        ("debug")`, by the repo's own comment: "No
                        dedicated release-signing mechanism exists in
                        this repository").
Keystore references:    None committed anywhere (confirmed by search:
                        zero *.jks/*.keystore files tracked, `.gitignore`
                        already excludes *.jks/*.keystore except
                        debug.keystore).
Release build type:     `isMinifyEnabled = false`,
                        `MANIFEST_URLS` hardcoded to production origins
                        - no signingConfig assigned at all before this
                        pass (an `assembleRelease` produced an UNSIGNED
                        artifact).
Debug/release diffs:    Both fetch the same production manifest origins
                        (by design, B20 - "does not add a distinct
                        staging manifest source"); release has
                        minification off; fieldTest is release-adjacent
                        but isolated (own source set, own applicationId
                        suffix `.fieldtest`).
CI signing:             DOES NOT EXIST - no .github/workflows directory
                        in this repository at all.
Local signing:          DOES NOT EXIST prior to this pass.
Secrets handling:       Established precedent exists (`gateway-
                        dev.properties`, gitignored, Properties()-loaded,
                        with an equivalent `.env.example`-style template
                        pattern already used elsewhere in this repo) -
                        reused directly for signing (see below), not
                        reinvented.
AAB support:            Standard AGP capability, unconfigured either way
                        (no bundle{} block customization) - not a gap
                        this pass needed to close.
APK support:            Standard, unaffected.
```

**Conclusion**: no partial signing infrastructure existed anywhere (no
CI workflow, no keystore.properties-style file, no signingConfigs block)
— confirmed by a repo-wide search for `signingConfig`/`keystore`/
`storePassword`/`keyAlias` across `.yml`/`.yaml`/`.kts`/`.gradle` files
and a `.github/workflows` existence check. Building the minimal
mechanism from scratch (below) was necessary, not a reinvention of
something partially there.

### This pass's change (minimal, safe, no regression)

Three files, following the repo's own existing `gateway-dev.properties`
convention exactly:

1. **`android/app/keystore.properties.example`** (new, committed,
   placeholder values only — `CHANGE_ME` for both passwords) — the
   template, with a `keytool -genkeypair` command documented for
   generating a real Beta keystore.
2. **`.gitignore`** — one new line, `android/app/keystore.properties`
   (the real, filled-in file — never committed; the `.jks`/`.keystore`
   file it points at was already covered by the existing `*.jks`/
   `*.keystore` patterns).
3. **`android/app/build.gradle.kts`** — reads `storeFile`/
   `storePassword`/`keyAlias`/`keyPassword` from that gitignored file,
   with an environment-variable fallback (`NOVA_RELEASE_STORE_FILE`/
   `_STORE_PASSWORD`/`_KEY_ALIAS`/`_KEY_PASSWORD`) for a future CI setup
   where secrets are injected as env vars rather than a checked-out
   file. **If neither source is present, `release` stays exactly as
   unsigned as it was before this change** — no build that previously
   worked is broken by this. No secret value is ever printed/logged by
   this code (only presence/absence is checked, via `.takeIf { it.isNotBlank() }`
   and a boolean `hasReleaseSigningConfig`).

**What still must happen (not done this pass, requires the repository
owner)**: actually generate a real Beta keystore (`keytool -genkeypair`,
command given in the template file) and place it + a filled-in
`keystore.properties` locally (never in git) — or supply the four
`NOVA_RELEASE_*` environment variables in whatever CI/build environment
produces the shipped artifact. **This pass created the mechanism, not
the actual secret material** — no keystore was generated, no password
was chosen or stored anywhere in this repository or this session.

## 7. Version

```text
Before: versionCode = 1,  versionName = "0.1-poc"
After:  versionCode = 2,  versionName = "0.1.0-beta1"
```

**Compatibility check performed before changing this** (not assumed, and
re-checked directly on `main` — an earlier pass of this same check,
run on a different branch, missed one usage found here): searched all
runtime usages of `BuildConfig.VERSION_NAME`/`BuildConfig.VERSION_CODE`
across `android/app/src/main`. Three call sites exist:

1. `MainViewModel.kt` (×2) — `appVersionName`/`appVersionCode`,
   `supportDiagnosticsAppVersionName`/`supportDiagnosticsAppVersionCode`
   — purely diagnostics reporting, no gating.
2. `MainViewModel.kt` → `CdnClientRuntimeCapabilities.pinnedXhttp(
   clientVersionCode = BuildConfig.VERSION_CODE.toLong())` →
   `CdnClientCapabilityPolicy.kt`'s `compatibilityWith(...)`, which
   checks `runtime.clientVersionCode < minimumClientVersionCode` (a
   value parsed from `CdnProviderProfileMetadata`, i.e. a signed CDN
   provider capability profile) and rejects with
   `CLIENT_VERSION_TOO_OLD` if the app's own versionCode is too low.
   **This IS a real version-gating mechanism** — but it gates the B27
   CDN-fronted-ingress feature specifically, which is `PLANNED`-tier
   with **no live production CDN provider profile deployed anywhere**
   (`docs/ROADMAP.md`'s own P1 section: "Real CDN-Fronted Ingress
   (Production, Provider-Agnostic) | PLANNED", "CDN Provider Capability
   Profile | PLANNED"). Since the comparison is `<` against a minimum,
   **increasing** `versionCode` (1→2) can only ever make this check
   pass more easily, never less — it is structurally safe to increase in
   isolation, and there is no live profile today for it to disagree
   with regardless.

**Neither usage is used for activation, backend compatibility gating
against any LIVE service, manifest schema versioning, or any update-path
decision.** The bump is therefore safe — it changes what a diagnostic
bundle reports, and can only improve (never worsen) the dormant CDN
capability-gate comparison.

`versionCode` was incremented (never decremented, satisfying future Play
Store monotonicity requirements) rather than left at `1`, even though
`1` was never actually shipped/distributed (no signed build has ever
existed) — starting the real numbering at `2` avoids ever having shipped
a "versionCode 1" artifact that later needs explaining.

## 8. Integration Order

```text
1. This Beta Cut document (this pass) — DONE
2. Release signing scaffolding + version bump (this pass, section 6/7) — DONE
3. Merge #49 (deploy-script fix) — isolated, zero-conflict, do first
4. Merge #107 (B53) onto the branch built in step 3 — confirmed no file
   overlap with step 3 or with this pass's own Gradle/gitignore change
5. Run B53's physical-device validation on that merged tree
6. Implement the minimal Support addition (section 5) on top
7. Produce the first real signed Beta build (requires the owner's real
   keystore per section 6's "what still must happen")
8. Full physical smoke test (all 3 transports, on this exact build)
```

Steps 3–4 can happen in either order relative to each other (no
dependency found), but both must land before step 5's physical pass, so
the device is validated against the ACTUAL tree Beta ships, not a
partial one.

## 9. Test Gates

| After | Must pass before proceeding |
|---|---|
| Merging #49 | Existing gateway deploy-script tests (if any exist for this script — not independently confirmed this pass; at minimum, a dry-run of the script's own logic against a sample host env file) |
| Merging #107 | Full debug JVM suite (expect 1734/1735 — the one pre-existing `EffectiveConfigDiffTest` failure, not a new one), release APK assembly + lint, DEX/manifest inspection for debug-class/secret leakage — **all already reported passing on #107's own branch; must be re-run on the actual merged Beta tree, not assumed to still hold** |
| Adding the minimal Support entry point | Any existing `SupportBundleTest`/`DiagnosticSanitizerTest` (must still pass unchanged — this addition should not touch the sanitizer/capture layers at all, only add a UI entry point) plus a new, small test for the entry point itself |
| Producing the first signed build | `assembleRelease` succeeds AND produces a signed artifact (verify via `apksigner verify` or equivalent — signature presence itself is the test, not just a successful Gradle exit code) |
| Before Day 2 closes | B53's physical-device validation actually run on the real OPPO CPH2173 device against the merged tree |

**This pass's own test attempt**: `./gradlew :app:tasks --console=plain`
was run to validate the Gradle Kotlin DSL change (section 6) parses
correctly. It failed — but with a **pre-existing, unrelated** error
(`java.lang.IllegalArgumentException: 26.0.1` inside the Kotlin
compiler's `JavaVersion.parse`, caused by this local machine's JDK
reporting a version string, `26.0.1`, that this project's pinned Kotlin/
AGP toolchain cannot parse). **Confirmed pre-existing, not caused by this
pass's change**: reproduced identically on the unmodified working tree
via `git stash` before re-testing. This is a local-environment toolchain
mismatch (this session's JDK is newer than this project's pinned
tooling expects), not a defect in this pass's edit — but it is a real
finding worth flagging for whoever runs the actual CI/release build this
week: **confirm the build machine's JDK version is compatible with this
project's pinned Gradle/Kotlin/AGP versions before Day 2**, since this
sandbox cannot itself validate a full `assembleRelease` this pass.

## 10. Day 2 Entry Criteria

Before Day 2 work begins, all of the following must be true:

- [ ] This Beta Cut document reviewed/accepted by the repository owner
      (particularly the #60/B36 HOLD decision, which depends on the
      target Beta market).
- [ ] #49 merged to the Beta integration branch.
- [ ] #107 (B53) merged to the same branch.
- [ ] B53's physical-device validation actually run and passed on the
      OPPO CPH2173 device, against the merged tree (not #107's branch in
      isolation).
- [ ] A real Beta keystore generated and either placed locally (as
      `android/app/keystore.properties` + its referenced `.jks`, both
      gitignored) or its four values loaded as `NOVA_RELEASE_*`
      environment variables in whatever machine will produce the shipped
      build.
- [ ] The build-machine JDK-version compatibility question (section 9)
      resolved — confirm `assembleRelease` actually succeeds end to end
      somewhere before treating this as done.
- [ ] Owner decision recorded on #60 (B36 bootstrap tunnel): HOLD for
      Beta, or promote to REQUIRED if the Beta cohort targets restricted
      networks.

---

## Files changed this pass

```text
.gitignore                              (+6 lines - keystore.properties ignore)
android/app/build.gradle.kts            (signing scaffolding + version bump)
android/app/keystore.properties.example (new - safe template, no secrets)
docs/NOVA_VPN_BETA_CUT.md               (this document)
```

**Worktree note (self-correction made mid-pass):** the signing/version
edits were first made in the wrong worktree — `C:/Users/akaza/Downloads/
VPN`, which is B37's own checkout (`field-test/b37-awg31-upgrade`) — and
were caught and reverted (`git checkout -- .gitignore
android/app/build.gradle.kts`, plus removing the added file) before
anything was committed, restoring that worktree to byte-identical state
with what it had at session start (re-verified via `git status --short`).
The real edits were then redone from a fresh, dedicated worktree, **`C:/
Users/akaza/Downloads/VPN-BETA-CUT`**, created from `main` (fast-forwarded
to `75cb4b2` — see section 1) specifically so Beta-cut work has its own
checkout, separate from both B37 and the B46-4A/Hysteria2 branch. **This
is now the Beta integration worktree** referenced throughout this
document; `docs/NOVA_VPN_BETA_CUT.md` itself is published from the
B46-4A worktree only because that is where this session's Hysteria2 docs
already live — the document's content applies to, and its file edits
happened in, `VPN-BETA-CUT`.

No PR was merged. No commit was created in any worktree. B37
(`C:/Users/akaza/Downloads/VPN`) was touched only by the mistaken edit
above, which was fully reverted before this pass ended — confirmed
byte-identical to its session-start state.

## Day 2-4 update

Superseded by, and full detail now in,
[`NOVA_VPN_BETA_ACCEPTANCE_REPORT.md`](NOVA_VPN_BETA_ACCEPTANCE_REPORT.md).
Summary of what changed since this document's Day 1 cut:

- #49 and #107 (B53) merged into `beta/0.1.0-beta1` exactly as planned
  above - zero file overlap, both clean.
- The JDK/toolchain blocker this document didn't yet know about was
  found and fixed on Day 2: this machine's system JDK (26.0.1) cannot
  compile this project's pinned Kotlin/AGP toolchain - Android Studio's
  bundled JBR (OpenJDK 21.0.8) is used for every build/test since.
- A real local Beta signing keystore was generated (gitignored, never
  committed) and the release build is genuinely signed - see the
  acceptance report for the current SHA256 (it has changed twice since
  Day 1 as real fixes landed; always check the acceptance report for the
  CURRENT value, never assume the first one issued still applies).
- The minimal Support flow (section 5 here) is fully implemented,
  including an explicit include/exclude-diagnostics choice added Day 4
  (the original Day 2 version always included the bundle with only
  removable text, which didn't satisfy the real requirement).
- Physical validation on the OPPO CPH2173 is real and ongoing, but
  **activation itself remains externally blocked** - no SSH access to
  the production gateway exists in this environment to mint a credential
  the real backend accepts. Everything reachable without one (app
  stability, B53 static/on-device checks, release integrity) has been
  physically verified; AWG/Xray/Shadowsocks/recovery/live-session
  Support testing all remain BLOCKED pending that credential.
