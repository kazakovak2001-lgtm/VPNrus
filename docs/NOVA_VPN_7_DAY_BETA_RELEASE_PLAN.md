# Nova VPN — 7-Day Beta Release Readiness Audit

> **Historical snapshot (written 2026-09-20/22, preserved 2026-10-09 from an uncommitted worktree).** Facts here describe that date; current status lives in `docs/ROADMAP.md`.

**Audit only. No implementation, no fix, no refactor, no commit, no deployment
performed by this document.** Prepared against `kazakovak2001-lgtm/VPNrus`,
`main` @ `75cb4b249da24dc5d13197b0cc016147d79e0a81` (2026-09-20), cross-checked
against 20 open PRs / unmerged branches and the repository's own
`docs/ROADMAP.md` / `PROJECT_ARCHITECTURE.md`.

**Evidence discipline**: every status below is backed by one of (in
descending priority, per this audit's own instructions): physical-device
evidence > test evidence > production/deployment evidence > source code >
merged commit > documentation > plan. Where documentation and repository
state disagree, the disagreement is called out explicitly — **this audit
found two severe cases of this** (section 3).

---

## 1. Executive summary

Nova VPN's actual *product* state is materially better than
`docs/ROADMAP.md` currently describes, and materially more fragmented
across branches than `PROJECT_ARCHITECTURE.md` (last updated 2026-09-01,
three weeks stale) suggests. Three independently working, physically
validated transports already exist and are merged to `main`: **AmneziaWG**,
**Xray/VLESS REALITY**, and **Shadowsocks-2022** (the last of these is
undocumented in both roadmap docs despite a completed, physically-validated,
production-manifest-deployed implementation — see section 3). Automatic
gateway failover, adaptive split-tunnel routing, and a local diagnostics/
support-bundle foundation are also merged and real.

Against that, there are three structural problems that threaten a 7-day
Beta timeline more than any single missing feature: **(a) there is no
release-signing mechanism in the repository at all** — the release build
type has no signing config, meaning no build produced today can currently
be distributed as a real Beta APK/AAB; **(b) 20 open PRs / branches**
(research, field-test, and one production-adjacent Hysteria2 track)
represent real, sometimes-substantial work that has not landed on `main`,
so "the product" is currently split across `main` plus several
long-lived branches, not one coherent tree; **(c) the version is still
`0.1-poc` / `versionCode 1`** — a cosmetic but real signal that release
packaging has never actually been exercised end to end.

Hysteria2 (B46-4P) is **not** a Beta blocker on the merits: it is a fourth,
additive transport behind an explicit, unresolved legal gate
(`docs/B46_4P_HYSTERIA2_LEGAL_REVIEW_PACKAGE.md`), and Beta does not need a
fourth transport when three independently working ones already exist. It
should proceed as a parallel, legal-gated workstream, not on the Beta
critical path.

The Report→Support-Center product ask is real but should be **scoped down
hard for Beta**: a backend support endpoint, ticket history, and chat do
not exist today (only a local, sanitized, share-sheet-export diagnostic
bundle does — see section 10). Building a full support system in 7 days
alongside everything else is a scope risk; a minimal "attach the existing
diagnostic bundle to a support email/contact flow" is the safe Beta-sized
version.

## 2. Current product state (verified, not assumed)

| Area | State | Evidence tier |
|---|---|---|
| AmneziaWG transport | Real, physically validated on 2 gateways (Frankfurt/Oracle, Stockholm/AWS), real handshake, real traffic, DNS validated, IPv6 fail-closed | Physical device (OPPO CPH2173) |
| Xray/VLESS REALITY transport | Real, physically validated, AWG→Xray automatic failover proven end to end on a real VPS | Physical device |
| Shadowsocks-2022 transport | Real, physically validated including Wi-Fi/cellular handover (B45B-5), signed production manifest v4 deployed for Frankfurt (B45B-4P) | Physical device + production manifest |
| Automatic gateway failover / Auto ranking | Real, health-aware, physically validated (real fault injection, real failover, real restore) | Physical device |
| Adaptive split-tunnel routing | Real for AWG + Xray/TLS, physically validated with real traffic and OS-level route-table proof | Physical device |
| Local diagnostics / support bundle (current "Report") | Real, sanitized, share-sheet export only — no backend, no persistence across app restart, no chat, no ticket history | Test evidence (1148+ tests) + code |
| Hysteria2 (all of B46) | Technical server-only build path verified this week; production wiring exists only on an unmerged branch; legal gate open | Documentation + prototype build (this week) |
| Release signing | **Does not exist** — no `signingConfigs` block for `release`, only `debug`/`fieldTest` (which explicitly reuses debug signing) | Source code (`android/app/build.gradle.kts`) |
| App version | `versionCode = 1`, `versionName = "0.1-poc"` | Source code |
| Security/device-exposure hardening (B53) | Audit complete, 1734/1735 unit tests pass, release APK/DEX inspected clean; **physical-device validation still pending**; PR explicitly marked "Do not merge: draft security milestone PR" | Documentation + test evidence, NOT physical |
| Restricted-network / Russia bootstrap activation (B36) | Real client-side bootstrap-tunnel design responding to an actual Russia field-test finding (neither gateway's control-plane nor Stockholm's transport ports were directly reachable); unmerged | Documentation, partial test evidence |
| CDN-fronted ingress / multi-provider pool | All PLANNED, no code | Documentation (roadmap explicit "No code") |

## 3. Documentation-vs-repository discrepancies found (must not be trusted blindly)

1. **`docs/ROADMAP.md` line 243**: `Shadowsocks fallback | PLANNED | No code.`
   **Reality**: Shadowsocks-2022 is fully implemented, wired into transport
   selection, hardened, and physically validated including a Wi-Fi/cellular
   handover test that PASSED (`B45B-5`), with a signed production manifest
   (`_v4`) already deployed for Frankfurt (`B45B-4P`). This is not a
   rounding error — it is a fully shipped transport the roadmap says has
   "no code." **This audit relies on git history and source code for
   Shadowsocks status, not the roadmap.**
2. **`PROJECT_ARCHITECTURE.md`**: zero mentions of Shadowsocks anywhere in
   2672 lines, and its own footer says "Last updated: 2026-09-01" — the
   document predates roughly three weeks and dozens of merged/unmerged
   PRs (B20 through B56+) that exist in this repository today.
3. **`docs/ROADMAP.md`** never mentions Hysteria2 at all (any of B46-1
   through B46-4P) — an entire transport initiative, including a legal
   review package, exists with zero roadmap-level record.

**Implication for this audit and for the team**: neither roadmap document
should be treated as current-state truth right now. Both need a
post-Beta-decision pass to resync with `main` (tracked as a POST-BETA
housekeeping item, section 12 — doing it now would burn Beta-week time on
documentation instead of shipping).

## 4. Branch / PR fragmentation (a structural finding, not a feature gap)

`main` is at PR #98 (merged 2026-09-20). **20 PRs are currently open**,
all in DRAFT or OPEN state, none merged since. They break down roughly
as:

- **Production-adjacent, not yet merged**: #111 (B46-4A Hysteria2
  production wiring), #107 (B53 security hardening — audit complete,
  physical validation pending), #108 (B54 restricted-network field
  validation framework), #60 (B36 bootstrap pre-activation tunnel), #62
  (B37 AWG 3.1 field-test upgrade), #58/#61 (Russia field-test
  enrollment/APK), #49 (a real deploy-script bug fix), #35 (B21 QUIC
  foundation), #22 (TLS/TCP physical-verification docs).
- **Research-only, explicitly not production-track**: #99/#109/#110 (B46
  Hysteria2 native-coexistence/process-isolation research), #100/#101
  (B47 traffic-fingerprint audit), #102 (B48 active-probing resistance),
  #103 (B49 chaos simulation), #104 (B50 ASN survivability), #105 (B51
  non-datacenter endpoints), #106 (B52 offline/outage mode).

**This matters for the 7-day plan directly**: "the product" that ships in
7 days is whatever gets merged to `main` in that window, plus whatever
`main` already has. The research branches (7 of the 20) are explicitly
out of scope by their own naming and should stay unmerged for Beta. The
production-adjacent ones need an explicit per-branch merge/no-merge
decision as part of Day 1 (section 16).

## 5. Required for Beta (🔴)

Each item states why it blocks a usable Beta, not just why it would be
nice to have.

1. **🔴 Release signing mechanism.** No `release` signing config exists.
   Without this, no Beta build can be distributed by any channel (Play
   Internal Testing, Firebase App Distribution, direct APK) as a properly
   signed release artifact. **Time: 2–4h** (generate a keystore, wire a
   `signingConfigs.release` block reading from environment/CI secrets —
   never committed — per this repo's own "no committed keystore"
   convention already established for debug).
2. **🔴 Version bump for Beta.** `0.1-poc` / `versionCode 1` is not a Beta
   identity. **Time: <2h.**
3. **🔴 A merge decision + actual merge for the transports Beta needs.**
   AWG, Xray/REALITY, and Shadowsocks are real and physically validated,
   but confirm they are all actually reachable together on whatever
   branch/tag becomes "Beta" — the Shadowsocks production-manifest work
   (B45B-4P/5) is on `main` already (confirmed above), so this is mostly
   a verification step, not new work. **Time: <2h to verify, already
   largely done.**
4. **🔴 One coherent Beta build/branch decision.** With 20 open branches,
   someone must decide explicitly which of the production-adjacent ones
   (B53 security, B36 bootstrap, B37 AWG 3.1) merge before Beta and which
   wait. Doing this implicitly (whoever merges last wins) is a real risk
   of shipping an inconsistent tree. **Time: 2–4h of triage + owner
   decision, not engineering time per se.**
5. **🔴 Physical-device validation of B53's security hardening**, if B53
   is merged for Beta (recommended — see section 6). The PR's own
   decision gate is explicit: `AUDIT COMPLETE / PHYSICAL DEVICE
   VALIDATION PENDING`. Shipping a Beta without this validation on the
   one real test device (OPPO CPH2173) means shipping unverified
   device-exposure hardening claims. **Time: 4–8h** (the audit + fixes
   are already done; this is validation only).
6. **🔴 A minimal, real path from the existing Report button to actual
   human support contact.** Not a full support center (see section 10)
   — but shipping Beta with literally no way for a user to reach a human
   when something breaks is not acceptable for a Beta cohort. **Time:
   4–8h** for the minimal safe version (see section 10's recommendation).
7. **🔴 A real end-to-end Beta smoke test on the physical device**,
   covering install → activate → connect (each of the 3 real transports)
   → disconnect/reconnect → app-restart recovery → export diagnostics,
   run against whatever build is actually tagged as Beta. Individual
   pieces have all been physically validated in isolation, at different
   times, on different branches — **no single pass has validated all of
   them together on one build**, which is what will actually ship.
   **Time: 4–8h, but genuinely CRITICAL TIME RISK if it surfaces an
   integration bug between branches merged on different days.**

## 6. Should-have (🟠) — desirable before Beta, not an absolute blocker

- **B53 security hardening merge.** Strongly recommended (audit is
  already complete and clean), but if time runs out, Beta *can* ship
  without it — it hardens exposure surfaces that are not new to Beta
  (they exist in the current `main` too); shipping without it is a risk
  acceptance, not a hard blocker, given the underlying attack surface
  isn't Beta-specific.
- **B36 restricted-network bootstrap activation.** Real and addresses a
  genuine field finding, but only matters for users on networks that
  block direct gateway access (the Russia field-test scenario
  specifically). If the Beta cohort is not primarily in such networks,
  this is safely deferrable.
- **ROADMAP.md / PROJECT_ARCHITECTURE.md resync.** Important for team
  velocity after Beta, actively harmful to spend Beta-week time on now
  (see section 3's own note).
- **B37 AWG 3.1 field-test upgrade.** Field-test-scoped (its own build
  type, isolated source set, never affects the normal release build per
  this repo's own architecture doc) — does not gate the normal Beta
  release build by construction.

## 7. Post-Beta (⚪) — explicitly deferred, with reasoning

| Feature | Why not now | Post-Beta priority |
|---|---|---|
| QUIC transport/fallback | PLANNED, zero code; 3 working transports already cover the Beta need | Medium |
| CDN-fronted ingress / multi-provider pool | PLANNED, zero code; large infrastructure project | Medium |
| Full Support Center (chat, ticket history, backend) | Real product value, but a multi-day backend+client project on its own; a minimal contact path covers Beta's actual need | High (first thing after Beta) |
| Hysteria2 production deployment | Legal-gated (see section 15); 3 transports already suffice | Conditional on legal decision |
| B47–B52 research (traffic fingerprint, active-probing resistance, chaos simulation, ASN survivability, non-datacenter endpoints, offline mode) | Explicitly research-track by their own naming/scope; none block a usable Beta | Varies, re-triage post-Beta |
| Multi-hop, shared exit pools, RAM-only gateways, DAITA-like traffic defense, post-quantum hybrid, rotating exit IP, Tor-over-VPN, custom DNS/DoH/DoT | All PLANNED in roadmap with zero code; advanced hardening beyond a usable Beta | Low–Medium, re-triage post-Beta |
| ROADMAP.md/PROJECT_ARCHITECTURE.md full resync | Documentation debt, not a product blocker (see section 3) | High, do immediately after Beta ships |

## 8. Blockers (⛔)

| Blocker | Why | Who/what resolves it | Parallel work possible? |
|---|---|---|---|
| No release signing config | No repo mechanism exists; needs a real keystore + CI secret handling decision | Repository owner decides keystore custody (self-managed vs. Play App Signing enrollment) | Yes — everything else can proceed while this is set up |
| Hysteria2 legal decision | GPL exposure question is open (`docs/B46_4P_HYSTERIA2_LEGAL_REVIEW_PACKAGE.md`) | Legal counsel | Yes — fully parallel, does not block Beta (Hysteria2 excluded from Beta scope) |
| B53 physical-device validation | The one real test device needs a dedicated pass | Whoever holds the OPPO CPH2173 device | Partially — device time must be scheduled against the other physical smoke test in item 7/section 5 |
| Stockholm's non-durable AWS public IP | Documented in `PROJECT_ARCHITECTURE.md`'s own gateway table — AWS auto-assigned, not reserved; an IP change would silently break every device already provisioned against it | Repository owner (allocate an Elastic IP — **note: this repo's own CLAUDE.md forbids allocating paid cloud resources without explicit owner approval**, so this is a decision this audit cannot make or act on) | N/A — pure decision, zero engineering time once approved |

## 9. Critical path for the next 7 days

Not a 50-item TODO list — the specific things that can actually cause a
missed Beta:

1. **Release signing mechanism** (section 5.1) — nothing ships without it.
2. **Branch/merge triage decision** (section 5.4) — without an explicit
   decision, engineering time gets spent on branches that won't ship,
   or a build ships that nobody actually validated as a whole.
3. **One full physical smoke test on the actual Beta build** (section
   5.7) — the single highest-risk unknown, because every physical
   validation so far happened on a different branch/day/build.
4. **B53 security-hardening merge + its physical validation** (sections
   5.5/6) — recommended, real risk if skipped.
5. **Minimal support contact path** (section 5.6/10) — a hard floor, not
   the full Support Center ask.
6. **Version/signing packaging correctness** (section 5.2) — small but
   real; a `0.1-poc` Beta undermines confidence in everything else on
   this list.
7. **Stockholm IP durability decision** (section 8) — an owner decision,
   not engineering work, but if deferred past Beta ship, provisioned
   Stockholm devices are at risk of silent breakage; needs at least an
   explicit "accepted risk" note if not resolved this week.

## 10. Support Center — current state and Beta scope

```text
Current Report implementation:  A local, in-app "Export diagnostics"/
                                 "Clear diagnostics" pair in Settings'
                                 Diagnostics section (B29). Shows a
                                 simple human-readable last-result
                                 sentence; export hands a sanitized JSON
                                 bundle to Android's native share-sheet
                                 (ACTION_SEND) — the user picks the
                                 destination (email, messaging app,
                                 etc.) themselves.
Existing diagnostics:           DiagnosticSession/DiagnosticEvent model,
                                 19 event categories, 17 failure-reason
                                 categories, automatically captured
                                 during real connect attempts. Bounded
                                 ring buffer, MAX 8 sessions retained,
                                 in-memory only (does not survive app
                                 process death).
Backend support endpoint:       DOES NOT EXIST. Explicitly excluded by
                                 B29's own design ("no backend
                                 telemetry/upload endpoint... export is
                                 local share-sheet only").
Persistence:                    In-memory only, per-app-instance, max 8
                                 sessions, oldest-first eviction. No
                                 disk-backed store.
Ticket history:                 DOES NOT EXIST.
Chat:                           DOES NOT EXIST.
Attachment:                     Works today, but only via the OS
                                 share-sheet to whatever app the user
                                 picks — not an in-app "attach to
                                 ticket" flow.
Redaction:                      Real and well-tested: structural (the
                                 recorder API cannot accept raw strings
                                 at all — reflection-enforced) plus
                                 pattern-based (rejects UUIDs, Base64
                                 key-shaped blobs, bearer tokens, PEM
                                 blocks, secret= query params, IP
                                 addresses). Proven with a dedicated
                                 security test using real sentinel
                                 secrets.
Fallback:                       The share-sheet itself IS the fallback
                                 — no dedicated "contact us" path exists
                                 separately from it today.
Android UI:                     Settings → Diagnostics section only, two
                                 buttons. No dedicated "Support" surface
                                 exists in the product yet — this is the
                                 literal "simple Report button" the
                                 product ask wants transformed.
```

### Classification

- **Required for Beta**: keep the existing diagnostics capture/redaction/
  export exactly as-is (it is real, tested, and safe) and add ONE
  minimal addition: a visible "Contact Support" entry point next to (or
  replacing) the current Report button that pre-fills the share-sheet
  target toward a real, monitored support inbox/address (e.g.,
  `mailto:` intent with the sanitized bundle attached) rather than
  leaving the destination fully open-ended. This reuses 100% of existing
  plumbing (per the product ask's own instruction: "využití existujícího
  report/diagnostic plumbing tam, kde to dává smysl... NE jako samostatný
  oddělený entry point vedle Reportu") and is estimated at **4–8h**.
- **Can be simplified for Beta**: rename "Report" to "Support" in the UI,
  keep it as one entry point (not two), and treat the diagnostic-bundle
  attachment as the "attachment" half of the product ask — this alone
  satisfies "diagnostic attachment works or has safe fallback" from the
  Beta exit criteria (section 11) without building a ticket system.
- **Post-Beta**: backend support endpoint, ticket history, chat, any
  server-side persistence of support conversations. These are the real
  "Support system" the product ask ultimately wants, but building them
  this week competes directly with the release-signing/branch-triage/
  physical-smoke-test critical path (section 9) for the same limited
  engineering time and the same one physical test device.

## 11. Beta exit criteria

Measurable, derived from what this repository can actually prove today
plus the minimum new work from section 5.

### Installation
- [ ] Release build produces a properly signed APK/AAB (not debug-signed).
- [ ] APK installs cleanly on a real device (OPPO CPH2173 or equivalent
      Android 14/SDK 34/arm64-v8a device).
- [ ] App launches to Home without crash.

### Activation
- [ ] A fresh device can complete `/v1/activate` against at least one
      real production gateway and reach Home with a provisioned
      identity — **already proven repeatedly on `main`**, re-verify on
      the actual Beta build.

### Connection
- [ ] AWG connects, real handshake, real traffic, correct exit IP —
      **already proven**, re-verify on the Beta build.
- [ ] Xray/REALITY connects (manual or via failover) — **already
      proven**, re-verify on the Beta build.
- [ ] Shadowsocks-2022 connects — **already proven** (including Wi-Fi/
      cellular handover), re-verify on the Beta build.
- [ ] Disconnect cleanly returns the device to normal (unprotected)
      networking — **already proven** for AWG/REALITY; re-verify.

### Recovery
- [ ] Automatic AWG↔Xray failover on a real induced fault — **already
      proven**, re-verify on the Beta build.
- [ ] App restart preserves activation/identity (does not force
      re-activation) — verify explicitly; not directly evidenced above.
- [ ] Network change (Wi-Fi↔cellular) does not silently drop protection
      — **already proven** for Shadowsocks handover and for the
      `AndroidReconnectManager` fix (B30B); re-verify on the Beta build.

### Security
- [ ] No production secrets in the release APK (B53's own DEX/manifest
      inspection already passed this on its own branch — must be
      re-confirmed on whatever tree actually ships).
- [ ] No debug-only surfaces (`XrayDiagnosticsActivity`, field-test
      activities) present in the release manifest — architecturally
      guaranteed by source-set isolation (`PROJECT_ARCHITECTURE.md`'s own
      "Production vs debug boundary" invariant); confirm on the actual
      release artifact, not just by code review.
- [ ] Credentials/diagnostics redacted — **already proven** by
      `DiagnosticSanitizerTest`/`SupportBundleTest`'s dedicated security
      tests.

### Support
- [ ] User has a visible way to report an issue and reach a human (see
      section 10's minimal recommendation).
- [ ] Diagnostic attachment works (already real) or has a documented
      safe fallback if the share-sheet target has no app installed.
- [ ] No ticket/history requirement for Beta (explicitly deferred).

### Backend
- [ ] Production `/v1/activate`, `/v1/xray-profile` reachable — **already
      proven live** on both gateways.
- [ ] Auth/provisioning works, revoke/rotate works — **already proven**
      for Xray/Shadowsocks in prior physical passes.

### Server
- [ ] AWG, Xray/REALITY, Shadowsocks all reachable and correct on both
      gateways — **already proven**.
- [ ] Firewall/TLS correct — **already proven** for the transports in
      scope.
- [ ] systemd services survive a restart — not independently re-verified
      by this audit this pass; recommend a quick operator check
      (`systemctl is-enabled`/a controlled restart) rather than assuming
      from documentation.

### Release
- [ ] Version bumped from `0.1-poc`/`versionCode 1` to a real Beta
      identifier.
- [ ] Build is signed with a real (even if Beta-only) release key.
- [ ] Artifact hash recorded for the shipped build.
- [ ] Release notes/known-limitations doc exists (should explicitly name
      Hysteria2 as "not included, pending legal review" and Support as
      "diagnostics + contact only, full ticket system post-Beta").

## 12. Test matrix

| Area | Automated | Integration | Physical | Production | Status |
|---|---:|---:|---:|---:|---|
| Activation | Yes (Android + gateway unit/integration tests) | Yes (`gateway/api/tests/`, 27 test files) | Yes, repeatedly, both gateways | Yes, live on both gateways | 🟢 |
| AWG | Yes | Yes | Yes, real handshake/traffic/failover, multiple passes | Yes, live | 🟢 |
| Xray/REALITY | Yes | Yes | Yes, including AWG→Xray failover | Yes, live | 🟢 |
| Shadowsocks | Yes (B45B unit suites) | Yes | Yes, incl. Wi-Fi/cellular handover (B45B-5, PASSED) | Yes, signed manifest v4 deployed (Frankfurt) | 🟢 |
| Hysteria2 (server-only prototype) | Partial (module-graph/build verification only) | No | Loopback-only, not a real client handshake | No (legal-gated) | 🟡 (deliberately not a Beta blocker) |
| Failover (AWG↔Xray, gateway-level) | Yes | Yes | Yes, real fault injection | N/A | 🟢 |
| Split tunnel (Adaptive routing) | Yes (14+ dedicated test cases) | Yes | Yes, real route-table proof (AWG + Xray) | N/A | 🟢 |
| Reconnect / network-change | Yes | Yes | Yes (B30B fix physically re-validated) | N/A | 🟢 |
| Support (diagnostics/export) | Yes (`DiagnosticSanitizerTest`, `SupportBundleTest`, etc.) | Partial | No dedicated field-test with a real user/support workflow | No backend exists | 🟡 |
| Security (B53 hardening) | Yes (1734/1735) | Yes (release APK/DEX inspection) | **No — pending**, PR's own explicit gate | N/A | 🟡 |
| Release packaging/signing | No | No | No | No — **mechanism doesn't exist** | 🔴 |

## 13. Physical-device gaps (explicit)

Everything below has automated and/or documented evidence, but has
**not** been physically re-verified on the specific build that will
actually ship as Beta:

- The combined effect of merging B53 (security hardening) + whatever
  else lands this week, together, on one real device pass.
- B53's own device-exposure hardening claims (explicitly "physical
  device validation pending" in the PR itself).
- App-restart identity/session recovery, end to end, on the Beta build
  specifically (individual pieces proven, not this exact combination).
- Any release-signed (not debug-signed) build has **never** been
  installed on a physical device, because no such build has ever existed
  in this repository (section 5.1/8).

## 14. Security/release gaps

- **No release signing** (section 5.1/8) — the single largest concrete
  gap found by this audit.
- **B53's hardening is unmerged** — real risk if Beta ships from `main`
  without it (existing exposure surfaces, not new ones, but still
  unaddressed).
- **`versionCode 1` / `0.1-poc`** — packaging has never been exercised
  for a real release identity.
- No secrets were found staged for commit anywhere touched by this
  audit (out of scope to re-scan the entire repo this pass — B53's own
  audit already did a secret-pattern scan and passed; this audit relies
  on that rather than repeating it, per this project's own
  no-repeated-audit convention).

## 15. Hysteria2 status

```text
Technical:  SERVER-ONLY BUILD TECHNICALLY VERIFIED (this week, see
            docs/B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md)
Legal:      LEGAL DECISION STILL REQUIRED (see
            docs/B46_4P_HYSTERIA2_LEGAL_REVIEW_PACKAGE.md)
Production deployment: BLOCKED BY LEGAL DECISION (hostname, port, TLS,
            manifest binding all explicitly undecided/not created per
            docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md)
```

**Is Hysteria2 required for Beta?** No, derived directly from the actual
product state, not opinion: Beta already has three independently working,
physically validated transports (AWG, Xray/REALITY, Shadowsocks-2022)
that together satisfy "connect, use the internet, disconnect/reconnect."
Nothing in `docs/ROADMAP.md`'s own P0/P1 prioritization or in the product
requirements supplied to this audit names Hysteria2 as a precondition for
a usable Beta — it is documented everywhere (including B46-4P's own
docs) as an *additional* transport for restricted-network resilience, not
a replacement for the three that already work. **Hysteria2 proceeds as a
parallel, legal-gated workstream** (Track E in section 16), fully
decoupled from the Beta ship date.

## 16. 7-day execution plan

Parallel tracks — do not serialize what doesn't need to be sequential.

```text
Track A — Android (release engineering)
Track B — Backend/server verification
Track C — Security (B53)
Track D — Support (minimal Beta scope)
Track E — Hysteria2 legal (fully parallel, non-blocking)
Track F — Branch triage / integration (owner + engineering, Day 1 only)
```

### Day 1
- **Track F**: Owner decision on which of the 20 open PRs merge before
  Beta (recommend: B53 yes, B36 conditional on target market, B37 no
  — field-test-isolated, research branches no). Produces the actual
  "Beta tree" everything else builds against.
- **Track A**: Start release-signing setup (generate/obtain keystore,
  wire `signingConfigs.release`, confirm CI/local secret handling
  convention matches this repo's existing "no committed keystore"
  pattern).
- **Track B**: Confirm live production state of both gateways (AWG,
  Xray/REALITY, Shadowsocks endpoints) with a read-only health check —
  no changes, per this repo's own infrastructure-safety rule.

### Day 2
- **Track A**: Finish release signing; bump version to a real Beta
  identifier; produce the first real signed build.
- **Track C**: Merge B53 into the Day-1-decided Beta tree (already
  passes 1734/1735 tests + release APK/DEX inspection on its own
  branch — this is an integration step, not new engineering).
- **Track D**: Implement the minimal "Contact Support" addition
  (section 10) — reuses existing `SupportBundle`/share-sheet plumbing,
  adds one pre-filled contact target.
- **Track E**: Hand the legal package to counsel (already prepared);
  no engineering time consumed further this week unless legal responds.

### Day 3
- **Track A**: Install the first real signed Beta build on the physical
  device; smoke-test install → launch → activate.
- **Track C**: Schedule/run B53's pending physical-device validation
  pass on this same build.
- **Track B**: Re-verify `/v1/activate`, `/v1/xray-profile`, Shadowsocks
  provisioning against the actual Beta build (not a dev build).

### Day 4
- **Track A**: Full physical smoke test — all 3 transports connect,
  disconnect, reconnect, exit-IP correctness, on the real Beta build.
- **Track D**: Verify the Contact Support flow end to end on-device
  (bundle attaches correctly, redaction holds).
- **Track C**: Close out any findings from Day 3's physical validation.

### Day 5
- **Track A**: Recovery testing — app restart, network change (Wi-Fi↔
  cellular), failed-transport failover, all on the Beta build
  specifically (not assembled from separate prior passes).
- **Track B**: Confirm systemd service restart survival on both gateways
  (read-only operator check, per infrastructure-safety rule — no
  destructive restart without owner sign-off if these are live
  production services already serving real traffic).

### Day 6
- **Buffer day** — this plan intentionally reserves one full day for
  whatever the Day 1–5 physical passes surface (the single largest risk
  per section 17). If nothing surfaces: finalize release notes/known-
  limitations doc, record the shipped build's artifact hash.

### Day 7
- Final Beta gate review against section 11's exit criteria.
- Ship, or make an explicit, evidence-based "not yet" call — not a
  default slip.

## 17. Time-risk analysis

| Item | Estimate | Risk |
|---|---|---|
| Release signing setup | 2–4h | Low — well-understood, standard Android task |
| Version bump | <2h | None |
| Branch triage decision | 2–4h (mostly owner time) | Low, but blocks everything else if delayed |
| B53 merge + integration | 2–4h | Low — already passes its own full suite |
| B53 physical-device validation | 4–8h | **CRITICAL TIME RISK** if it finds a real device-exposure issue requiring rework |
| Minimal Support contact addition | 4–8h | Low — reuses 100% existing plumbing |
| Full physical smoke test (all transports, one build) | 4–8h | **CRITICAL TIME RISK** — first time these branches' combined effect is tested together; most likely place to find an integration surprise |
| Recovery testing (restart/network-change/failover) on Beta build | 4–8h | Medium — individual pieces already proven, combination not yet |
| systemd/production server re-verification | <2h (read-only checks) | Low, if gateways are already healthy (no evidence of instability found) |
| Stockholm IP durability decision | Owner decision, ~0 engineering time once approved | Medium — silent breakage risk if left unresolved, but does not block Day-7 ship by itself |

**The two CRITICAL TIME RISK items (B53 physical validation, full
physical smoke test) both require the same physical device** — this is
the actual scheduling constraint for the week, more than raw engineering
hours.

## 18. Final Beta gate

```text
BETA FEASIBLE WITHIN 7 DAYS
```

Conditioned explicitly on:

1. The branch-triage decision (Track F, Day 1) actually happening on Day
   1, not drifting.
2. Release signing being treated as a Day-1/2 priority, not an
   afterthought (it is the one true hard blocker with zero existing
   mitigation).
3. The physical device (OPPO CPH2173) being available for the Day 3–5
   window this plan assumes — if it is not, this becomes the single
   most likely cause of a missed date, and the honest fallback is
   `BETA NOT FEASIBLE WITHIN 7 DAYS — no physical-device validation
   window available`.
4. Hysteria2 and the full Support Center staying explicitly out of
   scope, as this audit recommends — pulling either back in would
   directly compete with the critical path above for the same limited
   time and the same one physical device.

This conclusion rests on evidence, not optimism: three transports are
already real and physically proven, the security audit is already done
(only its physical confirmation is outstanding), and the remaining
blockers (signing, version, branch triage, one combined smoke test) are
bounded, well-understood engineering tasks with no open technical
unknowns — the only unknowns are scheduling (device availability) and
what a combined physical pass might surface for the first time.
