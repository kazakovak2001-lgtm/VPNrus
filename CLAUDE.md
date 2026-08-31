# Nova VPN (VPNrus) - project instructions

`docs/ROADMAP.md` is the authoritative source of truth for what is actually implemented vs. planned vs. foundation-only. Read it before making claims about capability status, and update it in the same branch/PR whenever a change alters what's actually true at runtime.

## Mandatory: the `vpn-architecture` subagent

This repository has a dedicated architecture-review subagent at `.claude/agents/vpn-architecture.md` (invoke it as `vpn-architecture`). It is a **read-only reviewer** - it never edits code and never merges. It must be invoked at three points for any change that touches: runtime architecture, provisioning, persistence, gateway selection, transport selection, Smart Connect, failover, reachability, networking, VPN lifecycle, Xray/AWG configuration, control-plane, or production-infrastructure assumptions.

**A. Before implementation** - invoke `vpn-architecture` to identify affected architectural boundaries, invariants that must remain true, likely regression surfaces, and tests that must be added.

**B. After implementation, before claiming completion** - invoke `vpn-architecture` again against the COMPLETE branch/PR diff (not just the latest commit) to trace all affected runtime flows end-to-end.

**C. Before declaring `MERGE READY`** - `vpn-architecture` approval is mandatory for architecture-affecting PRs. Only say `MERGE READY` when: implementation tests pass, the build passes, `vpn-architecture` found no architectural blocker, and ROADMAP/runtime truth is consistent. If it finds blockers, get ONE consolidated list, fix them in ONE pass, and re-audit ONCE - do not run a serial one-issue-at-a-time micro-audit loop.

Skip invoking it for changes that are purely cosmetic/copy/non-architectural (e.g. a string resource, a comment fix with no behavior change, a test-only refactor with no production-code change).

## Merge rule

Never merge without the repository owner's explicit approval given directly (e.g. "merge", "schvaluji merge", "sluč to"). Without it: implement, run the full review (including `vpn-architecture` per the rule above), report `MERGE READY` or the consolidated blocker list, and stop.

## Repository facts worth knowing up front

- Android app under `android/app/src/main/java/net/pocvpn/client/`.
- `debug`-only code (e.g. `XrayDiagnosticsActivity`) lives in `android/app/src/debug/` and must never leak into the release build/manifest.
- Two production gateways exist: Germany/Frankfurt (Oracle Cloud, fully self-service) and Stockholm/Sweden (AWS eu-north-1, data-plane physically validated, AWG client identity currently unprovisioned/disabled for release users, no self-service control-plane, auto-assigned non-durable public IP). See `docs/ROADMAP.md`'s Gateway Pool row for the current, authoritative detail - it changes as the project evolves, so re-read it rather than trusting a cached summary.
- Never allocate/purchase paid cloud resources (including Elastic IPs) or make destructive production infrastructure changes without explicit owner approval.
