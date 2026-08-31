# Nova VPN (VPNrus) - project instructions

`docs/ROADMAP.md` is the authoritative source of truth for what is actually implemented vs. planned vs. foundation-only. `PROJECT_ARCHITECTURE.md` is a compact, stable-invariants summary maintained alongside it - see the token-efficiency workflow below for which one to read when.

## Token-efficiency workflow (read this before starting any slice)

Do not reread the whole repository or the whole ROADMAP for every slice. Follow this instead:

1. **ROADMAP scope** - use `docs/ROADMAP.md` as source of truth, but read only the section(s) relevant to the current slice (e.g. just the Gateway Pool row for a gateway-selection change), not the whole file.
2. **Architecture summary** - `PROJECT_ARCHITECTURE.md` holds only stable architectural invariants and current runtime boundaries. Read it instead of re-deriving architecture from scratch. Update it only when stable architecture actually changes (a new boundary, a new gateway, a genuinely cross-cutting refactor) - not for every slice, and never for ROADMAP status-only edits. Keep it short and factual.
3. **Implementation scope** - inspect only: the files directly affected by the slice, their immediate runtime call-path dependencies, and the tests relevant to those paths. Don't open unrelated modules "just in case."
4. **Review scope** - inspect the PR diff plus only the code needed to trace the runtime paths that diff actually touches.
5. **Full-repository rereads** - only when the change is genuinely cross-cutting (touches the pipeline boundaries in `PROJECT_ARCHITECTURE.md` themselves) or `PROJECT_ARCHITECTURE.md` is stale/missing the area in question. Justify it in one sentence when you do it.
6. **Reuse session context** - if a file was already read earlier in the current session and hasn't changed, don't reread it; work from what's already in context.
7. **No repeated architecture-agent smoke tests** - this environment cannot dispatch `.claude/agents/vpn-architecture.md` as a real isolated subagent (no Agent/Task tool exposed here). Do not re-attempt to verify that mechanically on every turn - apply the agent's rules directly in-session (see below) and say so once, not per-slice.
8. **One consolidated review pass** - collect all findings from a review pass into ONE list; do not run a serial one-issue-at-a-time micro-audit loop (find one thing, fix, re-review, find another, repeat).
9. **`PROJECT_ARCHITECTURE.md` hygiene** - short, factual, invariants and current boundaries only - no historical narrative (that belongs in ROADMAP). Update it in the same commit as whatever change made it stale.

## Mandatory: the `vpn-architecture` review discipline

This repository has a dedicated architecture-review persona at `.claude/agents/vpn-architecture.md` (name: `vpn-architecture`). It is a **read-only reviewer** - it never edits code and never merges. Its rules must be applied at three points for any change that touches: runtime architecture, provisioning, persistence, gateway selection, transport selection, Smart Connect, failover, reachability, networking, VPN lifecycle, Xray/AWG configuration, control-plane, or production-infrastructure assumptions. Per rule 7 above, if no Agent/Task tool is available in the current session, apply its rules directly in-session (reading `PROJECT_ARCHITECTURE.md` + the relevant ROADMAP section + the diff, per rules 1-4 above) rather than attempting to dispatch it as a subagent - state plainly that this is what happened, once.

**A. Before implementation** - identify affected architectural boundaries (check against `PROJECT_ARCHITECTURE.md` first), invariants that must remain true, likely regression surfaces, and tests that must be added.

**B. After implementation, before claiming completion** - review again against the COMPLETE branch/PR diff (not just the latest commit) to trace all affected runtime flows end-to-end.

**C. Before declaring `MERGE READY`** - mandatory for architecture-affecting PRs. Only say `MERGE READY` when: implementation tests pass, the build passes, no architectural blocker was found, and ROADMAP/runtime truth is consistent. If blockers are found, collect ONE consolidated list, fix them in ONE pass, and re-audit ONCE (rule 8 above).

Skip A-C for changes that are purely cosmetic/copy/non-architectural (e.g. a string resource, a comment fix with no behavior change, a test-only refactor with no production-code change).

## Merge rule

Never merge without the repository owner's explicit approval given directly (e.g. "merge", "schvaluji merge", "sluč to"). Without it: implement, run the full review (per the rule above), report `MERGE READY` or the consolidated blocker list, and stop.

## Repository facts worth knowing up front

- Android app under `android/app/src/main/java/net/pocvpn/client/`.
- `debug`-only code (e.g. `XrayDiagnosticsActivity`) lives in `android/app/src/debug/` and must never leak into the release build/manifest.
- See `PROJECT_ARCHITECTURE.md` for the current gateway/runtime-boundary summary; see `docs/ROADMAP.md`'s Gateway Pool row for full authoritative detail when a slice actually needs it.
- Never allocate/purchase paid cloud resources (including Elastic IPs) or make destructive production infrastructure changes without explicit owner approval.
