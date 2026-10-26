---
name: pr-check
description: Manual pre-merge review skill for Nova VPN (VPNrus) pull requests. Run explicitly via /pr-check on a branch or PR to verify the complete diff, relevant tests, architecture invariants, and roadmap evidence. Produces PASS / FAIL / INCONCLUSIVE / NOT TESTED verdicts. Makes no code changes, commits, pushes, merges, or roadmap edits.
---

# PR Check

Manual pre-merge review for Nova VPN (VPNrus) pull requests.

Run this skill explicitly with `/pr-check <branch-or-PR>` to audit a change
before it merges. It inspects the complete diff, the tests that cover it, the
architectural invariants it touches, and the evidence it leaves against
`docs/ROADMAP.md`.

## Scope

- **In scope:** the complete diff of the branch/PR, its relevant tests, the
  architectural boundaries it touches, and its consistency with
  `docs/ROADMAP.md`.
- **Out of scope:** making code changes, editing files, committing, pushing,
  merging, or modifying `docs/ROADMAP.md`. This skill is read-only end to end.

## Verdicts

Use exactly one of these four verdicts per checked dimension:

| Verdict        | Meaning                                                                 |
| -------------- | ----------------------------------------------------------------------- |
| `PASS`         | Verified against the diff; evidence is present and consistent.         |
| `FAIL`         | A real defect, invariant violation, or missing evidence was found.      |
| `INCONCLUSIVE` | Cannot be determined from the available evidence; needs more info.      |
| `NOT TESTED`   | No test or evidence exists for this dimension; it was never checked.    |

## Procedure

1. **Complete diff.** Inspect the entire branch/PR diff, not just the latest
   commit. Use `git diff main...HEAD` (or the equivalent PR base).
2. **Relevant tests.** Identify the tests that cover the changed runtime
   paths. Confirm they still prove what they claim to prove after the change.
   If a test exists but does not exercise the changed path, mark it
   `NOT TESTED` for that path rather than `PASS`.
3. **Architecture.** Trace the affected runtime flows end-to-end against the
   boundaries in `PROJECT_ARCHITECTURE.md`. Flag any change that silently moves
   `PathScorer` into a live decision path, adds automatic multi-gateway
   selection, or weakens the debug/release boundary.
4. **Roadmap evidence.** Check the relevant `docs/ROADMAP.md` section(s) for
   stale claims, contradictory wording, capability-status inflation
   (marking FOUNDATION as IMPLEMENTED merely because code exists), or claims
   of production readiness backed only by debug/operator provisioning.
5. **Merge rule.** Never merge. Report the verdicts; merging always requires
   the repository owner's explicit approval given directly to the main agent.

## Output format

```
PR CHECK

Target: <branch or PR>

Diff:
PASS | FAIL | INCONCLUSIVE | NOT TESTED
...

Tests:
PASS | FAIL | INCONCLUSIVE | NOT TESTED
...

Architecture:
PASS | FAIL | INCONCLUSIVE | NOT TESTED
...

Roadmap:
PASS | FAIL | INCONCLUSIVE | NOT TESTED
...

Overall: PASS | FAIL | INCONCLUSIVE

Blockers:
1. ...
2. ...

Notes:
...
```

If every dimension is `PASS`, the overall verdict is `PASS`. Any `FAIL` makes
the overall verdict `FAIL`. `INCONCLUSIVE` or `NOT TESTED` dimensions are
reported but do not by themselves fail the check - they must be called out so
the owner can decide.