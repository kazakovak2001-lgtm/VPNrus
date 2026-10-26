---
name: fieldtest-report
description: Field-test report skill for Nova VPN (VPNrus). Run explicitly via /fieldtest-report to evaluate existing on-device field-test JSON/log outputs, distinguishing confirmed results from estimates and missing evidence. Read-only: never modifies the source logs.
disable-model-invocation: true
---

# Field Test Report

Explicit-only skill for Nova VPN (VPNrus). Invoke it with
`/field-test-report <path-or-evidence>` to evaluate existing on-device
field-test JSON/log outputs.

Because `disable-model-invocation: true`, this skill runs **only** when you
explicitly request it. It is never triggered automatically by the model while
you are doing other work.

## Scope

- **In scope:** reading and interpreting existing field-test JSON/log artifacts
  produced by the diagnostics/fieldtest pipeline.
- **Out of scope:** modifying, deleting, regenerating, or moving any source
  log or artifact. This skill is strictly read-only with respect to the
  evidence it reviews. It also never creates new files.

## Evidence classification

Classify every finding into exactly one of these categories:

| Category          | Meaning                                                                       |
| ----------------- | ----------------------------------------------------------------------------- |
| `CONFIRMED`       | Directly observed in the source logs; backed by a concrete record.            |
| `ESTIMATE`        | Reasoned inference from available evidence, but not directly observed.       |
| `MISSING`         | No supporting evidence in the supplied artifacts; measurement status unknown. |
| `CONTRADICTED`    | Source records conflict with each other or with a known baseline.            |

Distinguish `ESTIMATE` from `CONFIRMED` explicitly. Never present an estimate
as if it were a measured result, and never invent data that is not in the
logs.

## Procedure

1. Locate the field-test JSON/log artifacts for the run in question.
2. Read them directly; do not infer results from filenames or comments alone.
3. Classify each finding as `CONFIRMED`, `ESTIMATE`, `MISSING`, or
   `CONTRADICTED`.
4. Note any gaps where the run did not cover a path that the report implies
   it covered.
5. Flag anything that looks fabricated, hardcoded, or inconsistent with the
   physical test discipline in `PROJECT_ARCHITECTURE.md`.

## Safety

- Never print, log, quote, or reproduce secrets: private keys, VLESS UUIDs,
  API credentials, production tokens, signing private keys, tunnel IPs, or
  device identities. Public server keys and public IPs are not secrets, but
  do not dump them gratuitously - cite file:line instead of pasting values.
- Never modify the source logs or artifacts under any circumstances.

## Output format

```
FIELD TEST REPORT

Source: <path or artifact set>

Each finding carries exactly one label, given by the section it is listed in:

Confirmed (CONFIRMED):
- ...

Estimates (ESTIMATE):
- ...

Missing evidence (MISSING):
- ...

Contradictions (CONTRADICTED):
- ...

Notes:
...
```