# B-WL6 - Whitelist / restricted-network lab

A framework for recording **measured** behavior of Nova transports on real
restricted networks. It contains **no results yet**. Every cell below is `?`
until a real, dated measurement exists. Nothing in this directory is a claim
about any operator.

## Rules

1. One record = one concrete context: **operator + region + date + network
   type**. A result from one operator, region or day never stands in for
   another.
2. Classifications use the same `POSSIBLE_*` vocabulary as the Android
   `RestrictionClass` (B-WL1). No `CONFIRMED`, `DPI` or `TSPU` claims.
3. `HIGH` confidence requires a reproduced result (`repetitions >= 2`).
4. Privacy: no IPs, hostnames with tokens, UUIDs, keys, URLs or personal data.
   `lab_record.py` rejects records that contain them.
5. `bytesReceivedBeforeStall` is recorded only as an observation. It is never
   used as a detection threshold (see B-WL1: early drop is detected from
   behavior, never from a byte count).
6. Use owned/authorized infrastructure only (ROADMAP B48/B51).

## Record format

See `lab_record.py` for the closed schema and `records/EXAMPLE.template.json`
for a placeholder. Validate before committing:

```
python3 research/whitelist-lab/lab_record.py research/whitelist-lab/records/*.json
python3 -m unittest discover -s research/whitelist-lab/tests
```

Recommended procedure per context: a domestic reference probe
(`DOMESTIC_REFERENCE`, tells whitelist apart from full shutdown), then UDP
(AWG, Hysteria2), then TCP (REALITY RAW, REALITY XHTTP), then an ingress path
if one exists. Record each transport separately, at least twice.

## Matrix (placeholder - no measurements yet)

| Network (operator / region / date / type) | UDP | TCP | REALITY | XHTTP | Front/ingress | Result |
|---|---|---|---|---|---|---|
| Operator A / ? / ? / ? | ? | ? | ? | ? | ? | ? |
| Operator B / ? / ? / ? | ? | ? | ? | ? | ? | ? |
| Operator C / ? / ? / ? | ? | ? | ? | ? | ? | ? |
| Operator D / ? / ? / ? | ? | ? | ? | ? | ? | ? |

Operators are named in records only once someone has actually measured them.
