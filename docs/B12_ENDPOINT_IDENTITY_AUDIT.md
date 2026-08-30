# B12 — Endpoint-specific provisioning/identity audit

Audit only — no runtime code in this PR implements multi-endpoint
provisioning. This documents what the CURRENT (single-gateway) activation
model assumes, and what a real second gateway would require, so a future
slice doesn't have to re-derive it.

## Today's identity layering (single gateway, real code)

| Layer | What it is | Where it lives | Scope today |
|---|---|---|---|
| **Device identity** | The client's AmneziaWG/X25519 keypair (`ClientKeyRepository`) | `AndroidKeyStore`-backed, on-device | One per device install, never per-endpoint |
| **Endpoint identity** | Which gateway a request targets | Implicit — `GatewayConfiguration`'s single hardcoded host/port | Exactly one gateway exists, so this axis is currently degenerate (always "frankfurt") |
| **Transport credential** | The VLESS UUID `xray_provisioning.py` issues, or the AWG peer entry `provision-peer.sh` creates | `gateway/api/xray_provisioning.py`'s identity store (keyed by activation credential digest); AWG peer keyed by the device's public key | One VLESS UUID and one AWG peer PER DEVICE, reused for both REALITY and TLS transports (see `xray_activation.py`'s own "SAME identity is reused for either transport" docs) |

**The task's own invariant — `device identity != endpoint identity !=
transport credential` — already holds structurally today**, even though
"endpoint identity" has never had more than one real value to distinguish
itself from: the device's AWG public key IS the device identity, and it is
reused unchanged as the AWG peer's own key at whichever gateway provisions
it; the VLESS UUID is a SEPARATE, server-issued value, itself independent
of both the device's AWG key and of any notion of "which gateway."

## What a real second gateway needs (not built in this slice)

`POST /v1/activate`/`POST /v1/xray-profile` are written against **one**
activation store and **one** Xray identity store, both scoped to the single
process/VPS they run on. Adding a genuinely independent second gateway
(different VPS, different provider/ASN — the Gateway Pool goal) means one of
two shapes, not designed further here:

**(a) Per-gateway independent credentials (simpler, more isolated).**
Each gateway runs its own `gateway/api` process with its own
`activation_store_path`/`xray_store_path`. The SAME device public key is
submitted to `POST /v1/activate` on EACH gateway independently — each
gateway issues its OWN VLESS UUID and its OWN AWG peer entry for that same
device. This requires:
- the client to hold N sets of transport credentials (already modeled per-
  transport via `XrayProfileRepository`/`XrayTlsProfileRepository` — would
  need to become per-`(endpointId, transport)` rather than per-transport
  only, e.g. keyed the same way `PathHistoryStore` already keys local
  history), and
- N independent activation-credential redemptions (the enrollment/activation
  token model would need to either issue one credential valid at every pool
  member, or issue one per gateway — a product/ops decision, not made here).

**(b) A federated/shared identity system (more work, more coupling).**
One activation authority issues a credential that's valid across every pool
member, with per-gateway state synchronized or independently re-derived from
a shared source of truth. This avoids N independent redemptions but requires
either a real synchronization mechanism between gateways or a central
control-plane database — meaningfully larger scope, explicitly NOT started
here.

**Recommendation for the next slice that actually adds a second live
gateway:** start with (a). It requires zero changes to the proven
single-gateway `gateway/api` code (each instance stays exactly as
independent and simple as today's one), and the client-side credential
storage generalization it needs (`(endpointId, transport) -> credential`)
is a natural, additive extension of the SAME keying discipline B11/B12
already use for `PathHistoryStore` and `EndpointReachability`.

## What this audit does NOT change

No code in this PR modifies `gateway/api/activations.py`,
`gateway/api/xray_provisioning.py`, `gateway/api/xray_activation.py`,
`identity/ClientKeyRepository*`, `identity/XrayProfileRepository*`, or
`identity/XrayTlsProfileRepository*` — confirmed via `git diff` showing zero
changes to those files in this slice. Multi-gateway credential mapping is
PLANNED design guidance for a future slice, not implemented here.
