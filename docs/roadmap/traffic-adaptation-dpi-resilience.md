# Traffic Adaptation / DPI Resilience

<!-- Moved verbatim from docs/ROADMAP.md (2026-10-27): the full table row. -->

## Capability

Traffic Adaptation / DPI Resilience

## Status

PLANNED

## Notes

No code. Purpose: let Nova choose a safe, transport-specific traffic adaptation profile when real evidence suggests DPI/protocol interference, rather than only choosing WHICH transport/endpoint to use (that decision stays `ReachabilityEngine`/`PathScorer`'s job - B11, FOUNDATION). Future decision key: `networkFingerprint x endpointId x transportKind x adaptationProfile -> observed connection outcome` - the SAME `networkFingerprint x endpointId x transportKind` key `FilePathHistoryStore` (B11, Connection Memory row above) already uses today, extended with one more dimension rather than a new, parallel memory model. Safe future adaptation candidates: `NONE` (always the default), TLS handshake/write fragmentation, bounded transport padding, safe transport-level segmentation. Architecture rules for whenever this is actually built: adaptation is always transport-specific (never a global packet mangler shared across transports), `NONE` is always the default and every other profile requires real reachability/failure evidence before ever being selected, outcomes integrate with local Connection/Path Memory and a future `PathScorer` extension (never a separate, disconnected scoring path), retry/strategy rotation must be bounded (no unbounded profile-cycling loop), and no third-party service is ever impersonated (same architecture principle 4 discipline as Hard Whitelist Detection). This does NOT solve a destination-IP hard whitelist (`POSSIBLE_HARD_WHITELIST` - see `RestrictionClassifier`) - DPI/protocol-signature adaptation and a fixed-destination allowlist are different failure modes with different remediations, and must not be conflated. Explicitly NOT adopted from zapret2 or any similar tool, now or later: no root/NFQUEUE dependency, no fake packet injection, no bad-checksum tricks, no TTL manipulation, no TCP sequence/ACK deception, no arbitrary OS-level packet reordering, and zapret2 itself is never embedded or copied into Nova.
