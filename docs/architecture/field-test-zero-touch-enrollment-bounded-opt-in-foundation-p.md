# Field-test zero-touch enrollment (B67.4, Russia field test) - bounded, opt-in, FOUNDATION/PARTIAL until physically validated

<!-- Moved verbatim from PROJECT_ARCHITECTURE.md (2026-10-27). -->

A separate, additive enrollment PATH onto the SAME `/v1/activate`
entitlement model - never a second authorization system, and never a
replacement for B67.3's contract (see that section's own docs): the
credential this mints IS the same live legacy `ActivationCredential`
server-side authorization artifact, minted a different way. Server: `POST
/v1/field-enroll` (`gateway/api/field_enrollment.py`), disabled by default
(`AppConfig.field_enrollment_enabled`, requires an explicit env-var opt-in
plus `FIELD_ENROLLMENT_INDEX_PATH`/`FIELD_ENROLLMENT_WRAP_KEY_FILE` - see
below). Given only a fresh device's public key (no credential - none
exists yet), it mints a genuinely RANDOM per-device credential
(`secrets.token_urlsafe`, 256 bits of entropy, same as
`activations.issue_activation`'s own operator-issued credentials - never
HMAC-derived from any server secret, so compromising the mechanism
discloses only the handful of credentials it has already issued, never a
skeleton key over every device) and registers it via
`activations.register_credential` -> the SAME `provision_with_activation`
`/v1/activate` already uses. A random (non-derivable) credential needs ONE
piece of durable bookkeeping to stay race-free/idempotent under
concurrency: `FieldEnrollmentIndex` (`field_enrollment.py`'s own small,
self-initializing, capped index file, keyed by public key - never secret,
already sent in cleartext on every request) is the single atomic operation
making "same public key -> idempotent replay" and "global device cap" (now
scoped to THIS index, never to the shared `activations.json`'s own total
record count, which may also hold unrelated operator-issued multi-device
activations) race-free together.

**Credential-at-rest (round-3 review fix)**: the index does NOT store the
raw credential in plaintext - it stores `credential_digest` (the SAME
SHA-256 digest `activations.py` already uses everywhere) plus
`wrapped_credential` (AES-256-GCM ciphertext, base64, via `cryptography
.hazmat.primitives.ciphers.aead.AESGCM` - the same library this repo's own
manifest/envelope signing tooling already depends on, never a hand-rolled
cipher), with the device's own public key bound in as authenticated-
encryption associated data so one entry's wrapped blob can never decrypt
under a different public key. The wrapping key
(`AppConfig.field_enrollment_wrap_key_file` - 32 raw bytes, read
transiently per request, never logged/returned/embedded in the APK) is a
server-only secret in its own trust domain, disjoint from every other
key/secret in this codebase; an index-file leak alone (without that
separate key file) discloses nothing usable, and a corrupted/tampered
wrapped entry fails closed at decrypt time (GCM's own authentication tag)
rather than silently producing wrong bytes.

**Transactional integrity (round-3 review fix)**: `enroll_device` is an
explicit reserve -> register -> provision -> commit-or-rollback state
machine with an unambiguous ownership model - `activations
.RegisterCredentialResult.created` and `_Reservation.is_new_index_entry`
mark whether THIS call, specifically, created the activation record/index
entry (never inferred from exception-message text). If
`activations.register_credential` itself raises (a simulated storage
failure), the index reservation is rolled back (only if this call created
it) and the original exception re-raised - never a dangling reservation,
never a stuck device cap. If provisioning subsequently fails, the EXISTING
`unbind_reservation` mechanism (inside `provision_with_activation` itself)
already removes any PENDING device bind; this module additionally removes
the activation RECORD `register_credential` created via a new,
ownership-and-state-checked primitive, `activations
.remove_credential_if_unbound` (never a blind delete-by-activation_id -
it verifies the record's own `activation_id` matches and that
`bound_devices` is empty before removing anything, mirroring
`unbind_reservation`'s own "only remove what this call is certain it
owns" discipline, and reusing the module's existing fixed lock order -
per-activation lock, then the global store lock - rather than inventing a
new one), then the index reservation. `register_credential` is now
ALWAYS attempted, even on an idempotent replay - this closes a real
crash-recovery gap: a process that reserved an index entry but died
before ever registering the activation record no longer gets stuck
returning `DISABLED` forever; a retry self-heals. Two independent rate
limiters gate the endpoint (`server.py`): a
per-public-key one (`field_enrollment_limiter`) and a global one
(`field_enrollment_global_limiter`, keyed by a single constant) sized near
the device cap itself - the per-key limiter cannot help against an
attacker minting a fresh public key per request, so the global one is the
actual defense against fast device-cap exhaustion (a throttle, not a
Sybil-resistance guarantee - a cap this small has no stronger guarantee
available without the kind of identity proof, e.g. IP allowlisting or a
manually-typed credential, this field test's own constraints rule out).

**Corrective pass, two MAJOR findings from an independent post-round-3
audit (same day)**:

1. **Same-public-key rollback race.** The round-3 design above still had
   no lock serializing one public key's WHOLE lifecycle against a
   CONCURRENT attempt for that SAME key - a failed attempt's own index
   cleanup could delete a concurrent, successful attempt's live index
   entry (the activation-record side of the rollback already had a
   correct ownership check via `remove_credential_if_unbound`; the index
   side did not). Fixed with `field_enrollment_key_lock` - a real
   OS-level `flock` (never `threading.Lock`, since this API's worker
   model does not guarantee two concurrent requests for the same key
   land in the same process), keyed by SHA-256(public_key), that now
   wraps `enroll_device`'s ENTIRE body: same public key => fully
   serialized end to end (reserve -> register -> provision ->
   commit-or-rollback); different public keys => still fully concurrent.
   Fixed lock order, always in this direction: this key lock (outermost)
   -> `FieldEnrollmentIndex`'s own lock -> `activations.py`'s
   per-activation lock -> `activations.py`'s own global store lock
   (already nested inside the per-activation lock by `activations.py`'s
   own unchanged order) - nothing inside any inner critical section ever
   acquires the key lock, so this introduces no cycle. Independently, the
   index-side rollback itself is now ownership-checked -
   `remove_reservation_if_owned` (matches on `activation_id`, mirroring
   `remove_credential_if_unbound`'s own discipline) replaces a blind
   `remove_from_index(public_key)` call in both `enroll_device`'s own
   rollback and the operator CLI's revoke flow - defense in depth on top
   of the lock itself.
2. **Post-`os.replace()` commit uncertainty.** `activations
   ._atomic_write_store` can raise AFTER its own `os.replace()` already
   succeeded (the new content is filesystem-visible) if the FOLLOWING
   containing-directory `fsync()` then fails - a real durability edge
   case a caller must never conflate with "nothing happened."
   `activations.StoreCommitUncertainError` (internal) /
   `ActivationCommitUncertainError` (public, a subclass of the existing
   `ActivationStoreError` - handler.py's existing 503 mapping is
   unchanged) now name this outcome explicitly.
   `field_enrollment.enroll_device`'s registration-failure handler
   catches this SPECIFIC type first and re-raises WITHOUT touching the
   index reservation, even if this call made a new one - the activation
   record it was writing may already durably exist; a same-key retry
   finds the same reservation and reconciles via
   `register_credential`'s own idempotent-insert semantics
   (found-existing-digest -> `created=False`, genuinely absent -> a
   clean `created=True`), never minting a duplicate credential/
   activation_id for the same device.

**Operator CLI (`field_enrollment_admin.py`) TOCTOU fix**: the `revoke`
subcommand's prior find -> revoke -> blind-remove-by-public-key sequence
was three independent, unsynchronized operations - a concurrent
enrollment attempt for the SAME public key could interleave with any part
of it (revoke/remove a STALE entry the CLI read, then have its OWN fresh
entry deleted by that same call's final blind remove). It now calls a
single transactional primitive, `field_enrollment
.revoke_and_remove_if_owned`, entirely inside the SAME
`field_enrollment_key_lock` `enroll_device` itself uses - a concurrent
enrollment for that key either completes entirely before this call
acquires the lock, or entirely after it releases, never interleaved.
Read-only lookups (`find_in_index`/`list_index`) remain a separate,
un-lock-required API surface from transactional/ownership-sensitive
mutation (`_reserve_locked`/`remove_reservation_if_owned`
/`revoke_and_remove_if_owned`) - the CLI's `find`/`list` subcommands use
only the former.

**Index integrity**: `_read_index` now validates each entry's EXACT
shape, not merely field presence - `activation_id` (32 lowercase hex, the
same convention `activations.py` itself uses),
`credential_digest` (64 lowercase hex - a SHA-256 hex digest), and
`wrapped_credential` (valid base64, decoding to at least
nonce+GCM-tag-length bytes) - a corrupted entry of any kind fails closed
with `FieldEnrollmentIndexError` (mapped to 503 by handler.py) at read
time, never at decrypt time only.

**Second corrective pass (same day, independent re-audit of the first
corrective pass's own exact HEAD)** - two further MAJOR findings:

1. **Unbounded per-public-key lock-file growth.** `field_enrollment_key_lock`'s
   first version named its lock file directly by a digest of the public
   key, so the number of persistent lock files grew without bound as new,
   distinct, individually-valid public keys were presented - including
   ones that never successfully enrolled (rejected by the cap, a
   provisioning failure, or simply abandoned) - a cheap, unbounded
   filesystem-growth vector, in tension with this whole mechanism's own
   "bounded" design goal. Fixed with a FIXED-SIZE shard pool: every
   public key maps onto one of `_KEY_LOCK_SHARD_COUNT` (64) lock files via
   `SHA-256(public_key) % 64` (`_key_lock_shard_index`) - the persistent
   footprint this locking mechanism can ever create is bounded by that
   constant, full stop, regardless of request volume. 64 was chosen
   because this mechanism serves only a small, capped field-test cohort
   (`field_enrollment_max_devices`, e.g. 5) - large enough that two
   legitimately-enrolling real devices colliding on the same shard is
   implausible at that scale, small enough to stay a trivial, easily-
   audited constant. A shard collision between two DIFFERENT keys only
   ever serializes their attempts against each other - every read/write
   inside the locked section is still keyed by the real public key/
   credential digest, never by the shard index, so correctness is
   unaffected. No inode-replacement bypass is possible: a shard's lock
   file, once created, is never `unlink()`-ed or replaced for the life of
   the deployment - every subsequent open of that same shard resolves to
   the SAME inode, so two processes locking the same shard always
   `flock()` the same underlying file.
2. **`reservation.activation_id` vs. `register_result.activation_id`
   divergence.** `enroll_device` proceeded straight into provisioning
   using the index's own `reservation.activation_id` without ever
   confirming it matched `activations.register_credential`'s own
   returned `activation_id` (the id the durable activation-store record
   actually carries for that exact credential digest). These are always
   equal on every reachable code path today, but nothing enforced it -
   a prior corruption/manual edit/bug elsewhere could leave the index and
   the store disagreeing about which activation_id a credential digest
   belongs to, and `enroll_device` would silently provision and report
   success against whichever id the store happened to hold.
   `enroll_device` now checks `register_result.activation_id ==
   reservation.activation_id` immediately after registration and, on a
   mismatch, fails closed (`FieldEnrollmentIndexError`, mapped to 503)
   with NO provisioning, NO success response, and NO side effects beyond
   removing this attempt's OWN just-created index reservation (only if
   `reservation.is_new_index_entry`) - the store's own, already-durable
   record under the DIFFERENT `register_result.activation_id` is never
   touched, since this attempt has no ownership claim over it; a
   pre-existing (not newly reserved) index entry that turns out to
   disagree with the store is likewise left completely untouched, never
   silently rewritten to agree with the store.

**Third corrective pass (same day, independent re-audit of the second
corrective pass's own exact HEAD)** - one further MAJOR finding, closing
the LAST persistence-uncertainty gap in `activations._atomic_write_store`:
the second pass correctly classified a post-`os.replace()` directory
`fsync()` failure as `StoreCommitUncertainError`, but left two adjacent
failure points on the SAME side of the `os.replace()` boundary still able
to escape as a plain, unclassified `OSError` - the `os.open(directory,
...)` call that obtains the directory fd (unwrapped entirely) and
`os.close(dir_fd)` (called from a bare `finally`, so a close-time failure
after a successful fsync would propagate as its own uncaught error
instead of the fsync's already-correct classification). Either gap could
have reintroduced the same index-exists/activation-record-status
ambiguity the second pass otherwise closed. Fixed with an explicit local
flag, `replace_completed` (set `True` immediately after `os.replace()`
succeeds, never inferred from exception type or call position) and a
single `try/except OSError` wrapping the ENTIRE post-replace directory
sequence - open, fsync, AND close - that maps any failure among the three
to `StoreCommitUncertainError`. The resulting invariant, stated exactly:
before `os.replace()`, any failure is `DEFINITELY NOT COMMITTED` (store
byte-for-byte untouched, an ordinary `ActivationStoreError`); after
`os.replace()` succeeds, the outcome is always either `COMMITTED` (no
exception) or `COMMIT UNCERTAIN` (`StoreCommitUncertainError` /
`ActivationCommitUncertainError`) - never again `DEFINITELY NOT
COMMITTED`. `field_enrollment.enroll_device`'s existing commit-uncertain
handling (catch `ActivationCommitUncertainError` first, never roll back
the index reservation, re-raise unchanged) required no further change -
it already treats the whole exception type as one thing, regardless of
which of the three post-replace operations actually failed.

**Cross-host topology**: Germany/Stockholm-the-gateway and the Stockholm
ingress ROLE are SEPARATE `pocvpn-api` processes with their OWN,
independent activation stores even when co-located on the same physical
host (see `gateway/config/ingress.env.example`'s own "THIS host's own
dedicated activation store, never shared with a real gateway" docs) - a
credential minted against one is meaningless to the other; pointing both
configs at the same file path is NOT a shared store across hosts. The fix
is `field_enrollment.py` being deployed, independently and identically, on
EVERY control-plane role a device needs zero-touch authority against (the
target gateway AND, separately, the ingress role) - never a
server-to-server call or a shared filesystem. On the ingress role
(`handler.py` passes `provision_awg_peer=False` exactly when the process
was started with an `ingress_config`) `enroll_device` reserves and
registers only - no `provision_with_activation`, since the ingress's
provision script is a no-op placeholder (until this was fixed every
ingress enrollment returned 500, Stockholm 2026-10-28) - then checks the
registered record's entitlement read-only; the device binds on its first
`/v1/ingress-profile` (`provision_and_activate_identity_selfbind`). The
success response keeps its shape with `client_tunnel_ip` `0.0.0.0`
(nothing assigned). Client:
`MainViewModel.ensureZeroTouchEnrollment()` (called from `connect()` only
when `BuildConfig.FIELD_ENROLLMENT_ENABLED` and the device has never been
activated) calls `ProvisioningClient.fieldEnroll` against the TARGET
GATEWAY's own host, persists the credential in `FieldCredentialStore`
(AndroidKeyStore-backed, keyed BY ENDPOINT HOST - same per-endpoint
discipline `FileIngressProfileStore` already uses, since a gateway's and
an ingress's credentials are cryptographically and administratively
distinct), then calls the EXISTING `activateDevice(credential, ...)`
verbatim - no parallel apply/persist path. `attemptRelayedAttempt`'s
`PROFILE_NOT_PROVISIONED` branch, when zero-touch is enabled, separately
field-enrolls (or reuses a stored credential) against THIS candidate's own
`ingressBinding.host` specifically (the same host `IngressProfileProvisioner`
itself POSTs `/v1/ingress-profile` to) before calling the same
`performIngressActivation` helper `activateIngress` uses - never confusing
the two hosts' credentials. If ingress-side enrollment cannot succeed (not
deployed/enabled there, or a network failure), the combined sequence
advances to the next candidate immediately rather than pausing for
`ActivationScreen` - a field build can never render that prompt (see
`AppRoot`'s `isZeroTouchEnrollmentBuild` gating), so pausing would strand
the sequence forever with nothing able to resume it.

`BuildConfig.FIELD_ENROLLMENT_ENABLED` defaults `false` (set only via a
developer-local, gitignored `gateway-dev.properties` key) - an ordinary
debug/release build is byte-for-byte unaffected.

**Deliberately does NOT touch Smart Connect** (`PathScorer`/
`AutoGatewaySelector`/`SmartConnectDecisionEngine`/`TransportOrchestrator`/
`RoutingDecisionEngine`), attempt budgets, AWG, Xray/Reality, TLS fallback,
or the relay watchdog - enrollment/UX only, this slice's own explicit
scope boundary. A real, physically-observed CHAIN_DIRECT eligibility bug
(a different endpoint's Direct transport-health failures could poison an
unrelated, never-yet-dialed ingress candidate's own eligibility) exists in
the field-test history this recovery is based on, with an additive,
default-preserving fix already drafted - deliberately NOT ported here,
since fixing Smart Connect eligibility is a separate concern from minting
enrollment credentials and belongs with B67.7 (Smart Connect Integration,
still PLANNED) rather than being folded into this slice.

Not yet physically exercised end to end against a real field-test
deployment (in particular, the ingress role's own
`POCVPN_API_FIELD_ENROLLMENT_*` env vars have never been deployed - only
unit/integration-tested against a fake ingress config, and no nginx
`-t`/reload was performed against a live host). No production credential,
production `ActivationEnvelope`, or production infrastructure change was
made porting this to the current base - see `docs/ROADMAP.md`'s B67.4 row.
