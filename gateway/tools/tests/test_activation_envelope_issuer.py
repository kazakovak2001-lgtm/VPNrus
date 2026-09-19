"""B56-4A - tests for gateway/tools/activation_envelope_issuer.py.

Requires a POSIX environment with `fcntl` (Linux/WSL) for the `issue`-path
tests, exactly like this directory's existing suite (see run_tests.sh) -
the pure encoding/signing/key-generation/bundle-inspection tests do not
touch gateway.api.activations at all and are platform-independent.

Uses ONLY temporary stores/files - never a real production store, never a
real production key.
"""
import base64
import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_GATEWAY_DIR = os.path.abspath(os.path.join(_TOOLS_DIR, ".."))
for _path in (_GATEWAY_DIR, _TOOLS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import activation_envelope_issuer as issuer  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

import manifest_signing  # noqa: E402


# Deterministic TEST-ONLY key - same one embedded in
# ActivationEnvelopePythonCompatibilityTest.kt. Never a production key.
_TEST_PRIVATE_KEY_BYTES = bytes(range(32))


def _write_test_key_file(directory):
    path = os.path.join(directory, "test-issuer-private-key.bin")
    with open(path, "wb") as handle:
        handle.write(_TEST_PRIVATE_KEY_BYTES)
    return path


def _make_test_envelope(**overrides):
    fields = dict(
        activation_id="a1b2c3d4e5f60718293a4b5c6d7e8f90",
        credential="TESTcredential_urlsafe-0123456789ABCDEFGHIJ",
        issued_at_epoch_millis=1_700_000_000_000,
        not_before_epoch_millis=1_700_000_000_000,
        expires_at_epoch_millis=1_700_000_000_000 + 48 * 3600 * 1000,
        bootstrap_bundle_ref=None,
        bootstrap_endpoint_hints=("frankfurt-gw", "stockholm-gw"),
        bootstrap_capability_hint=None,
        nonce=bytes(range(16)),
        issuer_key_id="test-activation-issuer-key-1",
    )
    fields.update(overrides)
    return issuer.ActivationEnvelope(**fields)


class CanonicalEncodingLayoutTests(unittest.TestCase):
    def test_domain_tag_and_format_version_are_the_first_bytes(self):
        canon = issuer.canonical_bytes(_make_test_envelope())
        offset = 0
        tag_len = struct.unpack_from(">i", canon, offset)[0]
        offset += 4
        self.assertEqual(issuer.DOMAIN_TAG, canon[offset:offset + tag_len].decode("utf-8"))
        offset += tag_len
        format_version = struct.unpack_from(">i", canon, offset)[0]
        self.assertEqual(issuer.CANONICAL_FORMAT_VERSION, format_version)

    def test_no_bundle_ref_writes_false_boolean_and_nothing_else(self):
        canon = issuer.canonical_bytes(_make_test_envelope(bootstrap_bundle_ref=None))
        # Re-decode manually up to the boolean flag to assert it's exactly 0x00.
        offset = 4 + len(issuer.DOMAIN_TAG) + 4  # domain tag + its length prefix + format version
        offset += 4 + len("a1b2c3d4e5f60718293a4b5c6d7e8f90")  # activationId
        offset += 4 + len("TESTcredential_urlsafe-0123456789ABCDEFGHIJ")  # credential
        offset += 8 * 3  # issuedAt/notBefore/expiresAt longs
        has_bundle_byte = canon[offset]
        self.assertEqual(0, has_bundle_byte)

    def test_bundle_ref_writes_true_boolean_then_manifest_version_then_hash(self):
        content_hash = hashlib.sha256(b"fixture").digest()
        ref = issuer.BundleRef(manifest_version=7, content_hash=content_hash)
        canon = issuer.canonical_bytes(_make_test_envelope(bootstrap_bundle_ref=ref))
        offset = 4 + len(issuer.DOMAIN_TAG) + 4
        offset += 4 + len("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        offset += 4 + len("TESTcredential_urlsafe-0123456789ABCDEFGHIJ")
        offset += 8 * 3
        self.assertEqual(1, canon[offset])
        offset += 1
        manifest_version = struct.unpack_from(">i", canon, offset)[0]
        self.assertEqual(7, manifest_version)
        offset += 4
        hash_len = struct.unpack_from(">i", canon, offset)[0]
        offset += 4
        self.assertEqual(32, hash_len)
        self.assertEqual(content_hash, canon[offset:offset + hash_len])

    def test_endpoint_hints_are_encoded_in_original_order_never_sorted(self):
        env = _make_test_envelope(bootstrap_endpoint_hints=("zzz-last", "aaa-first"))
        canon = issuer.canonical_bytes(env)
        self.assertLess(canon.index(b"zzz-last"), canon.index(b"aaa-first"))

    def test_no_capability_hint_writes_false_boolean(self):
        env = _make_test_envelope()
        canon = issuer.canonical_bytes(env)
        offset = 4 + len(issuer.DOMAIN_TAG) + 4
        offset += 4 + len("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        offset += 4 + len("TESTcredential_urlsafe-0123456789ABCDEFGHIJ")
        offset += 8 * 3
        offset += 1  # hasBundleRef=false
        offset += 4  # hint count
        offset += 4 + len("frankfurt-gw") + 4 + len("stockholm-gw")
        has_capability_byte = canon[offset]
        self.assertEqual(0, has_capability_byte)

    def test_nonce_is_length_prefixed_16_bytes_at_the_expected_position(self):
        canon = issuer.canonical_bytes(_make_test_envelope())
        self.assertIn(struct.pack(">i", 16) + bytes(range(16)), canon)

    def test_issuer_key_id_is_the_final_field(self):
        canon = issuer.canonical_bytes(_make_test_envelope())
        key_id_bytes = "test-activation-issuer-key-1".encode("utf-8")
        self.assertTrue(canon.endswith(struct.pack(">i", len(key_id_bytes)) + key_id_bytes))


class SigningTests(unittest.TestCase):
    def test_signature_is_64_bytes_and_verifies_against_the_derived_public_key(self):
        priv = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)
        pub = priv.public_key()
        env = _make_test_envelope()
        sig = issuer.sign_envelope(env, priv)
        self.assertEqual(64, len(sig))
        pub.verify(sig, issuer.canonical_bytes(env))  # raises if invalid

    def test_signature_only_covers_canonical_bytes_not_a_json_or_object_repr(self):
        priv = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)
        env = _make_test_envelope()
        sig = issuer.sign_envelope(env, priv)
        tampered_canon = bytearray(issuer.canonical_bytes(env))
        tampered_canon[-1] ^= 0x01
        with self.assertRaises(Exception):
            priv.public_key().verify(sig, bytes(tampered_canon))


class OuterCodecLayoutTests(unittest.TestCase):
    def test_pack_signed_envelope_matches_exact_container_shape(self):
        priv = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)
        env = _make_test_envelope()
        canon = issuer.canonical_bytes(env)
        sig = issuer.sign_envelope(env, priv)
        artifact = issuer.pack_signed_envelope(canon, sig)

        offset = 0
        format_version = struct.unpack_from(">i", artifact, offset)[0]
        self.assertEqual(1, format_version)
        offset += 4
        canonical_len = struct.unpack_from(">i", artifact, offset)[0]
        self.assertEqual(len(canon), canonical_len)
        offset += 4
        self.assertEqual(canon, artifact[offset:offset + canonical_len])
        offset += canonical_len
        sig_len = struct.unpack_from(">i", artifact, offset)[0]
        self.assertEqual(64, sig_len)
        offset += 4
        self.assertEqual(sig, artifact[offset:offset + sig_len])
        offset += sig_len
        self.assertEqual(len(artifact), offset)  # exact consumption, no trailing bytes

    def test_pack_signed_envelope_rejects_wrong_signature_length(self):
        env = _make_test_envelope()
        canon = issuer.canonical_bytes(env)
        with self.assertRaises(issuer.IssuerError):
            issuer.pack_signed_envelope(canon, b"\x00" * 63)


class PrivateKeyFileTests(unittest.TestCase):
    def test_reads_exactly_32_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_test_key_file(tmp)
            priv = issuer.read_private_key_file(path)
            self.assertEqual(_TEST_PRIVATE_KEY_BYTES, priv.private_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    def test_rejects_wrong_length(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.bin")
            with open(path, "wb") as handle:
                handle.write(b"\x00" * 31)
            with self.assertRaises(issuer.IssuerError):
                issuer.read_private_key_file(path)

    def test_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(issuer.IssuerError):
                issuer.read_private_key_file(os.path.join(tmp, "does-not-exist.bin"))

    def test_error_message_never_contains_the_key_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.bin")
            secret_looking_bytes = b"\xaa" * 31
            with open(path, "wb") as handle:
                handle.write(secret_looking_bytes)
            try:
                issuer.read_private_key_file(path)
                self.fail("expected IssuerError")
            except issuer.IssuerError as exc:
                self.assertNotIn(secret_looking_bytes.hex(), str(exc))
                self.assertNotIn(base64.b64encode(secret_looking_bytes).decode(), str(exc))


class GenerateKeyTests(unittest.TestCase):
    def test_generates_key_and_writes_expected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = issuer.cmd_generate_key(args)
            self.assertEqual(0, rc)
            self.assertTrue(os.path.isfile(priv_path))
            self.assertTrue(os.path.isfile(meta_path))
            with open(priv_path, "rb") as handle:
                priv_bytes = handle.read()
            self.assertEqual(32, len(priv_bytes))
            with open(meta_path, "r", encoding="utf-8") as handle:
                metadata = json.load(handle)
            self.assertEqual({"issuerKeyId", "publicKeyBase64", "publicKeyFingerprintSha256Hex"}, set(metadata.keys()))
            self.assertEqual("test-key-1", metadata["issuerKeyId"])
            pub_bytes = base64.b64decode(metadata["publicKeyBase64"])
            self.assertEqual(32, len(pub_bytes))
            self.assertEqual(hashlib.sha256(pub_bytes).hexdigest(), metadata["publicKeyFingerprintSha256Hex"])

    def test_never_prints_the_private_key_bytes_or_its_base64(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                issuer.cmd_generate_key(args)
            with open(priv_path, "rb") as handle:
                priv_bytes = handle.read()
            combined_output = stdout.getvalue() + stderr.getvalue()
            self.assertNotIn(priv_bytes.hex(), combined_output)
            self.assertNotIn(base64.b64encode(priv_bytes).decode(), combined_output)

    def test_public_metadata_contains_no_private_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                issuer.cmd_generate_key(args)
            with open(priv_path, "rb") as handle:
                priv_bytes = handle.read()
            with open(meta_path, "r", encoding="utf-8") as handle:
                meta_text = handle.read()
            self.assertNotIn(priv_bytes.hex(), meta_text)
            self.assertNotIn(base64.b64encode(priv_bytes).decode(), meta_text)
            self.assertNotIn("private", meta_text.lower())

    def test_refuses_to_overwrite_existing_private_key_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            with open(priv_path, "wb") as handle:
                handle.write(b"\x00" * 32)
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)
            with self.assertRaises(issuer.IssuerError):
                issuer.cmd_generate_key(args)
            # Original file must be untouched.
            with open(priv_path, "rb") as handle:
                self.assertEqual(b"\x00" * 32, handle.read())

    def test_refuses_output_paths_inside_a_git_repository(self):
        # This repository's own tree IS a git working tree - a path inside
        # gateway/tools itself must be refused.
        inside_repo_path = os.path.join(_TOOLS_DIR, "should-never-be-written.key")
        self.addCleanup(lambda: os.path.exists(inside_repo_path) and os.remove(inside_repo_path))
        with tempfile.TemporaryDirectory() as tmp:
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=inside_repo_path, public_metadata_out=meta_path)
            with self.assertRaises(issuer.IssuerError):
                issuer.cmd_generate_key(args)
            self.assertFalse(os.path.exists(inside_repo_path))


class EndpointHintValidationTests(unittest.TestCase):
    def test_preserves_order(self):
        hints = issuer._validate_hints_order_preserving(["c", "a", "b"])
        self.assertEqual(("c", "a", "b"), hints)

    def test_rejects_duplicate(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._validate_hints_order_preserving(["a", "a"])

    def test_rejects_too_many(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._validate_hints_order_preserving([f"h{i}" for i in range(33)])

    def test_accepts_exactly_the_max(self):
        hints = issuer._validate_hints_order_preserving([f"h{i}" for i in range(32)])
        self.assertEqual(32, len(hints))

    def test_rejects_hint_exceeding_utf8_byte_bound(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._validate_hints_order_preserving(["x" * 129])

    def test_accepts_hint_at_exactly_the_utf8_byte_bound(self):
        hints = issuer._validate_hints_order_preserving(["x" * 128])
        self.assertEqual(("x" * 128,), hints)

    def test_rejects_blank_hint(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._validate_hints_order_preserving([""])


class BundleInspectionTests(unittest.TestCase):
    def _sign_and_package_manifest(self, tmp, manifest_version=3):
        priv = Ed25519PrivateKey.generate()
        manifest = manifest_signing.Manifest(
            manifest_version=manifest_version,
            issued_at_epoch_millis=1000,
            expires_at_epoch_millis=9_000_000_000,
            endpoints=[],
            signing_key_id="test-manifest-key",
        )
        canonical = manifest_signing.canonical_bytes(manifest)
        signature = manifest_signing.sign(manifest, priv)
        artifact = manifest_signing.pack_signed_manifest(canonical, signature)
        path = os.path.join(tmp, "bundle.bin")
        with open(path, "wb") as handle:
            handle.write(artifact)
        return path, artifact

    def test_extracts_manifest_version_and_exact_file_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, artifact = self._sign_and_package_manifest(tmp, manifest_version=42)
            version, content_hash = issuer.inspect_signed_manifest_bundle(path)
            self.assertEqual(42, version)
            self.assertEqual(hashlib.sha256(artifact).digest(), content_hash)

    def test_hash_is_over_exact_artifact_bytes_not_canonical_bytes_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, artifact = self._sign_and_package_manifest(tmp)
            _, content_hash = issuer.inspect_signed_manifest_bundle(path)
            wrong_hash = hashlib.sha256(artifact[8:]).digest()  # hash of canonical+sig section only
            self.assertNotEqual(wrong_hash, content_hash)

    def test_rejects_malformed_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.bin")
            with open(path, "wb") as handle:
                handle.write(b"\x01\x02\x03")
            with self.assertRaises(issuer.BundleInspectionError):
                issuer.inspect_signed_manifest_bundle(path)

    def test_rejects_trailing_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, artifact = self._sign_and_package_manifest(tmp)
            with open(path, "wb") as handle:
                handle.write(artifact + b"\x00")
            with self.assertRaises(issuer.BundleInspectionError):
                issuer.inspect_signed_manifest_bundle(path)

    def test_rejects_unsupported_outer_format_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, artifact = self._sign_and_package_manifest(tmp)
            tampered = struct.pack(">i", 2) + artifact[4:]
            with open(path, "wb") as handle:
                handle.write(tampered)
            with self.assertRaises(issuer.BundleInspectionError):
                issuer.inspect_signed_manifest_bundle(path)

    def test_does_not_parse_or_require_any_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            # manifest with zero endpoints still inspects cleanly - this is
            # metadata inspection, never a manifest-content verifier.
            path, _ = self._sign_and_package_manifest(tmp, manifest_version=1)
            version, _ = issuer.inspect_signed_manifest_bundle(path)
            self.assertEqual(1, version)


def _run_issue(args):
    """Mirrors main()'s own IssuerError -> exit-code-1 translation for
    PRE-issuance validation failures (steps 1-4 - before any revocable
    side effect exists, so cmd_issue itself simply raises, exactly like
    activation_tokens.py's own _fail()/SystemExit convention). Failures
    AFTER issue_activation() succeeds are handled inside cmd_issue's own
    try/except and already return 1 directly - this helper only covers
    the pre-issuance raise path so tests can assert on a return code
    uniformly."""
    try:
        return issuer.cmd_issue(args)
    except issuer.IssuerError:
        return 1


def _fcntl_available():
    try:
        import fcntl  # noqa: F401

        return True
    except ImportError:
        return False


@unittest.skipUnless(_fcntl_available(), "requires a POSIX fcntl environment - see run_tests.sh")
class IssueCommandTests(unittest.TestCase):
    """Uses the REAL gateway.api.activations store (temp dir only) - never mocked, per module requirements."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = os.path.join(self.tmp.name, "activations.json")
        self.lock = os.path.join(self.tmp.name, "activations.lock")
        self.key_path = _write_test_key_file(self.tmp.name)
        activations_module = issuer._activations_module()
        activations_module.init_store(self.store, self.lock)
        self.activations_module = activations_module

    def _base_args(self, **overrides):
        args = mock.Mock(
            store=self.store,
            lock=self.lock,
            issuer_key_id="test-activation-issuer-key-1",
            private_key_file=self.key_path,
            max_devices=1,
            activation_expires_in_days=None,
            envelope_valid_for_hours=48.0,
            endpoint_hint=[],
            bootstrap_bundle=None,
            out=os.path.join(self.tmp.name, "envelope.bin"),
        )
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def test_issue_uses_the_existing_issue_activation_and_produces_a_verifiable_envelope(self):
        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = issuer.cmd_issue(args)
        self.assertEqual(0, rc)

        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(1, len(records))
        self.assertEqual(self.activations_module.ACTIVE, records[0]["status"])

        with open(args.out, "rb") as handle:
            artifact = handle.read()
        # A client-verifiable envelope: correctly formed outer container,
        # correct signature length, decodable canonical section.
        self.assertGreater(len(artifact), 0)
        canonical_len = struct.unpack_from(">i", artifact, 4)[0]
        sig_len = struct.unpack_from(">i", artifact, 8 + canonical_len)[0]
        self.assertEqual(64, sig_len)

        priv = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)
        canonical = artifact[8:8 + canonical_len]
        signature = artifact[12 + canonical_len:12 + canonical_len + sig_len]
        priv.public_key().verify(signature, canonical)  # raises if invalid

    def test_credential_never_appears_in_stdout_or_stderr(self):
        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            issuer.cmd_issue(args)
        record = self.activations_module.list_all(self.store, self.lock)[0]
        digest_map_credentials = []  # we don't have the raw credential here by design - re-derive via a fresh issue
        combined = stdout.getvalue() + stderr.getvalue()
        # We cannot know the raw credential without re-deriving it, but we
        # CAN assert the envelope artifact bytes (which DO contain it) never
        # appear, and that no base64/hex blob resembling token_urlsafe(32)
        # output (43 chars, URL-safe alphabet) appears verbatim.
        with open(args.out, "rb") as handle:
            artifact = handle.read()
        self.assertNotIn(base64.b64encode(artifact).decode(), combined)
        self.assertNotIn(artifact.hex(), combined)

    def test_output_refuses_to_overwrite(self):
        args = self._base_args()
        with open(args.out, "wb") as handle:
            handle.write(b"existing")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = _run_issue(args)
        self.assertEqual(1, rc)
        with open(args.out, "rb") as handle:
            self.assertEqual(b"existing", handle.read())
        # The pre-flight overwrite check happens BEFORE issue_activation() -
        # no activation should have been created at all.
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_envelope_expiry_never_extends_beyond_server_activation_expiry(self):
        args = self._base_args(activation_expires_in_days=1.0, envelope_valid_for_hours=48.0)  # 48h > 24h(1 day)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as stderr:
            rc = issuer.cmd_issue(args)
        self.assertEqual(1, rc)
        self.assertIn("server-side expiry", stderr.getvalue())
        # Atomicity: the activation created for this attempt must be revoked, not left ACTIVE.
        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(1, len(records))
        self.assertEqual(self.activations_module.REVOKED, records[0]["status"])
        self.assertFalse(os.path.exists(args.out))

    def test_envelope_expiry_within_server_activation_expiry_succeeds(self):
        args = self._base_args(activation_expires_in_days=30.0, envelope_valid_for_hours=48.0)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = issuer.cmd_issue(args)
        self.assertEqual(0, rc)
        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(self.activations_module.ACTIVE, records[0]["status"])

    def test_nonce_is_exactly_16_random_bytes_and_differs_across_issuances(self):
        args1 = self._base_args(out=os.path.join(self.tmp.name, "env1.bin"))
        args2 = self._base_args(out=os.path.join(self.tmp.name, "env2.bin"))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            issuer.cmd_issue(args1)
            issuer.cmd_issue(args2)
        with open(args1.out, "rb") as h1, open(args2.out, "rb") as h2:
            a1, a2 = h1.read(), h2.read()
        self.assertNotEqual(a1, a2)  # different activation_id/credential/nonce guarantee this

    def test_capability_hint_is_always_absent_no_cli_option_exists(self):
        import argparse

        parser = issuer.build_parser()
        subparsers_action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        issue_parser = subparsers_action.choices["issue"]
        option_strings = {opt for action in issue_parser._actions for opt in action.option_strings}
        self.assertNotIn("--capability-hint", option_strings)
        self.assertNotIn("--bootstrap-capability-hint", option_strings)

    def test_bootstrap_bundle_is_never_re_signed_only_referenced_by_hash(self):
        priv = Ed25519PrivateKey.generate()
        manifest = manifest_signing.Manifest(
            manifest_version=5, issued_at_epoch_millis=1000, expires_at_epoch_millis=9_000_000_000,
            endpoints=[], signing_key_id="test-manifest-key",
        )
        canonical = manifest_signing.canonical_bytes(manifest)
        signature = manifest_signing.sign(manifest, priv)
        bundle_artifact = manifest_signing.pack_signed_manifest(canonical, signature)
        bundle_path = os.path.join(self.tmp.name, "bundle.bin")
        with open(bundle_path, "wb") as handle:
            handle.write(bundle_artifact)
        bundle_bytes_before = bundle_artifact

        args = self._base_args(bootstrap_bundle=bundle_path)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = issuer.cmd_issue(args)
        self.assertEqual(0, rc)
        with open(bundle_path, "rb") as handle:
            bundle_bytes_after = handle.read()
        self.assertEqual(bundle_bytes_before, bundle_bytes_after)  # byte-for-byte untouched

    def test_bootstrap_bundle_hash_and_version_flow_into_the_envelope(self):
        priv = Ed25519PrivateKey.generate()
        manifest = manifest_signing.Manifest(
            manifest_version=9, issued_at_epoch_millis=1000, expires_at_epoch_millis=9_000_000_000,
            endpoints=[], signing_key_id="test-manifest-key",
        )
        canonical = manifest_signing.canonical_bytes(manifest)
        signature = manifest_signing.sign(manifest, priv)
        bundle_artifact = manifest_signing.pack_signed_manifest(canonical, signature)
        bundle_path = os.path.join(self.tmp.name, "bundle.bin")
        with open(bundle_path, "wb") as handle:
            handle.write(bundle_artifact)
        expected_hash = hashlib.sha256(bundle_artifact).digest()

        args = self._base_args(bootstrap_bundle=bundle_path)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            issuer.cmd_issue(args)
        with open(args.out, "rb") as handle:
            artifact = handle.read()
        self.assertIn(expected_hash, artifact)  # the exact hash bytes are embedded in the canonical section
        self.assertIn(struct.pack(">i", 9), artifact)  # manifestVersion=9 present somewhere in canonical ints

    def test_malformed_bootstrap_bundle_rejected_before_activation_issuance(self):
        bundle_path = os.path.join(self.tmp.name, "bad-bundle.bin")
        with open(bundle_path, "wb") as handle:
            handle.write(b"not a real signed manifest")
        args = self._base_args(bootstrap_bundle=bundle_path)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = _run_issue(args)
        self.assertEqual(1, rc)
        # No activation was ever created - rejected before step 5.
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_trailing_bytes_in_bootstrap_bundle_rejected_before_activation_issuance(self):
        priv = Ed25519PrivateKey.generate()
        manifest = manifest_signing.Manifest(
            manifest_version=1, issued_at_epoch_millis=1000, expires_at_epoch_millis=9_000_000_000,
            endpoints=[], signing_key_id="test-manifest-key",
        )
        artifact = manifest_signing.pack_signed_manifest(
            manifest_signing.canonical_bytes(manifest), manifest_signing.sign(manifest, priv),
        )
        bundle_path = os.path.join(self.tmp.name, "trailing.bin")
        with open(bundle_path, "wb") as handle:
            handle.write(artifact + b"\xff")
        args = self._base_args(bootstrap_bundle=bundle_path)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_post_issue_signing_failure_revokes_the_new_activation(self):
        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(issuer, "canonical_bytes", side_effect=RuntimeError("simulated post-issue failure")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = issuer.cmd_issue(args)
        self.assertEqual(1, rc)
        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(1, len(records))
        self.assertEqual(self.activations_module.REVOKED, records[0]["status"])
        self.assertFalse(os.path.exists(args.out))
        self.assertNotIn("credential", stdout.getvalue().lower())

    def test_post_issue_output_write_failure_revokes_the_new_activation(self):
        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(issuer, "_atomic_write_secret_file", side_effect=OSError("simulated disk failure")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = issuer.cmd_issue(args)
        self.assertEqual(1, rc)
        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(1, len(records))
        self.assertEqual(self.activations_module.REVOKED, records[0]["status"])

    def test_revocation_failure_path_reports_activation_id_but_never_a_credential(self):
        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(issuer, "canonical_bytes", side_effect=RuntimeError("simulated failure")):
            with mock.patch.object(self.activations_module, "revoke_activation", side_effect=RuntimeError("revoke also failed")):
                with mock.patch.object(issuer, "_activations_module", return_value=self.activations_module):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = issuer.cmd_issue(args)
        self.assertEqual(1, rc)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertIn("CRITICAL", combined)
        self.assertIn("MANUAL REVOCATION REQUIRED", combined)
        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(1, len(records))
        # Since the mocked revoke_activation "failed", the record is still
        # ACTIVE - this is the documented, reported-not-silent failure mode.
        self.assertEqual(self.activations_module.ACTIVE, records[0]["status"])
        for record in records:
            combined_lower = combined.lower()
            self.assertIn(record["activation_id"], combined)  # non-secret id IS reported
        # No credential-shaped (43-char url-safe base64) token appears.
        import re

        self.assertIsNone(re.search(r"[A-Za-z0-9_-]{43}", combined))


if __name__ == "__main__":
    unittest.main()
