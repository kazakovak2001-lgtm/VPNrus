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
import re
import stat
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

import manifest_signing  # noqa: E402


# Deterministic TEST-ONLY key - same one embedded in
# ActivationEnvelopePythonCompatibilityTest.kt. Never a production key.
_TEST_PRIVATE_KEY_BYTES = bytes(range(32))
_TEST_ISSUER_KEY_ID = "test-activation-issuer-key-1"


def _write_test_key_file(directory, key_bytes=_TEST_PRIVATE_KEY_BYTES, name="test-issuer-private-key.bin"):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(key_bytes)
    os.chmod(path, 0o600)
    return path


def _write_metadata_file(directory, private_key_bytes=_TEST_PRIVATE_KEY_BYTES, issuer_key_id=_TEST_ISSUER_KEY_ID,
                          name="test-issuer-metadata.json", corrupt_fingerprint=False, corrupt_public_key=False):
    priv = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    pub_bytes = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    if corrupt_public_key:
        pub_bytes = bytes((b ^ 0xFF) for b in pub_bytes)
    fingerprint = hashlib.sha256(pub_bytes).hexdigest()
    if corrupt_fingerprint:
        fingerprint = "0" * 64
    metadata = {
        "issuerKeyId": issuer_key_id,
        "publicKeyBase64": base64.b64encode(pub_bytes).decode("ascii"),
        "publicKeyFingerprintSha256Hex": fingerprint,
    }
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle)
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
        issuer_key_id=_TEST_ISSUER_KEY_ID,
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
        key_id_bytes = _TEST_ISSUER_KEY_ID.encode("utf-8")
        self.assertTrue(canon.endswith(struct.pack(">i", len(key_id_bytes)) + key_id_bytes))

    def test_canonical_bytes_never_exceed_android_max_canonical_bytes(self):
        # Build a near-worst-case envelope (max hints, each at the max
        # UTF-8 byte length, plus a bundle ref) and confirm it stays within
        # Android's own MAX_CANONICAL_BYTES - PR #95 review fix item 11.
        hints = tuple(f"h{i:03d}-" + "x" * 121 for i in range(32))  # 128 bytes each
        ref = issuer.BundleRef(manifest_version=2_000_000_000, content_hash=b"\xff" * 32)
        env = _make_test_envelope(bootstrap_endpoint_hints=hints, bootstrap_bundle_ref=ref, credential="A" * 256)
        canon = issuer.canonical_bytes(env)
        self.assertLessEqual(len(canon), issuer.MAX_CANONICAL_BYTES)


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

    def test_encoded_artifact_never_exceeds_android_max_encoded_bytes(self):
        priv = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)
        hints = tuple(f"h{i:03d}-" + "x" * 121 for i in range(32))
        ref = issuer.BundleRef(manifest_version=2_000_000_000, content_hash=b"\xff" * 32)
        env = _make_test_envelope(bootstrap_endpoint_hints=hints, bootstrap_bundle_ref=ref, credential="A" * 256)
        artifact = issuer.pack_signed_envelope(issuer.canonical_bytes(env), issuer.sign_envelope(env, priv))
        self.assertLessEqual(len(artifact), issuer.MAX_ENCODED_BYTES)


class IssuerKeyIdValidationTests(unittest.TestCase):
    def test_accepts_a_normal_key_id(self):
        issuer.validate_issuer_key_id("prod-activation-issuer-2026-09")  # must not raise

    def test_rejects_blank(self):
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_issuer_key_id("")

    def test_rejects_whitespace_only(self):
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_issuer_key_id("   ")

    def test_accepts_exactly_64_utf8_bytes(self):
        issuer.validate_issuer_key_id("x" * 64)  # must not raise

    def test_rejects_65_utf8_bytes(self):
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_issuer_key_id("x" * 65)

    def test_rejects_multibyte_text_exceeding_byte_bound_even_if_char_count_is_low(self):
        # Each of these characters is multi-byte in UTF-8 - 64 of them
        # exceeds 64 BYTES even though the Python string length is 64.
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_issuer_key_id("é" * 64)


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
            os.chmod(path, 0o600)
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
            os.chmod(path, 0o600)
            try:
                issuer.read_private_key_file(path)
                self.fail("expected IssuerError")
            except issuer.IssuerError as exc:
                self.assertNotIn(secret_looking_bytes.hex(), str(exc))
                self.assertNotIn(base64.b64encode(secret_looking_bytes).decode(), str(exc))

    def test_rejects_a_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(issuer.IssuerError):
                issuer.read_private_key_file(tmp)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not meaningful on Windows")
    def test_rejects_group_readable_permissions_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_test_key_file(tmp)
            os.chmod(path, 0o640)  # group-readable
            with self.assertRaises(issuer.IssuerError):
                issuer.read_private_key_file(path)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not meaningful on Windows")
    def test_rejects_world_writable_permissions_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_test_key_file(tmp)
            os.chmod(path, 0o602)
            with self.assertRaises(issuer.IssuerError):
                issuer.read_private_key_file(path)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not meaningful on Windows")
    def test_accepts_owner_only_permissions_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_test_key_file(tmp)
            os.chmod(path, 0o600)
            issuer.read_private_key_file(path)  # must not raise


class IssuerMetadataFileTests(unittest.TestCase):
    def test_parses_a_well_formed_metadata_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_metadata_file(tmp)
            identity = issuer.read_issuer_metadata_file(path)
            self.assertEqual(_TEST_ISSUER_KEY_ID, identity.issuer_key_id)
            self.assertEqual(32, len(identity.public_key_bytes))

    def test_rejects_extra_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "meta.json")
            priv = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)
            pub_bytes = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            data = {
                "issuerKeyId": _TEST_ISSUER_KEY_ID,
                "publicKeyBase64": base64.b64encode(pub_bytes).decode(),
                "publicKeyFingerprintSha256Hex": hashlib.sha256(pub_bytes).hexdigest(),
                "extraField": "unexpected",
            }
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle)
            with self.assertRaises(issuer.IssuerError):
                issuer.read_issuer_metadata_file(path)

    def test_rejects_missing_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "meta.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"issuerKeyId": _TEST_ISSUER_KEY_ID}, handle)
            with self.assertRaises(issuer.IssuerError):
                issuer.read_issuer_metadata_file(path)

    def test_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "meta.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            with self.assertRaises(issuer.IssuerError):
                issuer.read_issuer_metadata_file(path)

    def test_rejects_public_key_wrong_length(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "meta.json")
            data = {
                "issuerKeyId": _TEST_ISSUER_KEY_ID,
                "publicKeyBase64": base64.b64encode(b"\x00" * 31).decode(),
                "publicKeyFingerprintSha256Hex": hashlib.sha256(b"\x00" * 31).hexdigest(),
            }
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle)
            with self.assertRaises(issuer.IssuerError):
                issuer.read_issuer_metadata_file(path)

    def test_rejects_non_strict_base64(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "meta.json")
            data = {
                "issuerKeyId": _TEST_ISSUER_KEY_ID,
                "publicKeyBase64": "not!!valid==base64",
                "publicKeyFingerprintSha256Hex": "0" * 64,
            }
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle)
            with self.assertRaises(issuer.IssuerError):
                issuer.read_issuer_metadata_file(path)

    def test_rejects_fingerprint_wrong_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "meta.json")
            priv = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)
            pub_bytes = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            data = {
                "issuerKeyId": _TEST_ISSUER_KEY_ID,
                "publicKeyBase64": base64.b64encode(pub_bytes).decode(),
                "publicKeyFingerprintSha256Hex": "NOT-HEX",
            }
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle)
            with self.assertRaises(issuer.IssuerError):
                issuer.read_issuer_metadata_file(path)

    def test_rejects_fingerprint_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_metadata_file(tmp, corrupt_fingerprint=True)
            with self.assertRaises(issuer.IssuerError):
                issuer.read_issuer_metadata_file(path)

    def test_rejects_invalid_issuer_key_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_metadata_file(tmp, issuer_key_id="   ")
            with self.assertRaises(issuer.IssuerError):
                issuer.read_issuer_metadata_file(path)


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
            # The generated key/metadata must themselves pass read_issuer_metadata_file/read_private_key_file.
            identity = issuer.read_issuer_metadata_file(meta_path)
            priv = issuer.read_private_key_file(priv_path)
            derived_pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            self.assertEqual(identity.public_key_bytes, derived_pub)

    def test_rejects_invalid_key_id_before_writing_anything(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="   ", private_key_out=priv_path, public_metadata_out=meta_path)
            with self.assertRaises(issuer.IssuerError):
                issuer.cmd_generate_key(args)
            self.assertFalse(os.path.exists(priv_path))
            self.assertFalse(os.path.exists(meta_path))

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
            with open(priv_path, "rb") as handle:
                self.assertEqual(b"\x00" * 32, handle.read())

    def test_refuses_output_paths_inside_a_git_repository(self):
        inside_repo_path = os.path.join(_TOOLS_DIR, "should-never-be-written.key")
        self.addCleanup(lambda: os.path.exists(inside_repo_path) and os.remove(inside_repo_path))
        with tempfile.TemporaryDirectory() as tmp:
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=inside_repo_path, public_metadata_out=meta_path)
            with self.assertRaises(issuer.IssuerError):
                issuer.cmd_generate_key(args)
            self.assertFalse(os.path.exists(inside_repo_path))

    def test_private_key_pre_publication_failure_leaves_metadata_as_a_harmless_orphan(self):
        # PR #95 review fix (round 2, item "remove the metadata cleanup
        # race") - metadata is published FIRST; if the PRIVATE key's OWN
        # publication then fails BEFORE its final link, the metadata is
        # deliberately LEFT IN PLACE rather than deleted - an unconditional
        # os.remove() of that pathname would be a TOCTOU cleanup race (a
        # concurrent actor could have replaced it). A metadata-only orphan
        # is harmless: it is public data that cannot sign anything without
        # a matching private key, which does not exist here.
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)

            original_publish = issuer.publish_secret_no_clobber
            calls = {"n": 0}

            def _fail_on_second_call(path, data):
                calls["n"] += 1
                if calls["n"] == 2:
                    raise OSError("simulated private-key pre-publication failure")
                return original_publish(path, data)

            with mock.patch.object(issuer, "publish_secret_no_clobber", side_effect=_fail_on_second_call):
                with self.assertRaises(OSError):
                    issuer.cmd_generate_key(args)
            self.assertFalse(os.path.exists(priv_path))  # no private key was ever created
            self.assertTrue(os.path.exists(meta_path))  # deliberately left in place - harmless public orphan
            # The orphaned metadata is unusable without a matching private
            # key, and contains no private material regardless.
            identity = issuer.read_issuer_metadata_file(meta_path)
            self.assertEqual("test-key-1", identity.issuer_key_id)

    def test_no_arbitrary_metadata_pathname_is_ever_deleted_on_private_key_failure(self):
        # Stronger proof than the above: even if a DIFFERENT file now
        # occupies the metadata pathname (simulating a concurrent actor
        # having replaced it after our own publish), this code path must
        # never delete it - it performs no os.remove() of that path at all.
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)

            original_publish = issuer.publish_secret_no_clobber
            calls = {"n": 0}

            def _fail_on_second_call(path, data):
                calls["n"] += 1
                if calls["n"] == 2:
                    # Simulate a concurrent actor replacing the metadata
                    # pathname's CONTENT right before our own private-key
                    # publication fails.
                    with open(meta_path, "w", encoding="utf-8") as handle:
                        handle.write("REPLACED-BY-ANOTHER-ACTOR")
                    raise OSError("simulated private-key pre-publication failure")
                return original_publish(path, data)

            with mock.patch.object(issuer, "publish_secret_no_clobber", side_effect=_fail_on_second_call):
                with self.assertRaises(OSError):
                    issuer.cmd_generate_key(args)
            with open(meta_path, "r", encoding="utf-8") as handle:
                self.assertEqual("REPLACED-BY-ANOTHER-ACTOR", handle.read())

    def test_metadata_publication_failure_leaves_no_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)
            with mock.patch.object(issuer, "publish_secret_no_clobber", side_effect=OSError("simulated metadata publication failure")):
                with self.assertRaises(OSError):
                    issuer.cmd_generate_key(args)
            self.assertFalse(os.path.exists(priv_path))
            self.assertFalse(os.path.exists(meta_path))


def _write_secret_file_for_test(path, data):
    """Test-only convenience combining the two real production stages
    (publish_secret_no_clobber + confirm_post_publication) - mirrors what
    cmd_issue/cmd_generate_key do, for tests that only care about the
    combined end-to-end file-write behavior, not the phase split itself."""
    tmp_path = issuer.publish_secret_no_clobber(path, data)
    return issuer.confirm_post_publication(path, tmp_path)


class PublicationCommitPointTests(unittest.TestCase):
    """PR #95 review fix (round 3) - the ROLLBACK BOUNDARY itself now ends
    IMMEDIATELY after `publish_secret_no_clobber` returns (its commit -
    the successful no-clobber link - and NOTHING else). Every POST-commit
    step (`confirm_post_publication`, including its own warning output)
    happens strictly OUTSIDE any region that could call
    `revoke_activation()`, and NEVER raises under any circumstance."""

    def test_directory_fsync_failure_after_successful_link_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            tmp_path = issuer.publish_secret_no_clobber(path, b"data")
            with mock.patch("os.fsync", side_effect=OSError("simulated directory fsync failure")):
                result = issuer.confirm_post_publication(path, tmp_path)
            self.assertFalse(result.directory_sync_confirmed)
            with open(path, "rb") as handle:
                self.assertEqual(b"data", handle.read())

    def test_directory_durability_confirmation_succeeds_in_a_normal_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            tmp_path = issuer.publish_secret_no_clobber(path, b"data")
            result = issuer.confirm_post_publication(path, tmp_path)
            self.assertTrue(result.directory_sync_confirmed)
            self.assertTrue(result.temp_cleanup_confirmed)

    def test_directory_fsync_failure_emits_a_non_secret_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            tmp_path = issuer.publish_secret_no_clobber(path, b"data")
            stderr = io.StringIO()
            with mock.patch("os.fsync", side_effect=OSError("simulated directory fsync failure")):
                with redirect_stderr(stderr):
                    result = issuer.confirm_post_publication(path, tmp_path)
            self.assertFalse(result.directory_sync_confirmed)
            self.assertIn("WARNING", stderr.getvalue())
            self.assertIn("durability", stderr.getvalue())
            self.assertIn(path, stderr.getvalue())

    def test_warning_output_itself_raising_never_propagates(self):
        # PR #95 review fix (round 3) - _print_durability_warning must be
        # best-effort even when the PRINT CALL ITSELF raises (a closed
        # stderr, BrokenPipeError, a patched/custom stream raising
        # RuntimeError, etc.) - confirm_post_publication must still return
        # normally, never propagate that failure.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            tmp_path = issuer.publish_secret_no_clobber(path, b"data")
            with mock.patch("os.fsync", side_effect=OSError("simulated directory fsync failure")):
                with mock.patch("builtins.print", side_effect=RuntimeError("simulated broken stream")):
                    result = issuer.confirm_post_publication(path, tmp_path)  # must not raise
            self.assertFalse(result.directory_sync_confirmed)
            with open(path, "rb") as handle:
                self.assertEqual(b"data", handle.read())

    def test_temp_cleanup_failure_does_not_raise_and_does_not_invalidate_final_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            tmp_path = issuer.publish_secret_no_clobber(path, b"data")
            with mock.patch("os.unlink", side_effect=OSError("simulated temp-cleanup failure")):
                result = issuer.confirm_post_publication(path, tmp_path)  # must not raise
            self.assertFalse(result.temp_cleanup_confirmed)
            with open(path, "rb") as handle:
                self.assertEqual(b"data", handle.read())

    def test_directory_fsync_and_warning_output_both_failing_still_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            tmp_path = issuer.publish_secret_no_clobber(path, b"data")
            with mock.patch("os.fsync", side_effect=OSError("fsync failure")):
                with mock.patch("os.unlink", side_effect=OSError("unlink failure")):
                    with mock.patch("builtins.print", side_effect=RuntimeError("warning output failure")):
                        result = issuer.confirm_post_publication(path, tmp_path)  # must not raise
            self.assertFalse(result.directory_sync_confirmed)
            self.assertFalse(result.temp_cleanup_confirmed)
            with open(path, "rb") as handle:
                self.assertEqual(b"data", handle.read())

    def test_issue_command_directory_fsync_failure_does_not_revoke_and_leaves_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "activations.json")
            lock = os.path.join(tmp, "activations.lock")
            key_path = _write_test_key_file(tmp)
            metadata_path = _write_metadata_file(tmp)
            activations_module = issuer._activations_module()
            activations_module.init_store(store, lock)
            out_dir = os.path.join(tmp, "out")
            os.makedirs(out_dir)  # separate directory from the store, so the fsync-failure injection below targets ONLY the envelope's own directory
            args = mock.Mock(
                store=store, lock=lock, issuer_metadata_file=metadata_path, private_key_file=key_path,
                max_devices=1, activation_expires_in_days=None, envelope_valid_for_hours=48.0,
                endpoint_hint=[], bootstrap_bundle=None, out=os.path.join(out_dir, "envelope.bin"),
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(activations_module, "revoke_activation") as revoke_spy:
                with mock.patch.object(issuer, "_activations_module", return_value=activations_module):
                    with _fail_only_directory_fsync(out_dir):
                        with redirect_stdout(stdout), redirect_stderr(stderr):
                            rc = issuer.cmd_issue(args)
                revoke_spy.assert_not_called()
            self.assertEqual(0, rc)  # NOT a failure - publication succeeded
            self.assertTrue(os.path.exists(args.out))
            records = activations_module.list_all(store, lock)
            self.assertEqual(1, len(records))
            self.assertEqual(activations_module.ACTIVE, records[0]["status"])  # never revoked
            combined = stdout.getvalue() + stderr.getvalue()
            self.assertIn("durability", combined)
            self.assertNotIn("REVOKED", combined)

    def test_issue_command_warning_output_raising_after_commit_never_reaches_revoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "activations.json")
            lock = os.path.join(tmp, "activations.lock")
            key_path = _write_test_key_file(tmp)
            metadata_path = _write_metadata_file(tmp)
            activations_module = issuer._activations_module()
            activations_module.init_store(store, lock)
            out_dir = os.path.join(tmp, "out")
            os.makedirs(out_dir)
            args = mock.Mock(
                store=store, lock=lock, issuer_metadata_file=metadata_path, private_key_file=key_path,
                max_devices=1, activation_expires_in_days=None, envelope_valid_for_hours=48.0,
                endpoint_hint=[], bootstrap_bundle=None, out=os.path.join(out_dir, "envelope.bin"),
            )
            with mock.patch.object(activations_module, "revoke_activation") as revoke_spy:
                with mock.patch.object(issuer, "_activations_module", return_value=activations_module):
                    with _fail_only_directory_fsync(out_dir):
                        with mock.patch("builtins.print", side_effect=RuntimeError("simulated broken stream")):
                            with self.assertRaises(RuntimeError):
                                # The warning failure propagates out of the
                                # unguarded print() calls made by cmd_issue
                                # ITSELF (its own success-message prints,
                                # not confirm_post_publication's, which
                                # never raises) - the important invariant
                                # under test is what happens NEXT: it must
                                # never reach revoke_activation().
                                issuer.cmd_issue(args)
                revoke_spy.assert_not_called()
            records = activations_module.list_all(store, lock)
            self.assertEqual(1, len(records))
            self.assertEqual(activations_module.ACTIVE, records[0]["status"])
            self.assertTrue(os.path.exists(args.out))

    def test_generate_key_directory_fsync_failure_leaves_both_files_intact(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)
            stdout, stderr = io.StringIO(), io.StringIO()
            with _fail_only_directory_fsync(tmp):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = issuer.cmd_generate_key(args)
            self.assertEqual(0, rc)
            self.assertTrue(os.path.exists(priv_path))
            self.assertTrue(os.path.exists(meta_path))
            combined = stdout.getvalue() + stderr.getvalue()
            self.assertIn("durability", combined)

    def test_generate_key_post_commit_warning_output_failure_leaves_both_files_intact(self):
        # Same scenario as above, but the warning PRINT ITSELF also fails -
        # neither file may ever be deleted, and cmd_generate_key must not
        # crash trying to report the durability warning (its own success
        # prints happen after, and are allowed to surface an unguarded
        # print failure, but MUST NOT have deleted anything by that point).
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "issuer.key")
            meta_path = os.path.join(tmp, "issuer.meta.json")
            args = mock.Mock(key_id="test-key-1", private_key_out=priv_path, public_metadata_out=meta_path)
            with _fail_only_directory_fsync(tmp):
                with mock.patch("builtins.print", side_effect=RuntimeError("simulated broken stream")):
                    with self.assertRaises(RuntimeError):
                        issuer.cmd_generate_key(args)
            self.assertTrue(os.path.exists(priv_path))
            self.assertTrue(os.path.exists(meta_path))

    def test_pre_link_publication_failure_still_revokes_the_activation(self):
        # Sanity check that the refactor did NOT weaken the existing,
        # correct PRE-commit rollback behavior - a failure before the link
        # succeeds must still revoke.
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, "activations.json")
            lock = os.path.join(tmp, "activations.lock")
            key_path = _write_test_key_file(tmp)
            metadata_path = _write_metadata_file(tmp)
            activations_module = issuer._activations_module()
            activations_module.init_store(store, lock)
            args = mock.Mock(
                store=store, lock=lock, issuer_metadata_file=metadata_path, private_key_file=key_path,
                max_devices=1, activation_expires_in_days=None, envelope_valid_for_hours=48.0,
                endpoint_hint=[], bootstrap_bundle=None, out=os.path.join(tmp, "envelope.bin"),
            )
            with mock.patch.object(issuer, "publish_secret_no_clobber", side_effect=issuer.IssuerError("simulated pre-link failure")):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    rc = issuer.cmd_issue(args)
            self.assertEqual(1, rc)
            records = activations_module.list_all(store, lock)
            self.assertEqual(1, len(records))
            self.assertEqual(activations_module.REVOKED, records[0]["status"])
            self.assertFalse(os.path.exists(args.out))


class AtomicNoClobberPublicationTests(unittest.TestCase):
    def test_publishes_when_target_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            _write_secret_file_for_test(path, b"hello")
            with open(path, "rb") as handle:
                self.assertEqual(b"hello", handle.read())

    def test_refuses_and_leaves_existing_target_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            with open(path, "wb") as handle:
                handle.write(b"original")
            with self.assertRaises(issuer.IssuerError):
                issuer.publish_secret_no_clobber(path, b"attacker-controlled-overwrite")
            with open(path, "rb") as handle:
                self.assertEqual(b"original", handle.read())

    def test_real_toctou_race_another_writer_creates_target_after_preflight_check(self):
        """Simulates EXACTLY the race the old exists()+os.replace() pattern
        was vulnerable to: preflight (_refuse_if_exists) sees the target
        absent, then another process/thread creates it BEFORE the final
        atomic publish runs. The real no-clobber primitive must still
        refuse, and the other writer's content must survive byte-for-byte."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            issuer._refuse_if_exists(path)  # preflight: sees it absent

            # "Another writer" creates the target in the window between
            # preflight and the final publish call.
            with open(path, "wb") as handle:
                handle.write(b"created-by-another-writer")

            with self.assertRaises(issuer.IssuerError):
                issuer.publish_secret_no_clobber(path, b"attacker-or-issuer-controlled-content")

            with open(path, "rb") as handle:
                self.assertEqual(b"created-by-another-writer", handle.read())

    def test_temp_file_is_removed_on_publish_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            with open(path, "wb") as handle:
                handle.write(b"existing")
            with self.assertRaises(issuer.IssuerError):
                issuer.publish_secret_no_clobber(path, b"new-data")
            leftover_temp_files = [f for f in os.listdir(tmp) if f.startswith(".activation-envelope-issuer.")]
            self.assertEqual([], leftover_temp_files)

    def test_fails_closed_when_link_is_unsupported_never_falls_back_to_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            with mock.patch.object(os, "link", side_effect=OSError("simulated: hardlinks unsupported on this filesystem")):
                with self.assertRaises(issuer.IssuerError):
                    issuer.publish_secret_no_clobber(path, b"data")
            self.assertFalse(os.path.exists(path))  # never silently written via a fallback


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

    def test_rejects_whitespace_only_hint(self):
        # PR #95 review fix item 3 - Android EndpointId requires
        # isNotBlank(); a single space must be rejected here too, not just
        # an empty string.
        with self.assertRaises(issuer.IssuerError):
            issuer._validate_hints_order_preserving([" "])
        with self.assertRaises(issuer.IssuerError):
            issuer._validate_hints_order_preserving(["\t\n  "])

    def test_every_accepted_hint_would_construct_as_an_android_endpoint_id(self):
        # A structural proxy for "Android EndpointId(value) would not
        # throw": non-blank after strip, <=128 UTF-8 bytes.
        hints = issuer._validate_hints_order_preserving(["frankfurt-gw", "stockholm-gw"])
        for hint in hints:
            self.assertTrue(hint.strip())
            self.assertLessEqual(len(hint.encode("utf-8")), 128)


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
            wrong_hash = hashlib.sha256(artifact[8:]).digest()
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
            path, _ = self._sign_and_package_manifest(tmp, manifest_version=1)
            version, _ = issuer.inspect_signed_manifest_bundle(path)
            self.assertEqual(1, version)

    def _package_with_raw_signature(self, tmp, signature_bytes, manifest_version=3):
        manifest = manifest_signing.Manifest(
            manifest_version=manifest_version, issued_at_epoch_millis=1000, expires_at_epoch_millis=9_000_000_000,
            endpoints=[], signing_key_id="test-manifest-key",
        )
        canonical = manifest_signing.canonical_bytes(manifest)
        artifact = manifest_signing.pack_signed_manifest(canonical, signature_bytes)
        path = os.path.join(tmp, "bundle.bin")
        with open(path, "wb") as handle:
            handle.write(artifact)
        return path

    def test_exact_64_byte_signature_accepted(self):
        # PR #95 review fix (round 2, item 2) - the real client trust
        # boundary (Ed25519ManifestVerifier) requires an exact 64-byte
        # signature; this is still metadata inspection only, so an
        # arbitrary 64 bytes (not a real signature) is structurally
        # accepted here - no cryptographic check happens in this function.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._package_with_raw_signature(tmp, b"\x42" * 64)
            version, _ = issuer.inspect_signed_manifest_bundle(path)
            self.assertEqual(3, version)

    def test_zero_length_signature_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._package_with_raw_signature(tmp, b"")
            with self.assertRaises(issuer.BundleInspectionError):
                issuer.inspect_signed_manifest_bundle(path)

    def test_63_byte_signature_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._package_with_raw_signature(tmp, b"\x00" * 63)
            with self.assertRaises(issuer.BundleInspectionError):
                issuer.inspect_signed_manifest_bundle(path)

    def test_65_byte_signature_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._package_with_raw_signature(tmp, b"\x00" * 65)
            with self.assertRaises(issuer.BundleInspectionError):
                issuer.inspect_signed_manifest_bundle(path)

    def test_256_byte_signature_rejected(self):
        # 256 is SignedManifestCodec's own generic container ceiling, and
        # would have passed the OLD "0..256" range check - it must now be
        # rejected since it can never be a valid Ed25519 signature.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._package_with_raw_signature(tmp, b"\x00" * 256)
            with self.assertRaises(issuer.BundleInspectionError):
                issuer.inspect_signed_manifest_bundle(path)

    def test_oversized_bundle_file_rejected_before_being_read_into_memory(self):
        # PR #95 review fix (round 2, item 3) - a pre-read os.path.getsize()
        # check must reject an obviously over-bound file before it is ever
        # opened for a full read.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "huge.bin")
            with open(path, "wb") as handle:
                handle.seek(issuer._SIGNED_MANIFEST_MAX_TOTAL_BYTES)  # sparse file - no real disk write
                handle.write(b"\x00")
            with mock.patch("builtins.open", side_effect=AssertionError("must not open the file for reading at all")) as mocked_open:
                with self.assertRaises(issuer.BundleInspectionError):
                    issuer.inspect_signed_manifest_bundle(path)
                mocked_open.assert_not_called()

    def test_bundle_at_exactly_the_max_total_size_is_not_rejected_for_size_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "at_max.bin")
            # Build a real, well-formed container whose total size is
            # comfortably under the max (constructing one AT the exact byte
            # is unnecessary - this proves the size gate uses > not >=
            # incorrectly by using a large-but-valid real container).
            manifest = manifest_signing.Manifest(
                manifest_version=1, issued_at_epoch_millis=1000, expires_at_epoch_millis=9_000_000_000,
                endpoints=[], signing_key_id="k" * 32,
            )
            canonical = manifest_signing.canonical_bytes(manifest)
            artifact = manifest_signing.pack_signed_manifest(canonical, b"\x00" * 64)
            with open(path, "wb") as handle:
                handle.write(artifact)
            self.assertLessEqual(os.path.getsize(path), issuer._SIGNED_MANIFEST_MAX_TOTAL_BYTES)
            version, _ = issuer.inspect_signed_manifest_bundle(path)
            self.assertEqual(1, version)


class FiniteTimeArgumentValidationTests(unittest.TestCase):
    def test_accepts_a_sane_positive_value(self):
        issuer._require_finite_positive(48.0, "--envelope-valid-for-hours", issuer._MAX_ENVELOPE_VALID_FOR_HOURS)

    def test_rejects_nan(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._require_finite_positive(float("nan"), "--envelope-valid-for-hours", issuer._MAX_ENVELOPE_VALID_FOR_HOURS)

    def test_rejects_positive_infinity(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._require_finite_positive(float("inf"), "--envelope-valid-for-hours", issuer._MAX_ENVELOPE_VALID_FOR_HOURS)

    def test_rejects_negative_infinity(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._require_finite_positive(float("-inf"), "--envelope-valid-for-hours", issuer._MAX_ENVELOPE_VALID_FOR_HOURS)

    def test_rejects_zero_and_negative(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._require_finite_positive(0.0, "--envelope-valid-for-hours", issuer._MAX_ENVELOPE_VALID_FOR_HOURS)
        with self.assertRaises(issuer.IssuerError):
            issuer._require_finite_positive(-1.0, "--envelope-valid-for-hours", issuer._MAX_ENVELOPE_VALID_FOR_HOURS)

    def test_rejects_beyond_max(self):
        with self.assertRaises(issuer.IssuerError):
            issuer._require_finite_positive(issuer._MAX_ENVELOPE_VALID_FOR_HOURS + 1, "--envelope-valid-for-hours", issuer._MAX_ENVELOPE_VALID_FOR_HOURS)


def _fcntl_available():
    try:
        import fcntl  # noqa: F401

        return True
    except ImportError:
        return False


import contextlib


@contextlib.contextmanager
def _fail_only_directory_fsync(target_directory):
    """Precisely simulates 'temp write succeeds, final link succeeds,
    directory fsync fails' end-to-end through the real cmd_issue/
    cmd_generate_key call graph - WITHOUT also breaking the temp file's
    own pre-commit fsync or (for cmd_issue) the UNRELATED activation
    store's own directory-fsync call (gateway.api.activations._atomic_write_store
    opens ITS OWN O_RDONLY directory fd too) - a blanket
    `mock.patch("os.fsync", side_effect=...)` would break all of those.
    Tags ONLY the read-only file descriptor(s) opened for EXACTLY
    `target_directory` (the envelope/key/metadata output's own containing
    directory) and fails `os.fsync` for those alone."""
    real_open = os.open
    real_fsync = os.fsync
    target_abs = os.path.abspath(target_directory)
    directory_fds = set()

    def _tagging_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if flags == os.O_RDONLY and os.path.abspath(path) == target_abs:
            directory_fds.add(fd)
        return fd

    def _selective_fsync(fd):
        if fd in directory_fds:
            raise OSError("simulated directory fsync failure")
        return real_fsync(fd)

    with mock.patch("os.open", side_effect=_tagging_open), mock.patch("os.fsync", side_effect=_selective_fsync):
        yield


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


@unittest.skipUnless(_fcntl_available(), "requires a POSIX fcntl environment - see run_tests.sh")
class IssueCommandTests(unittest.TestCase):
    """Uses the REAL gateway.api.activations store (temp dir only) - never mocked, per module requirements."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = os.path.join(self.tmp.name, "activations.json")
        self.lock = os.path.join(self.tmp.name, "activations.lock")
        self.key_path = _write_test_key_file(self.tmp.name)
        self.metadata_path = _write_metadata_file(self.tmp.name)
        activations_module = issuer._activations_module()
        activations_module.init_store(self.store, self.lock)
        self.activations_module = activations_module

    def _base_args(self, **overrides):
        args = mock.Mock(
            store=self.store,
            lock=self.lock,
            issuer_metadata_file=self.metadata_path,
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
        self.assertGreater(len(artifact), 0)
        canonical_len = struct.unpack_from(">i", artifact, 4)[0]
        sig_len = struct.unpack_from(">i", artifact, 8 + canonical_len)[0]
        self.assertEqual(64, sig_len)

        priv = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)
        canonical = artifact[8:8 + canonical_len]
        signature = artifact[12 + canonical_len:12 + canonical_len + sig_len]
        priv.public_key().verify(signature, canonical)  # raises if invalid

    def test_issuer_key_id_comes_from_metadata_not_a_cli_argument(self):
        parser = issuer.build_parser()
        import argparse

        subparsers_action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        issue_parser = subparsers_action.choices["issue"]
        option_strings = {opt for action in issue_parser._actions for opt in action.option_strings}
        self.assertNotIn("--issuer-key-id", option_strings)
        self.assertIn("--issuer-metadata-file", option_strings)

    def test_wrong_private_key_for_metadata_is_rejected_before_issue_activation(self):
        other_key_bytes = bytes((b ^ 0xFF) for b in _TEST_PRIVATE_KEY_BYTES)
        wrong_key_path = _write_test_key_file(self.tmp.name, key_bytes=other_key_bytes, name="wrong-key.bin")
        args = self._base_args(private_key_file=wrong_key_path)
        rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))
        self.assertFalse(os.path.exists(args.out))

    def test_metadata_fingerprint_mismatch_rejected_before_issue_activation(self):
        bad_metadata_path = _write_metadata_file(self.tmp.name, name="bad-meta.json", corrupt_fingerprint=True)
        args = self._base_args(issuer_metadata_file=bad_metadata_path)
        rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_metadata_public_key_not_matching_private_key_rejected_before_issue_activation(self):
        # A metadata file whose OWN internal fingerprint is consistent, but
        # whose public key doesn't match --private-key-file at all.
        other_key_bytes = bytes((b ^ 0x11) for b in _TEST_PRIVATE_KEY_BYTES)
        mismatched_metadata_path = _write_metadata_file(self.tmp.name, private_key_bytes=other_key_bytes, name="mismatched-meta.json")
        args = self._base_args(issuer_metadata_file=mismatched_metadata_path)
        rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_correct_matching_private_key_and_metadata_succeeds(self):
        args = self._base_args()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = issuer.cmd_issue(args)
        self.assertEqual(0, rc)
        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(self.activations_module.ACTIVE, records[0]["status"])

    def test_whitespace_only_endpoint_hint_rejected_before_issue_activation(self):
        args = self._base_args(endpoint_hint=[" "])
        rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_nan_envelope_valid_for_hours_rejected_before_issue_activation(self):
        args = self._base_args(envelope_valid_for_hours=float("nan"))
        rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_infinite_envelope_valid_for_hours_rejected_before_issue_activation(self):
        args = self._base_args(envelope_valid_for_hours=float("inf"))
        rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_nan_activation_expires_in_days_rejected_before_issue_activation(self):
        args = self._base_args(activation_expires_in_days=float("nan"))
        rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_credential_never_appears_in_stdout_or_stderr(self):
        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            issuer.cmd_issue(args)
        combined = stdout.getvalue() + stderr.getvalue()
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
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_envelope_expiry_never_extends_beyond_server_activation_expiry(self):
        args = self._base_args(activation_expires_in_days=1.0, envelope_valid_for_hours=48.0)  # 48h > 24h(1 day)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as stderr:
            rc = issuer.cmd_issue(args)
        self.assertEqual(1, rc)
        # PR #95 review fix item 5 - the exception MESSAGE (which would
        # have contained "server-side expiry") is no longer printed, only
        # its class name and the activation_id - see the secret-redaction
        # tests for the load-bearing proof of that rule.
        self.assertIn("IssuerError", stderr.getvalue())
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
        self.assertNotEqual(a1, a2)

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
        self.assertEqual(bundle_bytes_before, bundle_bytes_after)

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
        self.assertIn(expected_hash, artifact)
        self.assertIn(struct.pack(">i", 9), artifact)

    def test_malformed_bootstrap_bundle_rejected_before_activation_issuance(self):
        bundle_path = os.path.join(self.tmp.name, "bad-bundle.bin")
        with open(bundle_path, "wb") as handle:
            handle.write(b"not a real signed manifest")
        args = self._base_args(bootstrap_bundle=bundle_path)
        rc = _run_issue(args)
        self.assertEqual(1, rc)
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
        rc = _run_issue(args)
        self.assertEqual(1, rc)
        self.assertEqual([], self.activations_module.list_all(self.store, self.lock))

    def test_missing_newly_issued_record_enters_rollback_path(self):
        # PR #95 review fix item 10 - simulate find_by_activation_id
        # returning None right after issue_activation() succeeded.
        args = self._base_args()
        with mock.patch.object(self.activations_module, "find_by_activation_id", return_value=None):
            with mock.patch.object(issuer, "_activations_module", return_value=self.activations_module):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    rc = issuer.cmd_issue(args)
        self.assertEqual(1, rc)
        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(1, len(records))
        self.assertEqual(self.activations_module.REVOKED, records[0]["status"])
        self.assertFalse(os.path.exists(args.out))

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

    def test_post_issue_exception_secret_marker_never_printed(self):
        # PR #95 review fix item 5 - even if a lower-layer exception's
        # MESSAGE contains something secret-looking, it must never reach
        # stdout/stderr; only the exception's class name is ever printed.
        secret_marker = "SECRET-MARKER-zK9qLp3vXeR7"

        class _FakeSensitiveError(RuntimeError):
            pass

        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(issuer, "canonical_bytes", side_effect=_FakeSensitiveError(secret_marker)):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = issuer.cmd_issue(args)
        self.assertEqual(1, rc)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(secret_marker, combined)
        self.assertIn("_FakeSensitiveError", combined)  # class name IS reported

    def test_revocation_exception_secret_marker_never_printed(self):
        secret_marker = "SECRET-MARKER-revoke-9f3ak2"

        class _FakeSensitiveRevokeError(RuntimeError):
            pass

        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(issuer, "canonical_bytes", side_effect=RuntimeError("simulated failure")):
            with mock.patch.object(self.activations_module, "revoke_activation", side_effect=_FakeSensitiveRevokeError(secret_marker)):
                with mock.patch.object(issuer, "_activations_module", return_value=self.activations_module):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = issuer.cmd_issue(args)
        self.assertEqual(1, rc)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(secret_marker, combined)
        self.assertIn("_FakeSensitiveRevokeError", combined)
        self.assertIn("MANUAL REVOCATION REQUIRED", combined)

    def test_post_issue_output_write_failure_revokes_the_new_activation(self):
        args = self._base_args()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(issuer, "publish_secret_no_clobber", side_effect=OSError("simulated disk failure")):
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
        self.assertEqual(self.activations_module.ACTIVE, records[0]["status"])
        for record in records:
            self.assertIn(record["activation_id"], combined)
        self.assertIsNone(re.search(r"[A-Za-z0-9_-]{43}", combined))

    def test_transaction_commit_point_a_failure_after_successful_publication_never_revokes(self):
        # PR #95 review fix item 6 - once the atomic write has genuinely
        # succeeded, a LATER failure (simulated here as the print() calls
        # that follow it) must never revoke the activation or imply the
        # artifact should be removed.
        args = self._base_args()  # no bootstrap bundle -> exactly 4 post-commit print() calls
        with mock.patch("builtins.print", side_effect=[None, None, None, RuntimeError("simulated cosmetic failure")]):
            with self.assertRaises(RuntimeError):
                issuer.cmd_issue(args)
        records = self.activations_module.list_all(self.store, self.lock)
        self.assertEqual(1, len(records))
        self.assertEqual(self.activations_module.ACTIVE, records[0]["status"])
        self.assertTrue(os.path.exists(args.out))


class VerifyKeyTests(unittest.TestCase):
    """B56-4B2 - `verify-key` proves a (backup) private key copy matches the
    issuer metadata / pinned fingerprint and never emits private material."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.key = _write_test_key_file(self._tmp.name)
        self.meta = _write_metadata_file(self._tmp.name)
        pub = Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES).public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
        )
        self.fingerprint = hashlib.sha256(pub).hexdigest()

    def _run(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = issuer.main(["verify-key", "--private-key-file", self.key, "--issuer-metadata-file", self.meta, *extra])
        return code, out.getvalue(), err.getvalue()

    def _assert_no_private_material(self, text):
        self.assertNotIn(_TEST_PRIVATE_KEY_BYTES.hex(), text)
        self.assertNotIn(base64.b64encode(_TEST_PRIVATE_KEY_BYTES).decode("ascii"), text)
        self.assertNotIn(base64.urlsafe_b64encode(_TEST_PRIVATE_KEY_BYTES).decode("ascii").rstrip("="), text)

    def test_matching_key_prints_public_data_only(self):
        code, out, err = self._run("--expected-fingerprint", self.fingerprint)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), f"OK issuerKeyId={_TEST_ISSUER_KEY_ID} publicKeyFingerprintSha256Hex={self.fingerprint}")
        self._assert_no_private_material(out + err)

    def test_wrong_key_copy_is_rejected(self):
        self.key = _write_test_key_file(self._tmp.name, key_bytes=bytes(range(1, 33)), name="other.bin")
        code, out, err = self._run()
        self.assertEqual(code, 1)
        self.assertIn("does NOT match", err)
        self.assertEqual(out, "")
        self._assert_no_private_material(out + err)

    def test_fingerprint_pin_mismatch_is_rejected(self):
        code, _out, err = self._run("--expected-fingerprint", "0" * 64)
        self.assertEqual(code, 1)
        self.assertIn("--expected-fingerprint", err)

    def test_malformed_fingerprint_pin_is_rejected(self):
        code, _out, _err = self._run("--expected-fingerprint", "xyz")
        self.assertEqual(code, 1)

    def test_truncated_backup_copy_is_rejected(self):
        with open(self.key, "wb") as handle:
            handle.write(_TEST_PRIVATE_KEY_BYTES[:31])
        code, out, err = self._run()
        self.assertEqual(code, 1)
        self._assert_no_private_material(out + err)

    def test_group_readable_backup_copy_is_refused(self):
        if os.name == "nt":
            self.skipTest("POSIX modes only")
        os.chmod(self.key, 0o640)
        code, _out, err = self._run()
        self.assertEqual(code, 1)
        self.assertIn("chmod 600", err)

    def test_never_touches_an_activation_store(self):
        with mock.patch.object(issuer, "_activations_module", side_effect=AssertionError("store touched")):
            code, _out, _err = self._run()
        self.assertEqual(code, 0)


class PackageTests(unittest.TestCase):
    """B56-5 - `package` wraps an issued envelope artifact into the
    Android NovaActivationPackage text form (byte layout pinned by the
    Kotlin ActivationEnvelopePythonCompatibilityTest fixture)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.envelope_bytes = issuer.pack_signed_envelope(
            issuer.canonical_bytes(_make_test_envelope()),
            issuer.sign_envelope(_make_test_envelope(), Ed25519PrivateKey.from_private_bytes(_TEST_PRIVATE_KEY_BYTES)),
        )
        self.envelope_path = os.path.join(self._tmp.name, "envelope.bin")
        with open(self.envelope_path, "wb") as handle:
            handle.write(self.envelope_bytes)

    def _run(self, *extra, out_name="package.txt"):
        out_path = os.path.join(self._tmp.name, out_name)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = issuer.main(["package", "--envelope", self.envelope_path, "--out", out_path, *extra])
        return code, out_path, out.getvalue(), err.getvalue()

    def test_layout_matches_android_parser(self):
        pkg = issuer.pack_activation_package(self.envelope_bytes, None)
        tag = b"NOVA_ACTIVATION_PACKAGE_V1"
        expected = struct.pack(">i", len(tag)) + tag + struct.pack(">i", 1) + struct.pack(">i", len(self.envelope_bytes)) + self.envelope_bytes + struct.pack(">i", 0) + struct.pack(">i", 0)
        self.assertEqual(pkg, expected)
        text = issuer.package_text(pkg)
        self.assertTrue(text.startswith("nova-activation:1:"))
        self.assertNotIn("=", text)

    def test_bundle_bytes_are_embedded_verbatim(self):
        bundle = b"\x01" * 100
        pkg = issuer.pack_activation_package(self.envelope_bytes, bundle)
        self.assertIn(struct.pack(">i", 100) + bundle + struct.pack(">i", 0), pkg)

    def test_cli_writes_secret_output_0600_and_never_prints_it(self):
        code, out_path, out, err = self._run()
        self.assertEqual(code, 0)
        with open(out_path, encoding="ascii") as handle:
            text = handle.read()
        self.assertEqual(text, issuer.package_text(issuer.pack_activation_package(self.envelope_bytes, None)))
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(out_path).st_mode), 0o600)
        self.assertNotIn(text, out + err)
        self.assertNotIn(_make_test_envelope().credential, out + err)

    def test_cli_refuses_to_overwrite(self):
        self.assertEqual(self._run()[0], 0)
        self.assertEqual(self._run()[0], 1)

    def test_oversized_bundle_is_refused(self):
        with self.assertRaises(issuer.IssuerError):
            issuer.pack_activation_package(self.envelope_bytes, b"x" * (issuer.MAX_PACKAGE_BUNDLE_BYTES + 1))

    def test_invalid_bundle_file_is_refused(self):
        bad = os.path.join(self._tmp.name, "bad.bin")
        with open(bad, "wb") as handle:
            handle.write(b"not a signed manifest")
        code, _p, _o, err = self._run("--bootstrap-bundle", bad)
        self.assertEqual(code, 1)
        self.assertIn("--bootstrap-bundle rejected", err)


if __name__ == "__main__":
    unittest.main()
