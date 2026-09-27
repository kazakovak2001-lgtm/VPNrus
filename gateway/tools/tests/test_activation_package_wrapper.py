"""B56-7A - tests for gateway/tools/activation_package_wrapper.py.

Platform-independent (pure encoding, no `fcntl`/store/lock involvement at
all - this tool never touches an activation store). Uses ONLY a synthetic,
deterministic TEST-ONLY envelope - never a real production key, never a
real production envelope.

Compatibility proof strategy (Kotlin/Gradle is not available in this
environment - see module docstring): rather than invoking
NovaActivationPackage.kt directly, this suite (a) independently hand-builds
the EXPECTED wire bytes per the exact spec copied from that file's own
docstring, without ever calling the wrapper under test, and asserts the
wrapper's output matches byte-for-byte, and (b) independently re-implements
ActivationPackageParser.decode's own field-by-field validation (domain tag,
schema version, envelope/bundle/level2 length bounds, "no trailing bytes")
in this test file and asserts the wrapper's output round-trips through it
cleanly. Neither proof reuses the wrapper's own encoding logic.
"""
import base64
import hashlib
import os
import struct
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_GATEWAY_DIR = os.path.abspath(os.path.join(_TOOLS_DIR, ".."))
for _path in (_GATEWAY_DIR, _TOOLS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import activation_envelope_issuer as issuer  # noqa: E402
import activation_package_wrapper as wrapper  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

# Deterministic TEST-ONLY key - never a production key, never retained
# anywhere outside this process's memory.
_TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()


def _build_synthetic_envelope_bytes() -> bytes:
    """A synthetic, non-production, non-redeemable envelope artifact -
    signed with the TEST-ONLY key above, never activation_envelope_issuer's
    own `issue` command, never touching any activation store."""
    envelope = issuer.ActivationEnvelope(
        activation_id="0" * 32,
        credential="TEST_ONLY_SYNTHETIC_CREDENTIAL_NEVER_REDEEMABLE",
        issued_at_epoch_millis=1_700_000_000_000,
        not_before_epoch_millis=1_700_000_000_000,
        expires_at_epoch_millis=1_700_000_000_000 + 48 * 3600 * 1000,
        bootstrap_bundle_ref=None,
        bootstrap_endpoint_hints=(),
        bootstrap_capability_hint=None,
        nonce=b"\x00" * issuer.NONCE_LENGTH,
        issuer_key_id="test-only-issuer-key-id",
    )
    canonical = issuer.canonical_bytes(envelope)
    signature = _TEST_PRIVATE_KEY.sign(canonical)
    return issuer.pack_signed_envelope(canonical, signature)


def _independently_decode_package(package_bytes: bytes):
    """Standalone re-implementation of ActivationPackageParser.decode's own
    field-by-field checks (NovaActivationPackage.kt / that parser) - written
    independently of activation_package_wrapper.py's own encoder, so a bug
    shared between the two would NOT be masked."""
    off = 0

    def read_i32():
        nonlocal off
        (v,) = struct.unpack_from(">i", package_bytes, off)
        off += 4
        return v

    def read_bytes(n):
        nonlocal off
        b = package_bytes[off : off + n]
        off += n
        return b

    tag_len = read_i32()
    tag = read_bytes(tag_len)
    if tag != wrapper.DOMAIN_TAG.encode("utf-8"):
        raise AssertionError("domain tag mismatch")

    version = read_i32()
    if version != 1:
        raise AssertionError(f"unsupported schema version: {version}")

    envelope_len = read_i32()
    if not (1 <= envelope_len <= 32_768):
        raise AssertionError(f"envelope length out of bounds: {envelope_len}")
    envelope_bytes = read_bytes(envelope_len)

    bundle_len = read_i32()
    if not (0 <= bundle_len <= 262_144):
        raise AssertionError(f"bundle length out of bounds: {bundle_len}")
    bundle_bytes = read_bytes(bundle_len) if bundle_len else None

    level2_len = read_i32()
    if level2_len != 0:
        raise AssertionError("Level2NotSupported: level2SectionLength must be 0 in V1")

    if off != len(package_bytes):
        raise AssertionError(f"trailing bytes after Level-2 section: {len(package_bytes) - off}")

    return {
        "domain_tag": tag.decode("utf-8"),
        "schema_version": version,
        "envelope_bytes": envelope_bytes,
        "bundle_bytes": bundle_bytes,
        "level2_len": level2_len,
    }


class WrapEnvelopeBytesTests(unittest.TestCase):
    def test_wire_format_matches_hand_built_expected_bytes(self):
        envelope_bytes = _build_synthetic_envelope_bytes()

        domain_tag_bytes = "NOVA_ACTIVATION_PACKAGE_V1".encode("utf-8")
        expected = bytearray()
        expected += struct.pack(">i", len(domain_tag_bytes))
        expected += domain_tag_bytes
        expected += struct.pack(">i", 1)  # schemaVersion
        expected += struct.pack(">i", len(envelope_bytes))
        expected += envelope_bytes
        expected += struct.pack(">i", 0)  # bundleLength
        expected += struct.pack(">i", 0)  # level2SectionLength

        actual = wrapper.wrap_envelope_bytes(envelope_bytes)
        self.assertEqual(bytes(expected), actual)

    def test_envelope_bytes_embedded_verbatim(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        package_bytes = wrapper.wrap_envelope_bytes(envelope_bytes)
        decoded = _independently_decode_package(package_bytes)
        self.assertEqual(envelope_bytes, decoded["envelope_bytes"])

    def test_bundle_section_empty(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        package_bytes = wrapper.wrap_envelope_bytes(envelope_bytes)
        decoded = _independently_decode_package(package_bytes)
        self.assertIsNone(decoded["bundle_bytes"])

    def test_level2_section_empty(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        package_bytes = wrapper.wrap_envelope_bytes(envelope_bytes)
        decoded = _independently_decode_package(package_bytes)
        self.assertEqual(0, decoded["level2_len"])

    def test_schema_version_and_domain_tag(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        package_bytes = wrapper.wrap_envelope_bytes(envelope_bytes)
        decoded = _independently_decode_package(package_bytes)
        self.assertEqual(1, decoded["schema_version"])
        self.assertEqual("NOVA_ACTIVATION_PACKAGE_V1", decoded["domain_tag"])

    def test_empty_envelope_rejected(self):
        with self.assertRaises(wrapper.PackageWrapperError):
            wrapper.wrap_envelope_bytes(b"")

    def test_oversized_envelope_rejected(self):
        with self.assertRaises(wrapper.PackageWrapperError):
            wrapper.wrap_envelope_bytes(b"\x00" * (wrapper.MAX_ENVELOPE_BYTES + 1))


class EncodePackageTextTests(unittest.TestCase):
    def test_prefix_and_canonical_base64url(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        text = wrapper.encode_package_text(envelope_bytes)
        self.assertTrue(text.startswith("nova-activation:1:"))
        payload = text[len("nova-activation:1:") :]
        # No padding, URL-safe alphabet only.
        self.assertNotIn("=", payload)
        self.assertRegex(payload, r"^[A-Za-z0-9_-]+$")
        # Canonical: re-encoding the decoded bytes must reproduce the same string
        # (matches ActivationEnvelopeTextCodec/ActivationPackageParser's own
        # "reject non-canonical unused-bit aliases" discipline).
        decoded_bytes = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        reencoded = base64.urlsafe_b64encode(decoded_bytes).rstrip(b"=").decode("ascii")
        self.assertEqual(payload, reencoded)

    def test_deterministic_for_identical_input(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        text1 = wrapper.encode_package_text(envelope_bytes)
        text2 = wrapper.encode_package_text(envelope_bytes)
        self.assertEqual(text1, text2)

    def test_full_round_trip_through_independent_decoder(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        text = wrapper.encode_package_text(envelope_bytes)
        payload = text[len("nova-activation:1:") :]
        package_bytes = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        decoded = _independently_decode_package(package_bytes)
        self.assertEqual(envelope_bytes, decoded["envelope_bytes"])
        self.assertIsNone(decoded["bundle_bytes"])
        self.assertEqual(0, decoded["level2_len"])
        self.assertEqual(1, decoded["schema_version"])


class CliTests(unittest.TestCase):
    def test_reads_input_writes_output_file(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            envelope_path = os.path.join(tmp, "envelope.bin")
            out_path = os.path.join(tmp, "package.txt")
            with open(envelope_path, "wb") as f:
                f.write(envelope_bytes)

            rc = wrapper.main(["--envelope", envelope_path, "--out", out_path])
            self.assertEqual(0, rc)

            with open(out_path, "r", encoding="ascii") as f:
                text = f.read().strip()
            self.assertTrue(text.startswith("nova-activation:1:"))
            self.assertEqual(wrapper.encode_package_text(envelope_bytes), text)

    def test_refuses_to_overwrite_existing_output(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            envelope_path = os.path.join(tmp, "envelope.bin")
            out_path = os.path.join(tmp, "package.txt")
            with open(envelope_path, "wb") as f:
                f.write(envelope_bytes)
            with open(out_path, "w") as f:
                f.write("pre-existing")

            rc = wrapper.main(["--envelope", envelope_path, "--out", out_path])
            self.assertEqual(1, rc)
            with open(out_path, "r") as f:
                self.assertEqual("pre-existing", f.read())

    def test_refuses_missing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "package.txt")
            rc = wrapper.main(["--envelope", os.path.join(tmp, "does-not-exist.bin"), "--out", out_path])
            self.assertEqual(1, rc)
            self.assertFalse(os.path.exists(out_path))

    def test_refuses_empty_input_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            envelope_path = os.path.join(tmp, "empty.bin")
            out_path = os.path.join(tmp, "package.txt")
            open(envelope_path, "wb").close()
            rc = wrapper.main(["--envelope", envelope_path, "--out", out_path])
            self.assertEqual(1, rc)
            self.assertFalse(os.path.exists(out_path))

    def test_refuses_output_inside_git_repo(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            envelope_path = os.path.join(tmp, "envelope.bin")
            with open(envelope_path, "wb") as f:
                f.write(envelope_bytes)
            os.makedirs(os.path.join(tmp, ".git"))
            out_path = os.path.join(tmp, "package.txt")
            rc = wrapper.main(["--envelope", envelope_path, "--out", out_path])
            self.assertEqual(1, rc)
            self.assertFalse(os.path.exists(out_path))

    def test_does_not_modify_input_file(self):
        envelope_bytes = _build_synthetic_envelope_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            envelope_path = os.path.join(tmp, "envelope.bin")
            out_path = os.path.join(tmp, "package.txt")
            with open(envelope_path, "wb") as f:
                f.write(envelope_bytes)
            before_hash = hashlib.sha256(envelope_bytes).hexdigest()

            wrapper.main(["--envelope", envelope_path, "--out", out_path])

            with open(envelope_path, "rb") as f:
                after_bytes = f.read()
            self.assertEqual(before_hash, hashlib.sha256(after_bytes).hexdigest())


if __name__ == "__main__":
    unittest.main()
