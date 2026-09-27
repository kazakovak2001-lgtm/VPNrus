#!/usr/bin/env python3
"""B56-7A - operator-only NovaActivationPackage wrapper.

This is a SEPARATE, structural-only tool from gateway/tools/activation_envelope_issuer.py
(unchanged, never touched by this file). It takes an ALREADY-SIGNED
`SignedActivationEnvelope` artifact (produced by that tool's `issue` command)
and wraps its exact bytes into the EXISTING `NovaActivationPackage` V1 wire
container, then Base64URL-encodes the result with the existing
`nova-activation:1:` text prefix - the same format
net.pocvpn.client.activation.NovaActivationPackage/ActivationPackageParser
(Kotlin, B56-5) already parses in the shipped app's `ActivationScreen`.

## No cryptography, no new format

This tool never signs anything and never touches the activation-issuer
private key - it only rearranges already-signed, already-public-shaped
bytes into a second, EXISTING container format. The wire format below is
copied from (never re-derived independently of)
android/app/src/main/java/net/pocvpn/client/activation/NovaActivationPackage.kt
and its `ActivationPackageParser.encode`/`decode`:

    int   domainTagLength, bytes DOMAIN_TAG ("NOVA_ACTIVATION_PACKAGE_V1", UTF-8)
    int   schemaVersion (== 1)
    int   envelopeLength (1..MAX_ENVELOPE_BYTES), bytes  - the envelope artifact, VERBATIM
    int   bundleLength (0 here - this tool never attaches a bootstrap bundle)
    int   level2SectionLength (0 - V1 always empty)

Text form: `nova-activation:1:` + canonical, unpadded Base64URL of the bytes
above - matching `ActivationEnvelopeTextCodec`'s own canonical-alphabet,
no-padding, re-encode-and-compare discipline (B56-1), reused here via the
same `base64.urlsafe_b64encode`/strip-padding convention
`activation_envelope_issuer.py` already uses.

## Bearer-secret handling

The input envelope and the resulting package text are both bearer secrets
(see docs/B56_ACTIVATION_ISSUER_KEY_CEREMONY.md's "the envelope is a bearer
secret"). This tool:

- never prints the envelope's or the package's bytes/text to stdout/stderr
  on its own (an explicit `--out -` opts into stdout, on the operator's own
  responsibility, exactly like a deliberate `cat` would be - the point is
  the default behavior can never accidentally leak it into a log);
- never logs the input or output;
- refuses to overwrite an existing output file and refuses any output path
  inside a git working tree (same `_refuse_if_exists`/
  `_refuse_if_inside_git_repo` this repo's own issuer CLI already uses -
  reused directly, not reimplemented);
- never opens the input envelope for writing - it is read-only throughout.
"""
from __future__ import annotations

import argparse
import base64
import os
import struct
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import activation_envelope_issuer as issuer  # noqa: E402 - reuse existing no-clobber/git-guard helpers

DOMAIN_TAG = "NOVA_ACTIVATION_PACKAGE_V1"
SCHEMA_VERSION = 1
TEXT_PREFIX = "nova-activation:1:"

# Copied from NovaActivationPackage.kt / ActivationPackageParser.kt - never a
# second, independently-chosen bound. This tool only ever produces
# bundleLength=0/level2SectionLength=0, so the envelope bound below is the
# only one that can actually reject an input here.
MAX_ENVELOPE_BYTES = issuer.MAX_ENCODED_BYTES  # 32_768, same constant Kotlin's ActivationEnvelopeCodec.MAX_ENCODED_BYTES uses


class PackageWrapperError(Exception):
    """Raised for any operator-input error - never printed with a raw
    lower-layer exception message, matching this repo's issuer CLI
    convention (class name + a bounded, non-secret description only)."""


def wrap_envelope_bytes(envelope_bytes: bytes) -> bytes:
    """Wraps an already-signed envelope artifact's exact bytes into the
    NovaActivationPackage V1 binary container. `envelope_bytes` is used
    VERBATIM - this function never parses, re-signs, or modifies it; only
    its length is checked, matching ActivationPackageParser.decode's own
    `envelopeLen !in 1..MAX_ENCODED_BYTES` bound so this tool can never
    produce a package the existing Kotlin parser would reject as malformed."""
    if len(envelope_bytes) == 0:
        raise PackageWrapperError("input envelope is empty")
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        raise PackageWrapperError(
            f"input envelope ({len(envelope_bytes)} bytes) exceeds MAX_ENVELOPE_BYTES ({MAX_ENVELOPE_BYTES})"
        )

    domain_tag_bytes = DOMAIN_TAG.encode("utf-8")
    buf = bytearray()
    buf += struct.pack(">i", len(domain_tag_bytes))
    buf += domain_tag_bytes
    buf += struct.pack(">i", SCHEMA_VERSION)
    buf += struct.pack(">i", len(envelope_bytes))
    buf += envelope_bytes
    buf += struct.pack(">i", 0)  # bundleLength - this tool never attaches a bootstrap bundle
    buf += struct.pack(">i", 0)  # level2SectionLength - V1 always empty
    return bytes(buf)


def encode_package_text(envelope_bytes: bytes) -> str:
    """The full `nova-activation:1:<canonical Base64URL>` text form,
    matching ActivationPackageParser.encodeText byte-for-byte (canonical =
    unpadded, and only ever produced by this one encoder - never a second,
    independently-implemented alphabet)."""
    package_bytes = wrap_envelope_bytes(envelope_bytes)
    encoded = base64.urlsafe_b64encode(package_bytes).rstrip(b"=").decode("ascii")
    return TEXT_PREFIX + encoded


def _read_envelope_file(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise PackageWrapperError(f"failed to read envelope file {path!r}: {exc.__class__.__name__}") from None
    if len(data) == 0:
        raise PackageWrapperError(f"envelope file {path!r} is empty")
    return data


def _write_package_text(path: str, text: str) -> None:
    if path == "-":
        # Explicit operator opt-in only - never the default - see module docs.
        sys.stdout.write(text)
        sys.stdout.write("\n")
        return
    issuer._refuse_if_exists(path)
    issuer._refuse_if_inside_git_repo(path)
    # Same atomic no-clobber primitive activation_envelope_issuer.py uses for
    # every other sensitive output (private key, metadata, envelope
    # artifact) - reused directly, not reimplemented. The post-publication
    # directory-fsync confirmation is best-effort and never raises; see
    # that function's own docs.
    tmp_path = issuer.publish_secret_no_clobber(path, text.encode("ascii"))
    issuer.confirm_post_publication(path, tmp_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="activation_package_wrapper.py",
        description="B56-7A operator-only tool: wrap a signed ActivationEnvelope artifact into the "
        "existing NovaActivationPackage V1 text form (nova-activation:1:...). No cryptography, "
        "no signing, no private key access.",
    )
    parser.add_argument("--envelope", required=True, help="path to an existing signed envelope artifact (read-only)")
    parser.add_argument(
        "--out",
        required=True,
        help="output path for the package text (refuses to overwrite, refuses a path inside a git working tree); "
        "pass '-' to write to stdout instead (operator's own explicit choice - never the default)",
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        envelope_bytes = _read_envelope_file(args.envelope)
        text = encode_package_text(envelope_bytes)
        _write_package_text(args.out, text)
    except (PackageWrapperError, issuer.IssuerError) as exc:
        print(f"activation_package_wrapper: ERROR - {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"activation_package_wrapper: ERROR - {exc.__class__.__name__}", file=sys.stderr)
        return 1
    finally:
        envelope_bytes = None  # best-effort - drop the local reference promptly
        text = None

    if args.out != "-":
        print(f"activation_package_wrapper: package text written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
