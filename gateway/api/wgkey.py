"""Strict AmneziaWG/WireGuard public-key validation.

Shared by config.py (validating the gateway's own configured public key)
and handler.py (validating a request's public_key field) so there is one
definition of "valid key", not two that could drift.

Deliberately NOT just a length/regex check: a WireGuard/AmneziaWG public
key must be exactly a valid base64 encoding of 32 raw bytes. Strict
base64.b64decode(..., validate=True) plus a round-trip re-encode check
rejects whitespace-padded, non-canonically-padded, or otherwise "close
enough" strings that a length-only or loose-regex check would silently
accept.
"""
import base64
import binascii

_EXPECTED_ENCODED_LENGTH = 44
_EXPECTED_DECODED_BYTES = 32


def is_valid_wg_public_key(candidate):
    if not isinstance(candidate, str):
        return False
    if len(candidate) != _EXPECTED_ENCODED_LENGTH:
        return False
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(decoded) != _EXPECTED_DECODED_BYTES:
        return False
    # base64.b64decode(validate=True) rejects non-alphabet characters, but
    # does not by itself guarantee the padding bits in the final quantum
    # were zero - a non-canonical encoding can still decode successfully.
    # Re-encoding the decoded bytes and requiring an exact match rejects
    # any input that isn't the unique canonical encoding of those 32 bytes.
    if base64.b64encode(decoded).decode("ascii") != candidate:
        return False
    return True
