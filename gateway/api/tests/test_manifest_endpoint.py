"""B12 - HTTP-level tests for GET /v1/manifest: this process serves an
already-signed manifest artifact verbatim, never signs or validates it
itself - see handler.py's _handle_manifest docstring. Signature validity is
the CLIENT's concern (Android's Ed25519ManifestVerifier), exercised
separately in the Android test suite.
"""
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from _fixtures import RunningServer, make_app_config, write_fake_manifest_artifact, write_fake_provision_script
from _http import get_manifest


class ManifestEndpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.script_path = write_fake_provision_script(self._tmp.name)

    def _start(self, manifest_path=""):
        app_config = make_app_config(self._tmp.name, self.script_path, manifest_path=manifest_path)
        server = RunningServer(app_config)
        self.addCleanup(server.close)
        return server

    def test_not_configured_fails_closed_with_503(self):
        server = self._start(manifest_path="")
        status, _headers, body = get_manifest(server.port)
        self.assertEqual(status, 503)
        self.assertIn(b"manifest_not_configured", body)

    def test_configured_serves_the_artifact_bytes_verbatim(self):
        artifact_bytes = b"\x00\x00\x00\x01" + b"some-canonical-and-signature-bytes"
        manifest_path = write_fake_manifest_artifact(self._tmp.name, body=artifact_bytes)
        server = self._start(manifest_path=manifest_path)
        status, headers, body = get_manifest(server.port)
        self.assertEqual(status, 200)
        self.assertEqual(body, artifact_bytes)
        self.assertEqual(headers.get("content-type"), "application/octet-stream")
        self.assertEqual(headers.get("content-length"), str(len(artifact_bytes)))

    def test_a_changed_artifact_on_disk_is_served_fresh_on_the_next_request(self):
        manifest_path = write_fake_manifest_artifact(self._tmp.name, body=b"version-one")
        server = self._start(manifest_path=manifest_path)
        status1, _h1, body1 = get_manifest(server.port)
        self.assertEqual(status1, 200)
        self.assertEqual(body1, b"version-one")

        with open(manifest_path, "wb") as handle:
            handle.write(b"version-two-longer")
        status2, _h2, body2 = get_manifest(server.port)
        self.assertEqual(status2, 200)
        self.assertEqual(body2, b"version-two-longer")

    def test_post_is_method_not_allowed(self):
        manifest_path = write_fake_manifest_artifact(self._tmp.name)
        server = self._start(manifest_path=manifest_path)
        status, _headers, body = get_manifest(server.port, method="POST")
        self.assertEqual(status, 405)
        self.assertIn(b"method_not_allowed", body)

    def test_no_authorization_header_required(self):
        # Unlike every POST endpoint, GET /v1/manifest is intentionally
        # unauthenticated - a signed manifest is meant for broad
        # distribution (see handler.py's own docstring for why).
        manifest_path = write_fake_manifest_artifact(self._tmp.name)
        server = self._start(manifest_path=manifest_path)
        status, _headers, _body = get_manifest(server.port, extra_headers={})
        self.assertEqual(status, 200)

    def test_response_is_never_json_content_type(self):
        # A binary container, never accidentally treated as/parsed as JSON
        # by a naive client.
        manifest_path = write_fake_manifest_artifact(self._tmp.name)
        server = self._start(manifest_path=manifest_path)
        _status, headers, _body = get_manifest(server.port)
        self.assertNotEqual(headers.get("content-type"), "application/json")

    def test_missing_manifest_file_on_disk_is_internal_error_not_a_crash(self):
        manifest_path = os.path.join(self._tmp.name, "does-not-exist.bin")
        # Bypass config.py's own startup file-existence check (a real
        # deployment can never reach this state - the process would refuse
        # to start) to prove the HANDLER itself still fails safe if the
        # file disappears after startup (e.g. a botched deploy/rotation).
        server = self._start(manifest_path=write_fake_manifest_artifact(self._tmp.name))
        os.remove(server.app_config.manifest_path)
        status, _headers, body = get_manifest(server.port)
        self.assertEqual(status, 500)
        self.assertIn(b"internal_error", body)


if __name__ == "__main__":
    unittest.main()
