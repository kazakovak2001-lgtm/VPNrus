import io
import json
import logging
import os
import sys
import tempfile
import threading
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import tokens as tokens_module
from _fixtures import (
    RunningServer,
    make_app_config,
    make_public_key,
    make_token_store,
    set_plan,
    write_fake_provision_script,
)
from _http import parse_http_response, post_peers, raw_request, send_raw_lines


class HandlerTestCase(unittest.TestCase):
    """Spins up one real ProvisioningServer per test on an ephemeral
    127.0.0.1 port, backed by a throwaway token store and a scriptable
    fake provision-peer.sh. No Oracle, no real AWG mutation, no shared
    state between tests."""

    ACTIVE_TOKEN = "active-token-with-plenty-of-entropy-0001"
    REVOKED_TOKEN = "revoked-token-with-plenty-of-entropy-0002"
    UNKNOWN_TOKEN = "unknown-token-never-in-the-store-000003"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

        self.bound_public_key = make_public_key(0x10)
        self.other_public_key = make_public_key(0x20)

        self.script_path = write_fake_provision_script(self._tmp.name)
        self.plan_path = os.path.join(self._tmp.name, "plan.txt")
        set_plan(self.plan_path, "CREATED", "10.77.0.42")

        self._env_backup = dict(os.environ)
        os.environ["POCVPN_FAKE_PLAN"] = self.plan_path
        os.environ.pop("POCVPN_FAKE_ARGV_CAPTURE", None)
        self.addCleanup(self._restore_env)

        self.app_config = make_app_config(self._tmp.name, self.script_path)
        make_token_store(
            self.app_config.token_store_path,
            [
                (self.ACTIVE_TOKEN, self.bound_public_key, tokens_module.ACTIVE),
                (self.REVOKED_TOKEN, self.bound_public_key, tokens_module.REVOKED),
            ],
        )

        self._log_capture = io.StringIO()
        self._log_handler = logging.StreamHandler(self._log_capture)
        self._api_logger = logging.getLogger("pocvpn.api")
        self._api_logger.addHandler(self._log_handler)
        self._api_logger.setLevel(logging.DEBUG)
        self.addCleanup(lambda: self._api_logger.removeHandler(self._log_handler))

        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)

    def _restore_env(self):
        os.environ.clear()
        os.environ.update(self._env_backup)

    def set_plan(self, command, arg=""):
        set_plan(self.plan_path, command, arg)

    def post(self, **kwargs):
        return post_peers(self.server.port, **kwargs)

    def logs(self):
        return self._log_capture.getvalue()


# ============================================================
# AUTH
# ============================================================
class AuthTests(HandlerTestCase):
    def test_no_authorization_header_401(self):
        status, _headers, body = self.post(body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"error": "unauthorized"})

    def test_malformed_bearer_401(self):
        status, _headers, _body = self.post(
            body_obj={"public_key": self.bound_public_key},
            extra_headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        self.assertEqual(status, 401)

    def test_unknown_token_401(self):
        status, _headers, _body = self.post(
            token=self.UNKNOWN_TOKEN, body_obj={"public_key": self.bound_public_key}
        )
        self.assertEqual(status, 401)

    def test_revoked_token_401(self):
        status, _headers, _body = self.post(
            token=self.REVOKED_TOKEN, body_obj={"public_key": self.bound_public_key}
        )
        self.assertEqual(status, 401)

    def test_unknown_and_revoked_bodies_identical(self):
        _s1, _h1, body_unknown = self.post(
            token=self.UNKNOWN_TOKEN, body_obj={"public_key": self.bound_public_key}
        )
        _s2, _h2, body_revoked = self.post(
            token=self.REVOKED_TOKEN, body_obj={"public_key": self.bound_public_key}
        )
        self.assertEqual(body_unknown, body_revoked)

    def test_valid_token_bound_key_accepted(self):
        status, _headers, _body = self.post(
            token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key}
        )
        self.assertEqual(status, 201)

    def test_valid_token_wrong_key_403(self):
        status, _headers, body = self.post(
            token=self.ACTIVE_TOKEN, body_obj={"public_key": self.other_public_key}
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})


# ============================================================
# INPUT
# ============================================================
class InputTests(HandlerTestCase):
    def test_malformed_json_400(self):
        status, _headers, body = self.post(token=self.ACTIVE_TOKEN, raw_body=b"{not json", content_type="application/json")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "malformed_json"})

    def test_json_non_object_400(self):
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj=["a", "list"])
        self.assertEqual(status, 400)

    def test_missing_public_key_400(self):
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={})
        self.assertEqual(status, 400)

    def test_extra_unexpected_fields_400(self):
        status, _headers, _body = self.post(
            token=self.ACTIVE_TOKEN,
            body_obj={"public_key": self.bound_public_key, "label": "not-allowed"},
        )
        self.assertEqual(status, 400)

    def test_invalid_base64_public_key_400(self):
        status, _headers, _body = self.post(
            token=self.ACTIVE_TOKEN, body_obj={"public_key": "!" + self.bound_public_key[1:]}
        )
        self.assertEqual(status, 400)

    def test_base64_not_32_bytes_400(self):
        import base64

        not_32_bytes = base64.b64encode(b"\x01" * 31).decode("ascii")
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": not_32_bytes})
        self.assertEqual(status, 400)

    def test_wrong_content_type_415(self):
        status, _headers, body = self.post(
            token=self.ACTIVE_TOKEN,
            body_obj={"public_key": self.bound_public_key},
            content_type="text/plain",
        )
        self.assertEqual(status, 415)
        self.assertEqual(json.loads(body), {"error": "unsupported_media_type"})

    def test_missing_content_length_411(self):
        status, _headers, body = self.post(
            token=self.ACTIVE_TOKEN,
            body_obj={"public_key": self.bound_public_key},
            set_content_length=False,
        )
        self.assertEqual(status, 411)
        self.assertEqual(json.loads(body), {"error": "length_required"})

    def test_body_over_1024_bytes_413(self):
        oversized = json.dumps({"public_key": self.bound_public_key, "padding": "x" * 2000}).encode("utf-8")
        status, _headers, body = self.post(token=self.ACTIVE_TOKEN, raw_body=oversized)
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body), {"error": "payload_too_large"})


# ============================================================
# PROVISION RESULT
# ============================================================
class ProvisionResultTests(HandlerTestCase):
    def test_created_201_correct_json(self):
        self.set_plan("CREATED", "10.77.0.50")
        status, _headers, body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(
            payload,
            {
                "client_tunnel_ip": "10.77.0.50",
                "gateway_public_key": self.app_config.gateway_public_key,
                "gateway_tunnel_ip": self.app_config.gateway_tunnel_ip,
                "endpoint_host": self.app_config.endpoint_host,
                "endpoint_port": self.app_config.endpoint_port,
            },
        )

    def test_existing_200_same_schema(self):
        self.set_plan("EXISTING", "10.77.0.51")
        status, _headers, body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(set(payload.keys()), {
            "client_tunnel_ip", "gateway_public_key", "gateway_tunnel_ip", "endpoint_host", "endpoint_port",
        })
        self.assertEqual(payload["client_tunnel_ip"], "10.77.0.51")

    def test_helper_exit_20_503(self):
        self.set_plan("EXIT", "20")
        status, _headers, body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"error": "subnet_exhausted"})

    def test_helper_exit_1_500(self):
        self.set_plan("EXIT", "1")
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 500)

    def test_helper_exit_2_500(self):
        self.set_plan("EXIT", "2")
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 500)

    def test_unexpected_exit_code_500(self):
        self.set_plan("EXIT", "7")
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 500)

    def test_helper_timeout_504(self):
        # Rebuild config with a very small subprocess timeout for this
        # one test rather than sleeping the default 5s timeout away.
        self.app_config = make_app_config(self._tmp.name, self.script_path, subprocess_timeout_seconds=0.3)
        make_token_store(
            self.app_config.token_store_path,
            [(self.ACTIVE_TOKEN, self.bound_public_key, tokens_module.ACTIVE)],
        )
        self.server.close()
        self.server = RunningServer(self.app_config)
        self.addCleanup(self.server.close)

        self.set_plan("SLEEP", "5")
        status, _headers, body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 504)
        self.assertEqual(json.loads(body), {"error": "provisioning_timeout"})

    def test_malformed_stdout_500(self):
        self.set_plan("MALFORMED")
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 500)

    def test_extra_stdout_line_500(self):
        self.set_plan("EXTRA")
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 500)

    def test_invalid_returned_ip_500(self):
        self.set_plan("BADIP")
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 500)


# ============================================================
# SECURITY
# ============================================================
class SecurityTests(HandlerTestCase):
    def test_helper_argv_never_contains_bearer_token(self):
        capture_path = os.path.join(self._tmp.name, "argv_capture.txt")
        os.environ["POCVPN_FAKE_ARGV_CAPTURE"] = capture_path
        self.set_plan("CREATED", "10.77.0.60")
        self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        with open(capture_path, "r", encoding="utf-8") as handle:
            captured = handle.read().splitlines()
        self.assertEqual(captured, [self.bound_public_key])
        self.assertNotIn(self.ACTIVE_TOKEN, captured)

    def test_raw_token_absent_from_logs(self):
        self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertNotIn(self.ACTIVE_TOKEN, self.logs())

    def test_authorization_header_absent_from_logs(self):
        self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertNotIn("Authorization", self.logs())
        self.assertNotIn("Bearer", self.logs())

    def test_full_public_key_absent_from_logs(self):
        self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertNotIn(self.bound_public_key, self.logs())

    def test_token_store_contains_only_hash(self):
        with open(self.app_config.token_store_path, "r", encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn(self.ACTIVE_TOKEN, raw)
        self.assertNotIn(self.REVOKED_TOKEN, raw)

    def test_corrupted_token_store_is_500_not_401(self):
        with open(self.app_config.token_store_path, "w", encoding="utf-8") as handle:
            handle.write("{not valid json")
        status, _headers, body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 500)
        self.assertNotEqual(status, 401)
        self.assertEqual(json.loads(body), {"error": "internal_error"})

    def test_token_store_schema_corruption_is_500(self):
        digest = tokens_module.token_digest(self.ACTIVE_TOKEN)
        with open(self.app_config.token_store_path, "w", encoding="utf-8") as handle:
            json.dump({digest: {"status": "NOT_A_REAL_STATUS", "expected_public_key": "x"}}, handle)
        status, _headers, _body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status, 500)


# ============================================================
# RATE LIMIT
# ============================================================
class RateLimitTests(HandlerTestCase):
    def test_per_token_limit_429(self):
        # Reach directly into the running server's limiter to force the
        # boundary deterministically rather than firing dozens of real
        # requests (which would also be gated by the global limiter).
        self.server.srv.per_token_limiter._max_requests = 1
        status1, _h1, _b1 = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        status2, _h2, body2 = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status1, 201)
        self.assertEqual(status2, 429)
        self.assertEqual(json.loads(body2), {"error": "rate_limited"})

    def test_global_limit_429(self):
        self.server.srv.global_limiter._max_requests = 1
        status1, _h1, _b1 = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        status2, _h2, body2 = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
        self.assertEqual(status1, 201)
        self.assertEqual(status2, 429)
        self.assertEqual(json.loads(body2), {"error": "rate_limited"})

    def test_limiter_storage_bounded(self):
        limiter = self.server.srv.per_token_limiter
        for i in range(20):
            limiter.allow(f"synthetic-key-{i}")
        self.assertGreater(limiter.size(), 0)


# ============================================================
# SERVER
# ============================================================
class ServerTests(HandlerTestCase):
    def test_binds_127_0_0_1(self):
        self.assertEqual(self.server.host, "127.0.0.1")

    def test_unsupported_path_404(self):
        status, _headers, body = raw_request(self.server.port, "POST", "/v1/other", {"Content-Length": "0"})
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_unsupported_method_405(self):
        status, _headers, body = raw_request(self.server.port, "GET", "/v1/peers", {})
        self.assertEqual(status, 405)
        self.assertEqual(json.loads(body), {"error": "method_not_allowed"})

    def test_concurrent_requests_do_not_corrupt_shared_state(self):
        self.set_plan("CREATED", "10.77.0.70")
        results = []
        results_lock = threading.Lock()

        def worker():
            status, _headers, body = self.post(token=self.ACTIVE_TOKEN, body_obj={"public_key": self.bound_public_key})
            with results_lock:
                results.append((status, body))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(len(results), 10)
        for status, body in results:
            self.assertIn(status, (200, 201, 429))
            json.loads(body)  # every response is well-formed JSON, never a corrupted/partial body


# ============================================================
# FRAMING (final HTTP framing/security review)
# ============================================================
class FramingTests(HandlerTestCase):
    """Every test here sends the wire bytes directly via send_raw_lines,
    never through post_peers/raw_request's dict-based header builder -
    duplicate headers and malformed values can't reliably be expressed
    through a dict, and the point of these tests is exactly to prove the
    handler itself rejects them, not that some higher-level client would
    have "fixed" them first."""

    def _good_body(self):
        return json.dumps({"public_key": self.bound_public_key}).encode("utf-8")

    def _auth_and_type_headers(self):
        return [
            "Content-Type: application/json",
            f"Authorization: Bearer {self.ACTIVE_TOKEN}",
        ]

    def _send(self, content_length_lines, body=None):
        body = self._good_body() if body is None else body
        header_lines = self._auth_and_type_headers() + content_length_lines
        return send_raw_lines(self.server.port, "POST", "/v1/peers", header_lines, body)

    def test_content_length_negative_400(self):
        status, _h, body, _c = self._send(["Content-Length: -1"])
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "malformed_request"})

    def test_content_length_plus_prefix_400(self):
        status, _h, _b, _c = self._send([f"Content-Length: +{len(self._good_body())}"])
        self.assertEqual(status, 400)

    def test_content_length_non_numeric_400(self):
        status, _h, _b, _c = self._send(["Content-Length: abc"])
        self.assertEqual(status, 400)

    def test_content_length_float_400(self):
        status, _h, _b, _c = self._send(["Content-Length: 1.0"])
        self.assertEqual(status, 400)

    def test_content_length_comma_list_400(self):
        status, _h, _b, _c = self._send(["Content-Length: 10,20"])
        self.assertEqual(status, 400)

    def test_content_length_hex_400(self):
        status, _h, _b, _c = self._send(["Content-Length: 0x10"])
        self.assertEqual(status, 400)

    def test_content_length_still_enforces_411_and_413(self):
        # Regression guard alongside the new malformed-value cases above:
        # missing stays 411, oversized stays 413 - the fix must not have
        # collapsed these into 400 too.
        status_missing, _h1, body_missing, _c1 = self._send([])
        self.assertEqual(status_missing, 411)
        self.assertEqual(json.loads(body_missing), {"error": "length_required"})

        oversized = json.dumps({"public_key": self.bound_public_key, "padding": "x" * 2000}).encode("utf-8")
        status_big, _h2, body_big, _c2 = self._send([f"Content-Length: {len(oversized)}"], body=oversized)
        self.assertEqual(status_big, 413)
        self.assertEqual(json.loads(body_big), {"error": "payload_too_large"})

    def test_duplicate_content_length_rejected_even_if_identical(self):
        body = self._good_body()
        header_lines = self._auth_and_type_headers() + [
            f"Content-Length: {len(body)}",
            f"Content-Length: {len(body)}",  # identical value, still a duplicate
        ]
        status, _h, resp_body, _c = send_raw_lines(self.server.port, "POST", "/v1/peers", header_lines, body)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(resp_body), {"error": "malformed_request"})

    def test_duplicate_content_length_different_values_rejected(self):
        body = self._good_body()
        header_lines = self._auth_and_type_headers() + [
            f"Content-Length: {len(body)}",
            "Content-Length: 4",
        ]
        status, _h, _resp_body, _c = send_raw_lines(self.server.port, "POST", "/v1/peers", header_lines, body)
        self.assertEqual(status, 400)

    def test_transfer_encoding_present_rejected(self):
        body = self._good_body()
        header_lines = self._auth_and_type_headers() + [
            f"Content-Length: {len(body)}",
            "Transfer-Encoding: chunked",
        ]
        status, _h, resp_body, _c = send_raw_lines(self.server.port, "POST", "/v1/peers", header_lines, body)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(resp_body), {"error": "invalid_request"})

    def test_transfer_encoding_plus_content_length_smuggling_shape_rejected(self):
        # The classic smuggling shape: both headers present, with
        # Content-Length lying about a short body while Transfer-Encoding
        # claims chunked framing. Must be rejected outright, not parsed
        # either way.
        header_lines = self._auth_and_type_headers() + [
            "Content-Length: 4",
            "Transfer-Encoding: chunked",
        ]
        status, _h, _b, _c = send_raw_lines(
            self.server.port, "POST", "/v1/peers", header_lines, b"0\r\n\r\n"
        )
        self.assertEqual(status, 400)

    def test_unsupported_transfer_encoding_value_also_rejected(self):
        # Not just "chunked" - ANY Transfer-Encoding value is unsupported.
        body = self._good_body()
        header_lines = self._auth_and_type_headers() + [
            f"Content-Length: {len(body)}",
            "Transfer-Encoding: identity",
        ]
        status, _h, _b, _c = send_raw_lines(self.server.port, "POST", "/v1/peers", header_lines, body)
        self.assertEqual(status, 400)

    # --- Connection: close on every response path ---
    def _assert_connection_close(self, status_expected, header_lines, body):
        status, headers, _body, closed_by_peer = send_raw_lines(
            self.server.port, "POST", "/v1/peers", header_lines, body
        )
        self.assertEqual(status, status_expected)
        self.assertEqual(headers.get("connection"), "close")
        self.assertTrue(closed_by_peer, "server did not actually close the connection after responding")

    def test_connection_close_on_success(self):
        self.set_plan("CREATED", "10.77.0.80")
        body = self._good_body()
        self._assert_connection_close(
            201, self._auth_and_type_headers() + [f"Content-Length: {len(body)}"], body
        )

    def test_connection_close_on_400(self):
        self._assert_connection_close(400, self._auth_and_type_headers() + ["Content-Length: abc"], b"")

    def test_connection_close_on_401(self):
        body = self._good_body()
        header_lines = ["Content-Type: application/json", f"Content-Length: {len(body)}"]
        self._assert_connection_close(401, header_lines, body)

    def test_connection_close_on_413(self):
        oversized = json.dumps({"public_key": self.bound_public_key, "padding": "x" * 2000}).encode("utf-8")
        self._assert_connection_close(
            413, self._auth_and_type_headers() + [f"Content-Length: {len(oversized)}"], oversized
        )

    def test_connection_close_on_500(self):
        self.set_plan("EXIT", "1")
        body = self._good_body()
        self._assert_connection_close(
            500, self._auth_and_type_headers() + [f"Content-Length: {len(body)}"], body
        )

    def test_stalled_body_read_times_out_and_closes(self):
        import socket as socket_module
        import time as time_module

        from api import handler as handler_module

        original_timeout = handler_module._SOCKET_TIMEOUT_SECONDS
        handler_module._SOCKET_TIMEOUT_SECONDS = 0.4
        try:
            body = self._good_body()
            header_lines = self._auth_and_type_headers() + [f"Content-Length: {len(body)}"]
            lines = ["POST /v1/peers HTTP/1.1", f"Host: 127.0.0.1:{self.server.port}"] + header_lines + [""]
            head = ("\r\n".join(lines) + "\r\n").encode("latin-1")

            start = time_module.monotonic()
            with socket_module.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
                # Send headers and only PART of the declared body, then
                # deliberately stop - simulating a client that never
                # finishes sending.
                sock.sendall(head + body[:3])
                sock.settimeout(5)
                chunks = []
                closed_by_peer = False
                while True:
                    try:
                        chunk = sock.recv(65536)
                    except socket_module.timeout:
                        break
                    if not chunk:
                        closed_by_peer = True
                        break
                    chunks.append(chunk)
            elapsed = time_module.monotonic() - start

            self.assertTrue(closed_by_peer, "server never closed the stalled connection")
            self.assertLess(elapsed, 3.0, "server took far longer than its own read timeout to give up")
            if chunks:
                # If a response was sent before the close, it must be a
                # clean 500 with no exception detail - never a raw
                # traceback or partial/garbage bytes.
                status, _headers, resp_body = parse_http_response(b"".join(chunks))
                self.assertEqual(status, 500)
                self.assertEqual(json.loads(resp_body), {"error": "internal_error"})
        finally:
            handler_module._SOCKET_TIMEOUT_SECONDS = original_timeout


if __name__ == "__main__":
    unittest.main()
