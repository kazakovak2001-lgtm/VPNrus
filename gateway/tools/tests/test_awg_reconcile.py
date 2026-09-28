"""B47 T1 - AWG entitlement desired-state planner (tools/awg_reconcile.py)
and the revoke CLI's best-effort reconcile trigger (activation_tokens.py).

The planner is read-only by construction; the destructive half (removal
under .provision.lock) is exercised end-to-end in
gateway/scripts/tests/run_tests.sh against a fake awg0.conf."""
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_GATEWAY_DIR = os.path.abspath(os.path.join(_TOOLS_DIR, ".."))
for _path in (_GATEWAY_DIR, _TOOLS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import activation_tokens  # noqa: E402
import awg_reconcile  # noqa: E402
from api import activations as activations_module  # noqa: E402

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


def _key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


KEY_A, KEY_B, KEY_C, KEY_D, KEY_M = _key(1), _key(2), _key(3), _key(4), _key(9)


_INTERFACE = """# rendered by provision.sh from gateway/config/awg0.conf.example
[Interface]
PrivateKey = test-fixture-not-a-real-private-key
Address = 10.77.0.1/24
ListenPort = 51820
Jc = 6
Jmin = 40
Jmax = 100
S1 = 113
S2 = 159
S3 = 0
S4 = 0
H1 = 1106684696
H2 = 3677857287
H3 = 353316806
H4 = 2068198996
RandomTrailers = off
DisableCookies = off

# --- PEERS BEGIN --- (managed by scripts/add-peer.sh / remove-peer.sh; do not hand-edit below this line)
"""
_END = "# --- PEERS END ---\n"


def _peer_block(key, ip, label="provision-peer-1789000000"):
    """Exactly the block lib/peer_mutations.sh mutate_add_peer writes."""
    return f"[Peer]\n# label: {label}\nPublicKey = {key}\nAllowedIPs = {ip}/32\n\n"


def _awg_conf(keys):
    """A production-shaped awg0.conf holding one peer per key."""
    blocks = "".join(_peer_block(k, f"10.77.0.{i + 2}") for i, k in enumerate(keys))
    return _INTERFACE + blocks + _END


def _activation(status="ACTIVE", expires_at=None, keys=(), activation_id="a" * 32, state="confirmed"):
    return {
        "activation_id": activation_id,
        "status": status,
        "max_devices": max(1, len(keys)),
        "created_at": "2026-09-01T00:00:00+00:00",
        "expires_at": expires_at,
        "bound_devices": [{"public_key": k, "reservation_id": "", "state": state} for k in keys],
    }


def _token(key, status="ACTIVE", token_id="c" * 32):
    return {"token_id": token_id, "expected_public_key": key, "status": status}


def _plan(activations_data, token_data, peers, now=NOW):
    return awg_reconcile.plan_peer_removals(activations_data, token_data, peers, now)


class PlannerDesiredStateTests(unittest.TestCase):
    def test_active_entitlement_peer_is_desired(self):
        plan = _plan({"1" * 64: _activation(keys=(KEY_A,))}, {}, [KEY_A])
        self.assertEqual(plan.remove, ())
        self.assertEqual(plan.desired_present, 1)

    def test_unlimited_entitlement_peer_is_desired(self):
        plan = _plan({"1" * 64: _activation(expires_at=None, keys=(KEY_A,))}, {}, [KEY_A], now=NOW + timedelta(days=3650))
        self.assertEqual(plan.remove, ())

    def test_revoked_entitlement_peer_is_removed(self):
        plan = _plan({"1" * 64: _activation(status="REVOKED", keys=(KEY_A,))}, {}, [KEY_A])
        self.assertEqual(plan.remove, (KEY_A,))

    def test_expired_entitlement_peer_is_removed(self):
        plan = _plan({"1" * 64: _activation(expires_at=(NOW - timedelta(seconds=1)).isoformat(), keys=(KEY_A,))}, {}, [KEY_A])
        self.assertEqual(plan.remove, (KEY_A,))

    def test_exactly_at_expiry_peer_is_removed(self):
        plan = _plan({"1" * 64: _activation(expires_at=NOW.isoformat(), keys=(KEY_A,))}, {}, [KEY_A])
        self.assertEqual(plan.remove, (KEY_A,))

    def test_pending_binding_of_active_activation_is_desired(self):
        # An in-flight /v1/activate must never be undercut by a reconcile.
        plan = _plan({"1" * 64: _activation(keys=(KEY_A,), state="pending")}, {}, [KEY_A])
        self.assertEqual(plan.remove, ())

    def test_multiple_activations_yield_the_correct_key_set(self):
        data = {
            "1" * 64: _activation(keys=(KEY_A,), activation_id="1" * 32),
            "2" * 64: _activation(status="REVOKED", keys=(KEY_B,), activation_id="2" * 32),
            "3" * 64: _activation(expires_at=(NOW - timedelta(days=1)).isoformat(), keys=(KEY_C,), activation_id="3" * 32),
            "4" * 64: _activation(expires_at=(NOW + timedelta(days=1)).isoformat(), keys=(KEY_D,), activation_id="4" * 32),
        }
        plan = _plan(data, {}, [KEY_A, KEY_B, KEY_C, KEY_D])
        self.assertEqual(set(plan.remove), {KEY_B, KEY_C})
        self.assertEqual(plan.desired_present, 2)

    def test_same_key_bound_to_two_valid_entitlements_remains(self):
        data = {
            "1" * 64: _activation(keys=(KEY_A,), activation_id="1" * 32),
            "2" * 64: _activation(keys=(KEY_A,), activation_id="2" * 32),
        }
        self.assertEqual(_plan(data, {}, [KEY_A]).remove, ())

    def test_one_binding_revoked_but_another_valid_keeps_the_peer(self):
        data = {
            "1" * 64: _activation(status="REVOKED", keys=(KEY_A,), activation_id="1" * 32),
            "2" * 64: _activation(keys=(KEY_A,), activation_id="2" * 32),
        }
        self.assertEqual(_plan(data, {}, [KEY_A]).remove, ())

    def test_active_legacy_token_keeps_key_even_if_an_activation_for_it_expired(self):
        data = {"1" * 64: _activation(expires_at=(NOW - timedelta(days=1)).isoformat(), keys=(KEY_A,))}
        tokens = {"f" * 64: _token(KEY_A)}
        self.assertEqual(_plan(data, tokens, [KEY_A]).remove, ())

    def test_revoked_legacy_token_peer_is_removed(self):
        tokens = {"f" * 64: _token(KEY_A, status="REVOKED")}
        self.assertEqual(_plan(None, tokens, [KEY_A]).remove, (KEY_A,))

    def test_unknown_manual_peer_is_reported_never_removed(self):
        plan = _plan({"1" * 64: _activation(status="REVOKED", keys=(KEY_A,))}, {}, [KEY_A, KEY_M])
        self.assertEqual(plan.remove, (KEY_A,))
        self.assertEqual(plan.unknown, (KEY_M,))

    def test_disentitled_key_not_present_in_awg_is_not_planned(self):
        plan = _plan({"1" * 64: _activation(status="REVOKED", keys=(KEY_A,))}, {}, [])
        self.assertEqual(plan.remove, ())

    def test_malformed_expiry_fails_closed_with_no_plan(self):
        for bad in ("2099-01-01T00:00:00", "garbage"):
            with self.subTest(bad=bad), self.assertRaises(awg_reconcile.PlanInputError):
                _plan({"1" * 64: _activation(expires_at=bad, keys=(KEY_A,))}, {}, [KEY_A])



class AwgConfigStructureTests(unittest.TestCase):
    """parse_awg_config: the peer set is only trusted when awg0.conf can be
    interpreted unambiguously, in the exact shape lib/peer_mutations.sh
    writes; otherwise PlanInputError (-> no plan, no mutation, no reload)."""

    def _fails_closed(self, text):
        with self.assertRaises(awg_reconcile.PlanInputError) as ctx:
            awg_reconcile.parse_awg_config(text)
        # Never echo file content (PrivateKey/PresharedKey) into the journal.
        self.assertNotIn("test-fixture-not-a-real-private-key", str(ctx.exception))
        self.assertNotIn("sec" + "ret-psk", str(ctx.exception))

    # --- PASS ---
    def test_valid_single_peer(self):
        self.assertEqual(awg_reconcile.parse_awg_config(_awg_conf([KEY_A])), [KEY_A])

    def test_valid_multiple_peers(self):
        self.assertEqual(awg_reconcile.parse_awg_config(_awg_conf([KEY_A, KEY_B, KEY_C])), [KEY_A, KEY_B, KEY_C])

    def test_valid_with_manual_peer_and_preshared_key(self):
        manual = f"[Peer]\n# label: operator-manual\nPublicKey = {KEY_M}\nAllowedIPs = 10.77.0.9/32\nPresharedKey = secret-psk\n\n"
        text = _INTERFACE + _peer_block(KEY_A, "10.77.0.2") + manual + _END
        self.assertEqual(awg_reconcile.parse_awg_config(text), [KEY_A, KEY_M])

    def test_valid_zero_peers_matches_the_template_shape(self):
        self.assertEqual(awg_reconcile.parse_awg_config(_INTERFACE + _END), [])

    def test_interface_is_never_read_as_a_peer(self):
        # [Interface] has no PublicKey; its keys never reach the peer set.
        self.assertEqual(awg_reconcile.parse_awg_config(_awg_conf([KEY_A])), [KEY_A])

    # --- FAIL CLOSED ---
    def test_peer_without_public_key(self):
        self._fails_closed(_INTERFACE + "[Peer]\n# label: x\nAllowedIPs = 10.77.0.2/32\n\n" + _END)

    def test_peer_with_invalid_public_key(self):
        for bad in ("not-a-key", "B" * 43 + "=", KEY_A[:-2] + "=="):
            with self.subTest(bad=bad):
                self._fails_closed(_awg_conf([bad]))

    def test_duplicate_public_key_inside_one_peer(self):
        self._fails_closed(_INTERFACE + f"[Peer]\nPublicKey = {KEY_A}\nPublicKey = {KEY_B}\nAllowedIPs = 10.77.0.2/32\n\n" + _END)

    def test_duplicate_public_key_across_peers(self):
        self._fails_closed(_INTERFACE + _peer_block(KEY_A, "10.77.0.2") + _peer_block(KEY_A, "10.77.0.3") + _END)

    def test_key_line_after_block_terminator_is_ambiguous(self):
        # parse_conf would attribute this line to the peer; mutate_remove_peer's awk would not.
        text = _INTERFACE + f"[Peer]\nPublicKey = {KEY_A}\n\nAllowedIPs = 10.77.0.2/32\n\n" + _END
        self._fails_closed(text)

    def test_last_peer_without_terminating_blank_line(self):
        # The awk removal would swallow the END marker together with this block.
        self._fails_closed(_INTERFACE + f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.77.0.2/32\n" + _END)

    def test_missing_or_duplicated_or_reversed_markers(self):
        body = _peer_block(KEY_A, "10.77.0.2")
        begin = "# --- PEERS BEGIN --- (managed by scripts/add-peer.sh / remove-peer.sh; do not hand-edit below this line)\n"
        no_begin = _INTERFACE.replace(begin, "") + body + _END
        no_end = _INTERFACE + body
        two_end = _INTERFACE + body + _END + _END
        reversed_ = _INTERFACE.replace(begin, _END) + body + begin
        for name, text in (("no_begin", no_begin), ("no_end", no_end), ("two_end", two_end), ("reversed", reversed_)):
            with self.subTest(name):
                self._fails_closed(text)

    def test_peer_outside_markers(self):
        self._fails_closed(_INTERFACE + _END + _peer_block(KEY_A, "10.77.0.2"))

    def test_malformed_peer_sections(self):
        cases = {
            "unknown_field": f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.77.0.2/32\nEndpoint = 1.2.3.4:5\n\n",
            "missing_allowed_ips": f"[Peer]\nPublicKey = {KEY_A}\n\n",
            "non_kv_line": f"[Peer]\nPublicKey = {KEY_A}\nAllowedIPs 10.77.0.2/32\n\n",
            "misspelled_header": f"[Peer ]\nPublicKey = {KEY_A}\nAllowedIPs = 10.77.0.2/32\n\n",
            "unknown_section": f"[Peers]\nPublicKey = {KEY_A}\nAllowedIPs = 10.77.0.2/32\n\n",
        }
        for name, block in cases.items():
            with self.subTest(name):
                self._fails_closed(_INTERFACE + block + _END)

    def test_other_structural_errors(self):
        cases = {
            "second_interface": _INTERFACE.replace("# --- PEERS BEGIN", "[Interface]\nPrivateKey = x\n\n# --- PEERS BEGIN") + _END,
            "no_interface": "# --- PEERS BEGIN ---\n" + _peer_block(KEY_A, "10.77.0.2") + _END,
            "interface_between_markers": _INTERFACE + "[Interface]\nPrivateKey = x\n\n" + _END,
            "content_after_end": _awg_conf([KEY_A]) + "AllowedIPs = 10.77.0.9/32\n",
            "loose_kv_between_peers": _INTERFACE + _peer_block(KEY_A, "10.77.0.2") + "PublicKey = " + KEY_B + "\n" + _END,
            "secret_in_error_path": "PrivateKey = test-fixture-not-a-real-private-key\n" + _awg_conf([KEY_A]),
            "empty_input": "",
        }
        for name, text in cases.items():
            with self.subTest(name):
                self._fails_closed(text)


class PlannerCliTests(unittest.TestCase):
    """main() against real store files, the real config loader and the
    real shared-lock readers the API itself uses."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        d = self._tmp.name
        self.activation_store = os.path.join(d, "activations.json")
        self.activation_lock = self.activation_store + ".lock"  # config.py's own default
        self.token_store = os.path.join(d, "tokens.json")
        self.token_lock = self.token_store + ".lock"
        activations_module.init_store(self.activation_store, self.activation_lock)
        self._write(self.token_store, {})
        open(self.token_lock, "w").close()
        provision_script = os.path.join(d, "provision-peer.sh")
        open(provision_script, "w").close()
        self.env_file = os.path.join(d, "api.env")
        with open(self.env_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join([
                "POCVPN_API_ENDPOINT_HOST=203.0.113.1",
                "POCVPN_API_ENDPOINT_PORT=51820",
                f"POCVPN_API_GATEWAY_PUBLIC_KEY={_key(0x77)}",
                "POCVPN_API_GATEWAY_TUNNEL_IP=10.77.0.1",
                f"POCVPN_API_TOKEN_STORE_PATH={self.token_store}",
                f"POCVPN_API_PROVISION_SCRIPT_PATH={provision_script}",
                "POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS=5",
                "POCVPN_API_API_PORT=8443",
                f"POCVPN_API_ACTIVATION_STORE_PATH={self.activation_store}",
                "",
            ]))

    @staticmethod
    def _write(path, data):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    def _run(self, peers, now=NOW):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = awg_reconcile.main(
                ["--env-file", self.env_file, "--now", now.isoformat()],
                stdin=io.StringIO(peers if isinstance(peers, str) else _awg_conf(peers)), stdout=out,
            )
        return rc, out.getvalue().split(), err.getvalue()

    def test_revoked_and_expired_planned_active_and_unknown_kept(self):
        self._write(self.activation_store, {
            "1" * 64: _activation(keys=(KEY_A,), activation_id="1" * 32),
            "2" * 64: _activation(status="REVOKED", keys=(KEY_B,), activation_id="2" * 32),
            "3" * 64: _activation(expires_at=(NOW - timedelta(minutes=1)).isoformat(), keys=(KEY_C,), activation_id="3" * 32),
        })
        rc, removed, err = self._run([KEY_A, KEY_B, KEY_C, KEY_M])
        self.assertEqual(rc, awg_reconcile.EXIT_OK)
        self.assertEqual(set(removed), {KEY_B, KEY_C})
        self.assertIn("reported only, NOT removed", err)

    def test_corrupt_activation_store_fails_closed(self):
        with open(self.activation_store, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        rc, removed, err = self._run([KEY_A])
        self.assertEqual(rc, awg_reconcile.EXIT_STORE)
        self.assertEqual(removed, [])
        self.assertIn("FAIL CLOSED", err)

    def test_missing_activation_store_fails_closed(self):
        os.unlink(self.activation_store)
        rc, removed, _err = self._run([KEY_A])
        self.assertEqual((rc, removed), (awg_reconcile.EXIT_STORE, []))

    def test_missing_lock_file_fails_closed(self):
        os.unlink(self.activation_lock)
        rc, removed, _err = self._run([KEY_A])
        self.assertEqual((rc, removed), (awg_reconcile.EXIT_STORE, []))

    def test_corrupt_token_store_fails_closed(self):
        with open(self.token_store, "w", encoding="utf-8") as handle:
            handle.write("[]")
        self._write(self.activation_store, {"2" * 64: _activation(status="REVOKED", keys=(KEY_B,))})
        rc, removed, _err = self._run([KEY_B])
        self.assertEqual((rc, removed), (awg_reconcile.EXIT_STORE, []))

    def test_naive_expiry_in_store_fails_closed(self):
        self._write(self.activation_store, {"2" * 64: _activation(expires_at="2000-01-01T00:00:00", keys=(KEY_B,))})
        rc, removed, _err = self._run([KEY_B])
        self.assertEqual((rc, removed), (awg_reconcile.EXIT_STORE, []))

    def test_malformed_awg_config_fails_closed_even_with_a_revoked_key(self):
        self._write(self.activation_store, {"2" * 64: _activation(status="REVOKED", keys=(KEY_B,))})
        ambiguous = _INTERFACE + f"[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.77.0.2/32\n" + _END
        rc, removed, err = self._run(ambiguous)
        self.assertEqual((rc, removed), (awg_reconcile.EXIT_STORE, []))
        self.assertIn("structural validation", err)

    def test_bad_env_file_is_a_config_error(self):
        out = io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()):
            rc = awg_reconcile.main(["--env-file", os.path.join(self._tmp.name, "missing.env")], stdin=io.StringIO(""), stdout=out)
        self.assertEqual((rc, out.getvalue()), (awg_reconcile.EXIT_CONFIG, ""))

    def test_planner_waits_for_an_in_flight_store_write(self):
        """The planner reads through the store's shared lock, so it can
        never observe a half-applied decide_and_bind/revoke."""
        self._write(self.activation_store, {"2" * 64: _activation(status="REVOKED", keys=(KEY_B,))})
        import fcntl
        fd = os.open(self.activation_lock, os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        result = {}
        thread = threading.Thread(target=lambda: result.setdefault("r", self._run([KEY_B])))
        thread.start()
        time.sleep(0.3)
        self.assertNotIn("r", result)  # blocked behind the exclusive writer
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        thread.join(5)
        self.assertEqual(result["r"][1], [KEY_B])

    def test_revoke_racing_in_flight_provisioning_ends_with_the_peer_planned_for_removal(self):
        """revoke_activation blocks on the per-activation lock an in-flight
        provision_with_activation holds; while it waits the key is still
        entitled (kept), and once the revoke lands the next reconcile
        removes it - no permanently stale peer."""
        activation_id, credential = activations_module.issue_activation(self.activation_store, self.activation_lock, 1)
        activations_module.decide_and_bind(credential, KEY_A, self.activation_store, self.activation_lock)
        activations_module.finalize_reservation(credential, KEY_A, self.activation_store, self.activation_lock)
        digest = activations_module.credential_digest(credential)
        done = threading.Event()
        with activations_module.per_activation_lock(self.activation_store, digest):
            thread = threading.Thread(target=lambda: (
                activations_module.revoke_activation(self.activation_store, self.activation_lock, activation_id), done.set()))
            thread.start()
            time.sleep(0.3)
            self.assertFalse(done.is_set())  # revoke serialized behind "provisioning"
            rc, removed, _err = self._run([KEY_A], now=datetime.now(timezone.utc))
            self.assertEqual((rc, removed), (awg_reconcile.EXIT_OK, []))
        thread.join(5)
        self.assertTrue(done.is_set())
        rc, removed, _err = self._run([KEY_A], now=datetime.now(timezone.utc))
        self.assertEqual((rc, removed), (awg_reconcile.EXIT_OK, [KEY_A]))


class RevokeTriggerTests(unittest.TestCase):
    def test_trigger_requests_a_non_blocking_start_of_the_reconcile_unit(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(activation_tokens._trigger_awg_reconcile(runner=runner))
        argv = runner.call_args.args[0]
        self.assertEqual(argv, ["systemctl", "start", "--no-block", "pocvpn-awg-reconcile.service"])

    def test_trigger_failure_is_reported_not_raised(self):
        for runner in (
            mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "Unit not found.")),
            mock.Mock(side_effect=FileNotFoundError("systemctl")),
            mock.Mock(side_effect=subprocess.TimeoutExpired("systemctl", 10)),
        ):
            err = io.StringIO()
            with self.subTest(runner=runner), contextlib.redirect_stderr(err):
                self.assertFalse(activation_tokens._trigger_awg_reconcile(runner=runner))
            self.assertIn("WARNING", err.getvalue())

    def test_revoke_is_durable_even_when_the_trigger_fails_and_is_skippable(self):
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "activations.json")
            lock = store + ".lock"  # activation_tokens.py's own --lock default
            activations_module.init_store(store, lock)
            activation_id, _cred = activations_module.issue_activation(store, lock, 1)
            with mock.patch.object(activation_tokens, "_trigger_awg_reconcile", return_value=False) as trig, \
                    contextlib.redirect_stdout(io.StringIO()):
                activation_tokens.main(["--store", store, "revoke", activation_id])
            trig.assert_called_once()
            self.assertEqual(activations_module.find_by_activation_id(store, lock, activation_id)["status"], "REVOKED")
            with mock.patch.object(activation_tokens, "_trigger_awg_reconcile") as trig, \
                    contextlib.redirect_stdout(io.StringIO()):
                activation_tokens.main(["--store", store, "revoke", activation_id, "--no-awg-reconcile"])
            trig.assert_not_called()


if __name__ == "__main__":
    unittest.main()
