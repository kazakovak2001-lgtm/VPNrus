"""Runs the shell blocks of gateway/DEPLOYMENT.md "REALITY + XHTTP on
Stockholm" exactly as written (extracted by their <!-- rx-block:NAME -->
markers) against a throwaway directory tree.

`sudo`, `systemd-run` and `systemctl` are replaced by stubs on PATH: sudo
runs the command as the test user (dropping -u/-o/-g, which need root),
systemd-run runs it in the requested WorkingDirectory with the requested
EnvironmentFile loaded, systemctl only logs. The Python check inside
rx_check_api is NOT stubbed: it compiles/imports the real api package and
loads its config. Owner/group changes and the real systemd behaviour are
therefore not covered here - only ordering, guards, idempotence and what
changes on disk.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
_REPO_DIR = os.path.dirname(_GATEWAY_DIR)
_DEPLOYMENT_MD = os.path.join(_GATEWAY_DIR, "DEPLOYMENT.md")
_API_DIR = os.path.join(_GATEWAY_DIR, "api")
_TARGET_REV = "21e70783c63cb021c2fd606492b2d09268e56d53"
_PY = "/usr/bin/python3"
_TS = "20261027T120000Z"


def _blocks():
    text = open(_DEPLOYMENT_MD, encoding="utf-8").read().replace("\r\n", "\n")
    section = text[text.index("## REALITY + XHTTP on Stockholm"):text.index("## REALITY Frankfurt on TCP/443")]
    return dict(re.findall(r"<!-- rx-block:([a-z-]+) -->\n\n```\n(.*?)```", section, re.S))


def _runtime_files():
    return sorted(f for f in os.listdir(_API_DIR) if f.endswith(".py"))


_STUBS = {
    "sudo": """#!/bin/sh
[ "$1" = "-u" ] && shift 2
if [ "$1" = install ]; then
  shift
  while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) break ;; esac; done
  exec install "$@"
fi
exec "$@"
""",
    "systemd-run": """#!/bin/sh
echo "systemd-run-args $*" >> "$RX_LOG"
wd=; ef=
while [ $# -gt 0 ]; do
  case "$1" in
    -p) case "$2" in WorkingDirectory=*) wd=${2#*=} ;; EnvironmentFile=*) ef=${2#*=} ;; Environment=*) export "${2#Environment=}" ;; esac; shift 2 ;;
    --*) shift ;;
    *) break ;;
  esac
done
echo "systemd-run $wd" >> "$RX_LOG"
cd "$wd" || exit 1
set -a; . "$ef"; set +a
exec "$@"
""",
    "systemctl": """#!/bin/sh
echo "systemctl $*" >> "$RX_LOG"
case "$*" in
  *is-active*nova-xray-reconcile*) [ -n "$RX_RECONCILE_ACTIVE" ] && exit 0; exit 3 ;;
  "show -p MainPID --value nova-xray") echo "${RX_XRAY_PID:-0}" ;;
  is-active*) echo active ;;
esac
exit 0
""",
    "ss": """#!/bin/sh
[ -n "$RX_SS_OUT" ] && printf '%s\\n' "$RX_SS_OUT"
exit 0
""",
    # The test user cannot chown, so the OWNER is emulated (RX_FAKE_OWNER,
    # default the production root:pocvpn-api) and only the MODE is real. This
    # proves the block checks owner+mode - never that production owners are right.
    "stat": """#!/bin/sh
[ "$1" = -c ] && [ "$2" = '%U:%G %a' ] && { printf '%s %s\\n' "${RX_FAKE_OWNER:-root:pocvpn-api}" "$(/usr/bin/stat -c %a "$3")"; exit $?; }
exec /usr/bin/stat "$@"
""",
}


@unittest.skipUnless(os.name == "posix" and os.path.exists(_PY) and shutil.which("bash"), "needs POSIX bash and /usr/bin/python3")
class RxRolloutBlocksTest(unittest.TestCase):
    blocks = _blocks()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        r = self.root = self._tmp.name
        self.opt = os.path.join(r, "opt")
        self.gw = os.path.join(self.opt, "gateway")
        self.etc = os.path.join(r, "etc")
        self.home = os.path.join(r, "home")
        self.bin = os.path.join(r, "bin")
        self.log = os.path.join(r, "rx.log")
        for d in (self.gw, self.etc, self.home, self.bin):
            os.makedirs(d)
        for name, body in _STUBS.items():
            path = os.path.join(self.bin, name)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(body)
            os.chmod(path, 0o755)
        self.envf = os.path.join(self.etc, "api.env")
        script = os.path.join(r, "provision-peer.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(script, 0o755)
        self._write(self.envf, "".join(f"{k}={v}\n" for k, v in {
            "POCVPN_API_ENDPOINT_HOST": "203.0.113.1",
            "POCVPN_API_ENDPOINT_PORT": "51820",
            "POCVPN_API_GATEWAY_PUBLIC_KEY": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            "POCVPN_API_GATEWAY_TUNNEL_IP": "10.77.0.1",
            "POCVPN_API_TOKEN_STORE_PATH": os.path.join(r, "tokens.json"),
            "POCVPN_API_PROVISION_SCRIPT_PATH": script,
            "POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS": "5",
            "POCVPN_API_API_PORT": "8765",
        }.items()))
        os.chmod(self.envf, 0o640)

    # --- helpers -------------------------------------------------------

    def _write(self, path, data, mode="w"):
        with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8", "newline": "\n"})) as f:
            f.write(data)

    def _read(self, path, mode="r"):
        with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
            return f.read()

    def _run(self, *names, helpers=True, extra="", cwd=None, **env):
        script = "\n".join(([self.blocks["helpers"]] if helpers else []) + [self.blocks[n] for n in names] + [extra])
        full_env = {
            "PATH": f"{self.bin}:/usr/bin:/bin", "HOME": self.home, "RX_LOG": self.log,
            "GW": self.gw, "ENVF": self.envf, "MD": self.etc, "LC_ALL": "C",
        }
        full_env.update(env)
        r = subprocess.run(["bash", "-c", script], env=full_env, cwd=cwd, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def _log(self):
        return self._read(self.log) if os.path.exists(self.log) else ""

    def _live_api(self, mutate=None, drop=()):
        live = os.path.join(self.gw, "api")
        os.makedirs(live)
        for f in _runtime_files():
            if f not in drop:
                shutil.copy(os.path.join(_API_DIR, f), live)
                os.chmod(os.path.join(live, f), 0o644)  # production model (deploy-backend-update.sh)
        if mutate:
            for f in mutate:
                self._write(os.path.join(live, f), self._read(os.path.join(live, f)) + "\n# live-old\n")
        return live

    def _snapshot_tar(self, extra=None):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for d in ("gateway/", "gateway/api/"):
                info = tarfile.TarInfo(d.rstrip("/"))
                info.type = tarfile.DIRTYPE
                info.mode = 0o755  # as git archive writes them
                tar.addfile(info)
            for f in _runtime_files():
                tar.add(os.path.join(_API_DIR, f), arcname=f"gateway/api/{f}")
            if extra:
                data = b"x = 1\n"
                info = tarfile.TarInfo(extra)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        blob = buf.getvalue()
        self._write(os.path.join(self.home, "rx-api-21e7078.tar"), blob, "wb")
        return hashlib.sha256(blob).hexdigest()

    def _stage(self, **kw):
        sha = self._snapshot_tar()
        out = self._run("stage", RXSHA=sha, **kw)
        ts = re.search(r"TS=(\d{8}T\d{6}Z)", out)
        return out, (ts.group(1) if ts else None)

    def _opt_extras(self):
        return sorted(d for d in os.listdir(self.opt) if d != "gateway")

    def _same_as_snapshot(self, d):
        return all(self._read(os.path.join(d, f), "rb") == self._read(os.path.join(_API_DIR, f), "rb") for f in _runtime_files())

    # --- snapshot definition --------------------------------------------

    def test_documented_runtime_count_matches_the_target_commit(self):
        self.assertIn("-eq 29 ]", self.blocks["stage"])
        self.assertEqual(len(_runtime_files()), 29)
        try:
            listed = subprocess.run(["git", "-C", _REPO_DIR, "ls-tree", "--name-only", _TARGET_REV, "gateway/api/"],
                                    capture_output=True, text=True, timeout=30)
        except OSError:
            self.skipTest("git not available")
        if listed.returncode != 0:
            self.skipTest("target commit not in this clone")
        self.assertEqual(sorted(p.split("/")[-1] for p in listed.stdout.split() if p.endswith(".py")), _runtime_files())

    def test_every_block_parses_in_bash_and_posix_sh(self):
        self.assertEqual(set(self.blocks), {"helpers", "inventory-compare", "stage", "swap", "env-set",
                                            "manifest-install", "rollback-env", "rollback-api", "rollback-manifest"})
        for sh in ("bash", "dash"):
            if not shutil.which(sh):
                continue
            for name, body in self.blocks.items():
                r = subprocess.run([sh, "-n"], input=self.blocks["helpers"] + "\n" + body, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, f"{sh} -n {name}: {r.stderr}")

    # --- 1b stage -------------------------------------------------------

    def test_stage_reports_new_and_changed_and_leaves_live_untouched(self):
        live = self._live_api(mutate=["config.py"], drop=["admin_auth.py"])
        before = {f: self._read(os.path.join(live, f), "rb") for f in os.listdir(live)}
        out, ts = self._stage()
        self.assertIn("new      admin_auth.py", out)
        self.assertIn("changed  config.py", out)
        self.assertIn("staged", out)
        self.assertTrue(self._same_as_snapshot(os.path.join(self.opt, f"rx-stage-{ts}", "api")))
        self.assertEqual(os.listdir(self.gw), ["api"])  # nothing staged inside the served tree
        self.assertEqual(before, {f: self._read(os.path.join(live, f), "rb") for f in os.listdir(live)})
        self.assertNotIn("systemctl", self._log())

    def test_stage_stops_on_wrong_hash(self):
        self._live_api()
        self._snapshot_tar()
        out = self._run("stage", RXSHA="0" * 64)
        self.assertNotIn("staged", out)
        self.assertFalse(os.path.exists(os.path.join(self.home, "rx-api-21e7078")))
        self.assertEqual(self._opt_extras(), [])

    def test_stage_stops_on_unexpected_archive_entry(self):
        self._live_api()
        sha = self._snapshot_tar(extra="gateway/api/tests/test_x.py")
        out = self._run("stage", RXSHA=sha)
        self.assertNotIn("staged", out)
        self.assertEqual(self._opt_extras(), [])

    def test_stage_stops_on_live_only_runtime_file(self):
        live = self._live_api()
        self._write(os.path.join(live, "unknown_module.py"), "x = 1\n")
        out, _ = self._stage()
        self.assertIn("live-only runtime files: unknown_module.py - STOP", out)
        self.assertEqual(self._opt_extras(), [])

    # --- 1c in-place install + rollback-api -------------------------------

    def _module_not_imported_by_server(self):
        code = ("import sys, os, api.server; print(sorted(f for f in os.listdir('api') if f.endswith('.py') "
                "and f != '__init__.py' and 'api.' + f[:-3] not in sys.modules)[0])")
        return subprocess.run([_PY, "-B", "-c", code], cwd=_GATEWAY_DIR, capture_output=True, text=True,
                              check=True).stdout.strip()

    def test_swap_replaces_in_place_with_a_full_backup_and_rollback_restores(self):
        added = self._module_not_imported_by_server()
        live = self._live_api(mutate=["config.py", "handler.py"], drop=[added])
        # Only the api/ DIRECTORY inode is preserved (it is never renamed or
        # recreated). Replaced FILES get new inodes (install + mv -f), so the
        # contract checked for files is name set, bytes and mode, not inode.
        dir_inode = os.stat(live).st_ino
        old = {f: self._read(os.path.join(live, f), "rb") for f in os.listdir(live)}
        _, ts = self._stage()
        out = self._run("swap", TS=ts)
        self.assertIn("compile+import+config OK", out)
        self.assertTrue(self._same_as_snapshot(live))
        self.assertEqual(os.stat(live).st_ino, dir_inode)  # api/ directory never renamed away
        self.assertEqual(os.listdir(self.gw), ["api"])
        self.assertEqual([f for f in os.listdir(live) if f.endswith(".rx-tmp")], [])
        backup = os.path.join(self.opt, "gateway-backups", f"gateway-rx-{ts}", "api")
        self.assertEqual({f: self._read(os.path.join(backup, f), "rb") for f in os.listdir(backup)}, old)
        self.assertEqual(self._log().count("systemctl restart pocvpn-api"), 1)
        self.assertEqual(self._log().count("systemd-run-args"), 2)  # staged, then live
        self.assertIn("-p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes", self._log())

        self._run("rollback-api", TS=ts)
        self.assertEqual({f: self._read(os.path.join(live, f), "rb") for f in os.listdir(live)}, old)
        self.assertFalse(os.path.exists(os.path.join(live, added)))  # added by the rollout, removed again
        self.assertEqual(os.stat(live).st_ino, dir_inode)
        self.assertEqual([f for f in os.listdir(live) if f.endswith(".rx-tmp")], [])
        # Owner (root:root) needs a root run; the mode is what this user can prove.
        self.assertEqual({oct(os.stat(os.path.join(live, f)).st_mode & 0o777) for f in os.listdir(live)}, {"0o644"})
        self.assertEqual(self._log().count("systemctl restart pocvpn-api"), 2)

    def test_rollback_api_refuses_a_backup_that_does_not_import(self):
        live = self._live_api(mutate=["config.py"])
        _, ts = self._stage()
        self._run("swap", TS=ts)
        self._write(os.path.join(self.opt, "gateway-backups", f"gateway-rx-{ts}", "api", "config.py"), "def broken(:\n")
        self._run("rollback-api", TS=ts)
        self.assertTrue(self._same_as_snapshot(live))
        self.assertEqual(self._log().count("systemctl restart pocvpn-api"), 1)

    def test_swap_and_rollback_refuse_while_reconcile_can_run(self):
        live = self._live_api(mutate=["config.py"])
        old = self._read(os.path.join(live, "config.py"))
        _, ts = self._stage()
        out = self._run("swap", TS=ts, RX_RECONCILE_ACTIVE="1")
        self.assertIn("nova-xray-reconcile timer/service active - STOP", out)
        self.assertEqual(self._read(os.path.join(live, "config.py")), old)
        self.assertFalse(os.path.exists(os.path.join(self.opt, "gateway-backups")))
        self.assertNotIn("restart", self._log())
        # the guard only observes: it never stops or starts the timer itself
        self.assertNotRegex(self._log(), r"systemctl (stop|start) nova-xray-reconcile")

        self._run("swap", TS=ts)
        after_swap = self._api_state(live)
        checks = self._log().count("systemd-run-args")
        out = self._run("rollback-api", TS=ts, RX_RECONCILE_ACTIVE="1")
        self.assertIn("nova-xray-reconcile timer/service active - STOP", out)
        self.assertEqual(self._api_state(live), after_swap)
        self.assertEqual(self._log().count("systemd-run-args"), checks)  # stopped before any temp write
        self.assertEqual(self._log().count("systemctl restart pocvpn-api"), 1)
        self.assertNotRegex(self._log(), r"systemctl (stop|start) nova-xray-reconcile")

    def _api_state(self, live):
        return {f: (self._read(os.path.join(live, f), "rb"), os.stat(os.path.join(live, f)).st_mode)
                for f in os.listdir(live)}

    def test_rollback_api_refuses_a_live_file_that_appeared_after_staging(self):
        live = self._live_api(mutate=["config.py"])
        _, ts = self._stage()
        self._run("swap", TS=ts)
        late = os.path.join(live, "late_module.py")
        self._write(late, "LATE = 1\n")
        before = self._api_state(live)
        checks = self._log().count("systemd-run-args")
        out = self._run("rollback-api", TS=ts)
        self.assertIn("live *.py not in this rollout's staged set: late_module.py - STOP, nothing changed", out)
        self.assertEqual(self._read(late), "LATE = 1\n")  # never deleted, moved or overwritten
        self.assertEqual(self._api_state(live), before)
        self.assertEqual(self._log().count("systemd-run-args"), checks)
        self.assertEqual(self._log().count("systemctl restart pocvpn-api"), 1)

    def test_rollback_api_refuses_without_the_staged_inventory(self):
        live = self._live_api(mutate=["config.py"])
        _, ts = self._stage()
        self._run("swap", TS=ts)
        shutil.rmtree(os.path.join(self.opt, f"rx-stage-{ts}"))
        before = self._api_state(live)
        self._run("rollback-api", TS=ts)
        self.assertEqual(self._api_state(live), before)
        self.assertEqual(self._log().count("systemctl restart pocvpn-api"), 1)

    def test_rollback_a4_documents_the_reconcile_pause(self):
        text = open(_DEPLOYMENT_MD, encoding="utf-8").read().replace("\r\n", "\n")
        rollback = text[text.index("### Rollback\n", text.index("## REALITY + XHTTP on Stockholm")):]
        a4 = " ".join(rollback[rollback.index("  4. the API block below"):rollback.index("- **B - after step 6**")].split())
        for phrase in ("separately approved `PRODUCTION MUTATION` (`sudo systemctl stop nova-xray-reconcile.timer`)",
                       "confirm `systemctl is-active nova-xray-reconcile.timer nova-xray-reconcile.service` prints `inactive`",
                       "only CHECKS this (`rx_reconcile_paused`); it never stops or starts the timer",
                       "the block stops before any file is touched",
                       "resume the timer only through the separately approved step",
                       "says `converged`"):
            self.assertIn(phrase, a4)

    def test_swap_refuses_a_staged_package_that_does_not_import(self):
        live = self._live_api(mutate=["config.py"])
        old = self._read(os.path.join(live, "config.py"))
        _, ts = self._stage()
        self._write(os.path.join(self.opt, f"rx-stage-{ts}", "api", "admin_auth.py"), "def broken(:\n")
        self._run("swap", TS=ts)
        self.assertEqual(self._read(os.path.join(live, "config.py")), old)
        self.assertFalse(os.path.exists(os.path.join(self.opt, "gateway-backups")))
        self.assertNotIn("restart", self._log())

    def test_swap_does_nothing_without_ts_or_without_helpers(self):
        live = self._live_api(mutate=["config.py"])
        old = self._read(os.path.join(live, "config.py"))
        _, ts = self._stage()
        for kw in ({"TS": ""}, {"TS": "2026-10-27"}):
            self.assertIn("TS unset/invalid - STOP", self._run("swap", **kw))
        self._run("swap", helpers=False, TS=ts, GW=self.gw)
        self.assertEqual(self._read(os.path.join(live, "config.py")), old)
        self.assertNotIn("restart", self._log())

    # --- 3 env-set + rollback-env ---------------------------------------

    def _stub_api(self, fail_on_xhttp=False):
        live = os.path.join(self.gw, "api")
        os.makedirs(live)
        self._write(os.path.join(live, "__init__.py"), "")
        self._write(os.path.join(live, "server.py"), (
            "import os, types\n"
            "def _load():\n"
            f"    if {fail_on_xhttp!r} and os.environ.get('POCVPN_API_XRAY_REALITY_XHTTP_SERVER_PORT'):\n"
            "        raise SystemExit('config error')\n"
            "config_module = types.SimpleNamespace(load_config=_load)\n"
            "ingress_config_module = types.SimpleNamespace(load_ingress_config=lambda: None)\n"))

    def _xhttp_lines(self):
        return [l for l in self._read(self.envf).splitlines() if l.startswith("POCVPN_API_XRAY_REALITY_XHTTP_")]

    def test_env_set_is_idempotent_and_keeps_the_original_backup(self):
        self._stub_api()
        original = self._read(self.envf)
        out = self._run("env-set", TS=_TS, XPORT="2096")
        self.assertIn("api.env updated", out)
        self.assertEqual(self._xhttp_lines(), ["POCVPN_API_XRAY_REALITY_XHTTP_SERVER_PORT=2096",
                                               "POCVPN_API_XRAY_REALITY_XHTTP_PATH=/nova-rx/"])
        self.assertEqual(oct(os.stat(self.envf).st_mode & 0o777), "0o640")
        out = self._run("env-set", TS=_TS, XPORT="2096")
        self.assertIn("already has exactly these lines - unchanged", out)
        self.assertEqual(len(self._xhttp_lines()), 2)
        self.assertEqual(self._read(f"{self.envf}.backup-rx-{_TS}"), original)
        self.assertEqual(self._log().count("systemctl restart pocvpn-api"), 2)

        self._run("rollback-env", TS=_TS)
        self.assertEqual(self._read(self.envf), original)

    def test_env_set_stops_on_conflicting_lines_or_bad_port(self):
        self._stub_api()
        self._write(self.envf, self._read(self.envf) + "POCVPN_API_XRAY_REALITY_XHTTP_SERVER_PORT=2097\n")
        before = self._read(self.envf)
        self.assertIn("other XHTTP lines - STOP", self._run("env-set", TS=_TS, XPORT="2096"))
        for port in ("", "20 96", "70000"):
            self._run("env-set", TS=_TS, XPORT=port)
        self.assertEqual(self._read(self.envf), before)
        self.assertNotIn("restart", self._log())

    def test_env_set_does_not_merge_into_a_last_line_without_newline(self):
        self._stub_api()
        self._write(self.envf, self._read(self.envf).rstrip("\n"))
        self._run("env-set", TS=_TS, XPORT="2096")
        self.assertIn("POCVPN_API_API_PORT=8765", self._read(self.envf).splitlines())
        self.assertEqual(len(self._xhttp_lines()), 2)

    def test_env_set_does_not_restart_when_the_new_env_fails_to_load(self):
        self._stub_api(fail_on_xhttp=True)
        self._run("env-set", TS=_TS, XPORT="2096")
        self.assertNotIn("restart", self._log())
        self._run("rollback-env", TS=_TS)
        self.assertEqual(self._xhttp_lines(), [])
        self.assertEqual(self._log().count("systemctl restart pocvpn-api"), 1)

    def test_real_config_rejects_xhttp_without_the_reality_group(self):
        self._live_api()
        out = self._run("env-set", TS=_TS, XPORT="2096")
        self.assertNotIn("compile+import+config OK", out)
        self.assertNotIn("restart", self._log())

    # --- 6c manifest install + rollback-manifest --------------------------

    def _manifests(self):
        served = os.path.join(self.etc, "endpoint-manifest.bin")
        self._write(served, b"v8", "wb")
        os.chmod(served, 0o640)
        self._write(os.path.join(self.home, "endpoint-manifest-v9.bin"), b"v9", "wb")
        self._write(os.path.join(self.home, "endpoint-manifest-v10.bin"), b"v10", "wb")
        return served, hashlib.sha256(b"v9").hexdigest(), hashlib.sha256(b"v10").hexdigest()

    def test_v9_is_served_only_with_a_verified_v10_standby(self):
        served, sha9, sha10 = self._manifests()
        out = self._run("manifest-install", TS=_TS, SHA9=sha9, SHA10=sha10)
        self.assertIn("v9 served, v10 standby", out)
        self.assertEqual(self._read(served, "rb"), b"v9")
        self.assertEqual(oct(os.stat(served).st_mode & 0o777), "0o640")
        self.assertEqual(self._read(os.path.join(self.etc, "endpoint-manifest-v10-rollback.bin"), "rb"), b"v10")
        self.assertEqual(self._read(os.path.join(self.etc, f"endpoint-manifest.bin.v8-backup-{_TS}"), "rb"), b"v8")

        self.assertIn("v10 served", self._run("rollback-manifest", TS=_TS, SHA10=sha10))
        self.assertEqual(self._read(served, "rb"), b"v10")

    def test_manifest_install_reports_failure_on_a_wrong_owner(self):
        _, sha9, sha10 = self._manifests()
        out = self._run("manifest-install", TS=_TS, SHA9=sha9, SHA10=sha10, RX_FAKE_OWNER="pocvpn-api:pocvpn-api")
        self.assertNotIn("v9 served", out)

    def test_v9_is_not_served_without_v10(self):
        served, sha9, sha10 = self._manifests()
        os.remove(os.path.join(self.home, "endpoint-manifest-v10.bin"))
        self._run("manifest-install", TS=_TS, SHA9=sha9, SHA10=sha10)
        self._run("manifest-install", TS=_TS, SHA9=sha9, SHA10="")
        self._run("manifest-install", TS=_TS, SHA9=sha9, SHA10=sha9)
        self.assertEqual(self._read(served, "rb"), b"v8")
        self.assertFalse(os.path.exists(os.path.join(self.etc, "endpoint-manifest-v10-rollback.bin")))

    # --- 0a port owner (read-only) -----------------------------------------

    def test_port_owner_absent_and_nova_xray(self):
        own = 'LISTEN 0 4096 *:2096 *:* users:(("xray",pid=4242,fd=7))'
        other = 'LISTEN 0 511 0.0.0.0:2096 0.0.0.0:* users:(("nginx",pid=99,fd=6))'
        check = lambda mode, **kw: self._run(extra=f"rx_port_owner {mode} && echo PASS", XPORT="2096", **kw)
        self.assertIn("PASS", check("absent"))
        self.assertIn("already in use, owner not configured by this repository - STOP", check("absent", RX_SS_OUT=own))
        self.assertIn("PASS", check("nova-xray", RX_SS_OUT=own, RX_XRAY_PID="4242"))
        self.assertNotIn("PASS", check("nova-xray", RX_SS_OUT=other, RX_XRAY_PID="4242"))
        self.assertNotIn("PASS", check("nova-xray", RX_SS_OUT=own + "\n" + other, RX_XRAY_PID="4242"))
        self.assertNotIn("PASS", check("nova-xray", RX_XRAY_PID="4242"))  # listener missing
        self.assertNotIn("PASS", check("nova-xray", RX_SS_OUT=own, RX_XRAY_PID="0"))  # nova-xray not running
        self.assertNotIn("PASS", self._run(extra="rx_port_owner absent && echo PASS", XPORT=""))

    # --- 0b inventory compare (read-only, owner's PC) ---------------------

    def _inventory(self, target, known_old, live):
        for name, rows in (("rx-target", target), ("rx-known-old", known_old), ("rx-live", live)):
            self._write(os.path.join(self.root, f"{name}.sha256"), "".join(f"{h}  api/{f}\n" for f, h in rows.items()))
        return self._run("inventory-compare", helpers=False, cwd=self.root)

    def test_inventory_classifies_names_and_hashes(self):
        a, b, c = "a" * 64, "b" * 64, "c" * 64
        target = {"config.py": a, "admin_auth.py": a, "wgkey.py": a}
        known_old = {"config.py": b, "wgkey.py": a}
        out = self._inventory(target, known_old, {"config.py": b, "wgkey.py": a})
        self.assertIn("known-old    config.py", out)
        self.assertIn("new          admin_auth.py", out)
        self.assertIn("current      wgkey.py", out)
        self.assertIn("INVENTORY: OK", out)
        for live, marker in (({"config.py": b, "wgkey.py": a, "extra.py": a}, "SERVER-ONLY  extra.py"),
                             ({"config.py": c, "wgkey.py": a}, "UNEXPECTED   config.py"),
                             ({"config.py": b}, "MISSING      wgkey.py")):
            out = self._inventory(target, known_old, live)
            self.assertIn(marker, out)
            self.assertIn("INVENTORY: BLOCK", out)


if __name__ == "__main__":
    unittest.main()
