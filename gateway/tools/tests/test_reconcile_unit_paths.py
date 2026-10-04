"""B47 Frankfurt - the reconcile units' systemd sandbox covers exactly the
paths the reconcile code writes, per host.

Write sets are derived from the code paths, not guessed:
  xray_activation.activate_if_needed - XRAY_ACTIVATION_LOCK_PATH is opened
    O_RDWR on every run (xray_provisioning._exclusive_lock); the last hash
    and the staging config are written via mkstemp/replace in their
    directories; the sudo nova-xray-reload root child publishes into
    xray.env's XRAY_LIVE_CONFIG_DIR inside this unit's mount namespace.
  activation/xray/token stores and their locks are opened O_RDONLY only
    (read_store_shared), so their directories need no write access.
  reconcile-peers.sh (AWG) writes only poc.env's CONFIG_DIR."""
import os
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))

_XRAY_UNIT = os.path.join(_GATEWAY_DIR, "systemd", "nova-xray-reconcile.service")
_AWG_UNIT = os.path.join(_GATEWAY_DIR, "systemd", "pocvpn-awg-reconcile.service")
_FRANKFURT_DROPIN = os.path.join(_GATEWAY_DIR, "hosts", "frankfurt", "nova-xray-reconcile.service.d", "paths.conf")
_FRANKFURT_ENV = os.path.join(_THIS_DIR, "fixtures", "frankfurt-api-paths.env")
_API_ENV_EXAMPLE = os.path.join(_GATEWAY_DIR, "config", "api.env.example")
_XRAY_ENV = os.path.join(_GATEWAY_DIR, "config", "xray.env")
_POC_ENV = os.path.join(_GATEWAY_DIR, "config", "poc.env")

_BROAD = {"/", "/etc", "/var", "/var/lib", "/opt", "/usr", "/run"}


def _read_env(path):
    result = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                result[key.strip()] = value.strip()
    return result


def _read_write_paths(*unit_files):
    """systemd semantics: assignments accumulate, an empty assignment resets
    the list, a leading '-' only makes a missing path non-fatal."""
    paths = []
    for unit_file in unit_files:
        with open(unit_file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line.startswith("ReadWritePaths="):
                    continue
                value = line.partition("=")[2].strip()
                if not value:
                    paths = []
                    continue
                paths.extend(p.lstrip("-") for p in value.split())
    return paths


def _covered(path, rw_paths):
    path = os.path.normpath(path)
    return any(path == rw or path.startswith(rw.rstrip("/") + "/") for rw in map(os.path.normpath, rw_paths))


def _xray_write_dirs(api_env, xray_env):
    return {
        os.path.dirname(api_env["POCVPN_API_XRAY_ACTIVATION_LOCK_PATH"]),
        os.path.dirname(api_env["POCVPN_API_XRAY_ACTIVATION_LAST_HASH_PATH"]),
        os.path.dirname(api_env["POCVPN_API_XRAY_STAGING_CONFIG_PATH"]),
        xray_env["XRAY_LIVE_CONFIG_DIR"],
    }


def _read_only_dirs(api_env):
    keys = (
        "POCVPN_API_ACTIVATION_STORE_PATH", "POCVPN_API_ACTIVATION_LOCK_PATH",
        "POCVPN_API_TOKEN_STORE_PATH", "POCVPN_API_TOKEN_LOCK_PATH",
    )
    return {os.path.dirname(api_env[k]) for k in keys if api_env.get(k)}


class FrankfurtXrayReconcilePathsTest(unittest.TestCase):
    def setUp(self):
        self.env = _read_env(_FRANKFURT_ENV)
        self.rw = _read_write_paths(_XRAY_UNIT, _FRANKFURT_DROPIN)

    def test_base_unit_alone_does_not_cover_frankfurt(self):
        # The blocker the precheck found: the shared unit would hit EROFS on
        # the O_RDWR activation lock under /var/lib/pocvpn-xray.
        base = _read_write_paths(_XRAY_UNIT)
        self.assertFalse(_covered(self.env["POCVPN_API_XRAY_ACTIVATION_LOCK_PATH"], base))

    def test_dropin_covers_every_write_path(self):
        for directory in _xray_write_dirs(self.env, _read_env(_XRAY_ENV)):
            self.assertTrue(_covered(directory, self.rw), directory)

    def test_dropin_is_minimal(self):
        self.assertEqual(sorted(self.rw), ["/etc/nova-xray", "/var/lib/pocvpn-xray"])
        self.assertFalse(_BROAD & set(map(os.path.normpath, self.rw)))
        for directory in _read_only_dirs(self.env):
            self.assertFalse(_covered(directory, self.rw), f"{directory} must stay read-only")

    def test_root_side_staging_path_matches_api_side(self):
        # xray-activate.sh (root) reads XRAY_STAGING_CONFIG; the API writes
        # XRAY_STAGING_CONFIG_PATH - they must name the same file.
        self.assertEqual(self.env["POCVPN_API_XRAY_STAGING_CONFIG_PATH"], _read_env(_XRAY_ENV)["XRAY_STAGING_CONFIG"])


class DefaultLayoutXrayReconcilePathsTest(unittest.TestCase):
    """Stockholm/api.env.example layout keeps working with the base unit."""

    def test_base_unit_covers_example_layout(self):
        env = _read_env(_API_ENV_EXAMPLE)
        rw = _read_write_paths(_XRAY_UNIT)
        for directory in _xray_write_dirs(env, _read_env(_XRAY_ENV)) - {_read_env(_XRAY_ENV)["XRAY_LIVE_CONFIG_DIR"]}:
            self.assertTrue(_covered(directory, rw), directory)
        self.assertTrue(_covered(_read_env(_XRAY_ENV)["XRAY_LIVE_CONFIG_DIR"], rw))


class AwgReconcilePathsTest(unittest.TestCase):
    def test_awg_unit_covers_config_dir_only(self):
        rw = _read_write_paths(_AWG_UNIT)
        self.assertEqual(rw, [_read_env(_POC_ENV)["CONFIG_DIR"]])

    def test_awg_unit_needs_no_frankfurt_store_paths(self):
        # Stores are read-only for the planner; /var stays readable under
        # ProtectSystem=strict, so Frankfurt needs no AWG drop-in.
        rw = _read_write_paths(_AWG_UNIT)
        for directory in _read_only_dirs(_read_env(_FRANKFURT_ENV)):
            self.assertFalse(_covered(directory, rw))


if __name__ == "__main__":
    unittest.main()
