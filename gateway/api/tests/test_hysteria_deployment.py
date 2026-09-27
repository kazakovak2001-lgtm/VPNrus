"""B46-4P.3 - Hysteria2 deployment artifacts: the server-config renderer
(hysteria_server_config.py) and static assertions over the tracked
Stockholm config, systemd units, cert deploy hook, pinned VERSION and
env template. Never starts Hysteria2 or systemd, never touches a host."""
import dataclasses
import ipaddress
import os
import re
import subprocess
import shutil
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import config as config_module
from api import hysteria_auth_server
from api import hysteria_server_config as hsc
from _fixtures import make_app_config, write_fake_provision_script

try:
    import yaml
except ImportError:  # optional: PyYAML is not a gateway dependency
    yaml = None

_STOCKHOLM_CONFIG = os.path.join(_GATEWAY_DIR, "hysteria", "nova-hysteria-stockholm.yaml")
_VERSION = os.path.join(_GATEWAY_DIR, "hysteria", "VERSION")
_FETCH = os.path.join(_GATEWAY_DIR, "hysteria", "fetch-hysteria-server.sh")
_HY_UNIT = os.path.join(_GATEWAY_DIR, "systemd", "nova-hysteria.service")
_AUTH_UNIT = os.path.join(_GATEWAY_DIR, "systemd", "pocvpn-hysteria-auth.service")
_HOOK = os.path.join(_GATEWAY_DIR, "edge", "nova-hysteria-cert-deploy-hook.sh")
_API_ENV_EXAMPLE = os.path.join(_GATEWAY_DIR, "config", "api.env.example")
_EDGE_DIR = os.path.join(_GATEWAY_DIR, "edge")

_STOCKHOLM_SNI = "origin-sthlm.aknova.pp.ua"
_SECRET_RE = re.compile(r"(?i)(BEGIN [A-Z ]*PRIVATE KEY|password\s*:|userpass|obfs|salamander|[0-9a-f]{64})")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _unit_directives(path):
    """[(section, key, value)] for every non-comment directive."""
    section, out = None, []
    for raw in _read(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, _, value = line.partition("=")
        out.append((section, key.strip(), value.strip()))
    return out


def _unit_value(path, key):
    values = [v for _s, k, v in _unit_directives(path) if k == key]
    return values[-1] if values else None


def _version_value(key):
    match = re.search(rf"^{key}=(\S+)$", _read(_VERSION), re.MULTILINE)
    return match.group(1) if match else None


class RendererTests(unittest.TestCase):
    def test_tracked_stockholm_config_is_exactly_the_rendered_output(self):
        self.assertEqual(_read(_STOCKHOLM_CONFIG), hsc.render_server_config(443, _STOCKHOLM_SNI, 8446))

    def test_listen_is_udp_443_and_auth_is_loopback_8446(self):
        text = hsc.render_server_config(443, _STOCKHOLM_SNI, 8446)
        self.assertIn('listen: ":443"\n', text)
        self.assertIn('url: "http://127.0.0.1:8446/auth"\n', text)
        self.assertIn("insecure: false\n", text)
        self.assertIn("  type: http\n", text)

    def test_auth_host_constant_matches_the_auth_servers_bind_host(self):
        self.assertEqual(hsc.AUTH_BACKEND_HOST, hysteria_auth_server._BIND_HOST)
        self.assertTrue(ipaddress.ip_address(hsc.AUTH_BACKEND_HOST).is_loopback)

    def test_no_public_or_wildcard_auth_endpoint(self):
        text = hsc.render_server_config(443, _STOCKHOLM_SNI, 8446)
        auth_urls = re.findall(r"url: \"([^\"]+)\"", text)
        self.assertEqual(auth_urls, ["http://127.0.0.1:8446/auth"])
        self.assertNotIn("0.0.0.0:8446", text)
        self.assertNotIn("https://", text)

    def test_tls_uses_runtime_copies_never_letsencrypt_and_strict_sni(self):
        text = hsc.render_server_config(443, _STOCKHOLM_SNI, 8446)
        self.assertIn("  cert: /etc/nova-hysteria/tls/fullchain.pem\n", text)
        self.assertIn("  key: /etc/nova-hysteria/tls/privkey.pem\n", text)
        self.assertIn("  sniGuard: strict\n", text)
        self.assertNotIn("/etc/letsencrypt", text)
        self.assertNotIn("acme:", text)

    def test_no_secret_material_and_no_tcp_masquerade_listeners(self):
        text = hsc.render_server_config(443, _STOCKHOLM_SNI, 8446)
        self.assertIsNone(_SECRET_RE.search(text))
        for key in ("listenHTTP", "listenHTTPS", "password", "obfs", "userpass", "command"):
            self.assertNotIn(key, text)

    def test_acl_rejects_loopback_linklocal_private_then_direct_last(self):
        text = hsc.render_server_config(443, _STOCKHOLM_SNI, 8446)
        rules = re.findall(r"^    - (.+)$", text, re.MULTILINE)
        self.assertEqual(rules[-1], "direct(all)")
        rejected = [ipaddress.ip_network(r[len("reject("):-1]) for r in rules[:-1]]
        self.assertTrue(all(r.startswith("reject(") for r in rules[:-1]))
        for probe in ("127.0.0.1", "169.254.169.254", "172.31.36.199", "172.31.0.2", "10.77.0.1", "192.168.1.1", "::1", "fe80::1", "fd00::1"):
            addr = ipaddress.ip_address(probe)
            self.assertTrue(any(addr in net for net in rejected if net.version == addr.version), probe)
        for public in ("1.1.1.1", "16.170.208.231", "2606:4700::1111"):
            addr = ipaddress.ip_address(public)
            self.assertFalse(any(addr in net for net in rejected if net.version == addr.version), public)

    def test_acl_never_contains_the_ipv4_mapped_catch_all(self):
        # Go normalizes ::ffff:0:0/96 to 0.0.0.0/0 - it would reject ALL IPv4.
        self.assertNotIn("::ffff:0:0/96", hsc.ACL_REJECT_CIDRS)
        self.assertNotIn("::ffff:", hsc.render_server_config(443, _STOCKHOLM_SNI, 8446))

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_parses_as_the_expected_yaml_structure(self):
        data = yaml.safe_load(hsc.render_server_config(443, _STOCKHOLM_SNI, 8446))
        self.assertEqual(set(data), {"listen", "tls", "auth", "masquerade", "acl"})
        self.assertEqual(data["listen"], ":443")
        self.assertEqual(data["auth"], {"type": "http", "http": {"url": "http://127.0.0.1:8446/auth", "insecure": False}})
        self.assertEqual(data["masquerade"], {"type": "404"})
        self.assertEqual(data["tls"]["sniGuard"], "strict")

    def test_fails_closed_on_invalid_ports(self):
        for bad in (0, 65536, -1, "443", None, True, 443.0):
            with self.assertRaises(hsc.HysteriaServerConfigError):
                hsc.render_server_config(bad, _STOCKHOLM_SNI, 8446)
            with self.assertRaises(hsc.HysteriaServerConfigError):
                hsc.render_server_config(443, _STOCKHOLM_SNI, bad)

    def test_fails_closed_on_invalid_sni(self):
        for bad in ("", "16.170.208.231", "localhost", "Origin-Sthlm.aknova.pp.ua", "a b.example", "-x.example",
                    "x..example", "x.example.", None, "a" * 64 + ".example"):
            with self.assertRaises(hsc.HysteriaServerConfigError, msg=repr(bad)):
                hsc.render_server_config(443, bad, 8446)


class RenderFromAppConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = make_app_config(
            self._tmp.name, write_fake_provision_script(self._tmp.name),
            activation_store_path=os.path.join(self._tmp.name, "a.json"),
            activation_lock_path=os.path.join(self._tmp.name, ".a.lock"),
        )
        self.full = dataclasses.replace(
            base,
            hysteria2_store_path=os.path.join(self._tmp.name, "h.json"),
            hysteria2_lock_path=os.path.join(self._tmp.name, ".h.lock"),
            hysteria2_server_port=443, hysteria2_sni=_STOCKHOLM_SNI, hysteria2_auth_backend_port=8446,
        )

    def test_full_config_renders_the_stockholm_file(self):
        self.assertEqual(hsc.render_from_app_config(self.full), _read(_STOCKHOLM_CONFIG))

    def test_missing_auth_backend_port_fails_closed(self):
        with self.assertRaises(hsc.HysteriaServerConfigError):
            hsc.render_from_app_config(dataclasses.replace(self.full, hysteria2_auth_backend_port=0))

    def test_unconfigured_group_fails_closed(self):
        for field in ("hysteria2_store_path", "hysteria2_lock_path", "hysteria2_sni"):
            with self.assertRaises(hsc.HysteriaServerConfigError, msg=field):
                hsc.render_from_app_config(dataclasses.replace(self.full, **{field: ""}))
        with self.assertRaises(hsc.HysteriaServerConfigError):
            hsc.render_from_app_config(dataclasses.replace(self.full, hysteria2_server_port=0))

    def test_partial_env_group_is_rejected_by_load_config_itself(self):
        env = {
            "POCVPN_API_ENDPOINT_HOST": "16.170.208.231", "POCVPN_API_ENDPOINT_PORT": "51820",
            "POCVPN_API_GATEWAY_PUBLIC_KEY": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            "POCVPN_API_GATEWAY_TUNNEL_IP": "10.77.0.1", "POCVPN_API_TOKEN_STORE_PATH": "/x/t.json",
            "POCVPN_API_PROVISION_SCRIPT_PATH": "/bin/false", "POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS": "15",
            "POCVPN_API_API_PORT": "8443", "POCVPN_API_HYSTERIA2_SERVER_PORT": "443",
        }
        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(env)


class PinnedVersionTests(unittest.TestCase):
    def test_version_pins_tag_commit_and_sha256(self):
        self.assertEqual(_version_value("HYSTERIA_TAG"), "app/v2.12.3")
        self.assertEqual(_version_value("HYSTERIA_VERSION"), "v2.12.3")
        self.assertRegex(_version_value("HYSTERIA_COMMIT"), r"^[0-9a-f]{40}$")
        self.assertRegex(_version_value("HYSTERIA_RELEASE_ASSET_SHA256"), r"^[0-9a-f]{64}$")
        self.assertIn("app%2Fv2.12.3/hysteria-linux-amd64", _version_value("HYSTERIA_RELEASE_ASSET_URL"))

    def test_fetch_script_verifies_sha256_before_executing_and_never_overwrites(self):
        script = _read(_FETCH)
        self.assertIn("set -euo pipefail", script)
        self.assertLess(script.index("sha256sum"), script.index('"$WORK/hysteria" version'))
        self.assertIn('if [ -d "$VERSIONED_DIR" ]', script)
        self.assertIn("CommitHash:", script)


class HysteriaUnitTests(unittest.TestCase):
    def test_runs_as_dedicated_non_root_user(self):
        self.assertEqual(_unit_value(_HY_UNIT, "User"), "nova-hysteria")
        self.assertEqual(_unit_value(_HY_UNIT, "Group"), "nova-hysteria")

    def test_only_capability_is_net_bind_service(self):
        self.assertEqual(_unit_value(_HY_UNIT, "CapabilityBoundingSet"), "CAP_NET_BIND_SERVICE")
        self.assertEqual(_unit_value(_HY_UNIT, "AmbientCapabilities"), "CAP_NET_BIND_SERVICE")
        self.assertEqual(_unit_value(_HY_UNIT, "NoNewPrivileges"), "true")

    def test_hardening_and_restart_policy(self):
        for key, value in (
            ("ProtectSystem", "strict"), ("ProtectHome", "yes"), ("PrivateTmp", "yes"), ("PrivateDevices", "yes"),
            ("RestrictSUIDSGID", "yes"), ("MemoryDenyWriteExecute", "yes"), ("SystemCallFilter", "@system-service"),
            ("Restart", "on-failure"), ("WorkingDirectory", "/var/lib/nova-hysteria"),
            ("StateDirectory", "nova-hysteria"),
        ):
            self.assertEqual(_unit_value(_HY_UNIT, key), value, key)
        self.assertIsNone(_unit_value(_HY_UNIT, "ReadWritePaths"))

    def test_execstart_uses_pinned_binary_and_explicit_config(self):
        exec_start = _unit_value(_HY_UNIT, "ExecStart")
        self.assertEqual(
            exec_start,
            f"/opt/pocvpn/hysteria/{_version_value('HYSTERIA_VERSION')}/hysteria server "
            "--config /etc/nova-hysteria/config.yaml --disable-update-check",
        )

    def test_no_secrets_or_env_files_in_unit(self):
        self.assertIsNone(_unit_value(_HY_UNIT, "EnvironmentFile"))
        envs = [v for _s, k, v in _unit_directives(_HY_UNIT) if k == "Environment"]
        self.assertEqual(envs, ["HYSTERIA_DISABLE_UPDATE_CHECK=true"])
        self.assertIsNone(_SECRET_RE.search(_read(_HY_UNIT)))

    def test_wants_not_requires_the_auth_backend(self):
        self.assertIn("pocvpn-hysteria-auth.service", _unit_value(_HY_UNIT, "Wants"))
        self.assertIsNone(_unit_value(_HY_UNIT, "Requires"))


class AuthBackendUnitTests(unittest.TestCase):
    def test_runs_existing_b46_4p2_module_as_pocvpn_api(self):
        self.assertEqual(_unit_value(_AUTH_UNIT, "ExecStart"), "/usr/bin/python3 -m api.hysteria_auth_server")
        self.assertEqual(_unit_value(_AUTH_UNIT, "User"), "pocvpn-api")
        self.assertEqual(_unit_value(_AUTH_UNIT, "WorkingDirectory"), "/opt/pocvpn/gateway")
        self.assertEqual(_unit_value(_AUTH_UNIT, "EnvironmentFile"), "/etc/pocvpn/api.env")

    def test_no_privileges_at_all(self):
        self.assertEqual(_unit_value(_AUTH_UNIT, "NoNewPrivileges"), "yes")
        self.assertEqual(_unit_value(_AUTH_UNIT, "CapabilityBoundingSet"), "")
        self.assertEqual(_unit_value(_AUTH_UNIT, "AmbientCapabilities"), "")

    def test_loopback_only_at_cgroup_level(self):
        self.assertEqual(_unit_value(_AUTH_UNIT, "IPAddressDeny"), "any")
        self.assertEqual(_unit_value(_AUTH_UNIT, "IPAddressAllow"), "localhost")
        self.assertNotIn("AF_INET6", _unit_value(_AUTH_UNIT, "RestrictAddressFamilies"))

    def test_writable_paths_limited_to_the_stores(self):
        self.assertEqual(_unit_value(_AUTH_UNIT, "ProtectSystem"), "strict")
        self.assertEqual(_unit_value(_AUTH_UNIT, "ReadWritePaths"), "/var/lib/pocvpn-provision")


class CertDeployHookTests(unittest.TestCase):
    def setUp(self):
        self.hook = _read(_HOOK)

    def test_acts_only_on_the_advertised_sni_lineage(self):
        self.assertIn("POCVPN_API_HYSTERIA2_SNI", self.hook)
        self.assertIn('if [ "$RENEWED_LINEAGE" != "/etc/letsencrypt/live/$sni" ]; then\n    exit 0', self.hook)

    def test_validates_hostname_expiry_and_key_match_before_install(self):
        first_install = self.hook.index("install -o")
        for check in ("-checkhost", "-checkend 0", 'if [ "$cert_pub" != "$key_pub" ]'):
            self.assertLess(self.hook.index(check), first_install, check)

    def test_runtime_copy_is_owned_by_hysteria_user_and_never_world_readable(self):
        self.assertIn('install -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0400 "$src_key"', self.hook)
        self.assertIn('install -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0440 "$src_cert"', self.hook)
        self.assertIn('install -d -o root -g "$RUNTIME_GROUP" -m 0750 "$TLS_DIR"', self.hook)
        self.assertIn("umask 077", self.hook)
        for mode in re.findall(r"-m (0\d{3})", self.hook):
            self.assertEqual(int(mode, 8) & 0o007, 0, mode)

    def test_atomic_swap_key_then_cert_and_no_restart_or_nginx_reload(self):
        self.assertLess(self.hook.index('mv -f "$TLS_DIR/.privkey.pem.new"'), self.hook.index('mv -f "$TLS_DIR/.fullchain.pem.new"'))
        code = "\n".join(l for l in self.hook.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotIn("systemctl", code)
        self.assertNotIn("nginx", code)
        self.assertNotIn("chmod", code)

    @unittest.skipUnless(shutil.which("bash") and os.name == "posix", "needs POSIX bash")
    def test_is_a_noop_for_other_lineages_and_fails_without_lineage(self):
        env = dict(os.environ, RENEWED_LINEAGE="/etc/letsencrypt/live/16.170.208.231")
        result = subprocess.run(["bash", _HOOK], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        env.pop("RENEWED_LINEAGE")
        self.assertNotEqual(subprocess.run(["bash", _HOOK], env=env, capture_output=True).returncode, 0)


class DeploymentBoundaryTests(unittest.TestCase):
    def test_no_nginx_template_routes_hysteria_or_the_auth_backend(self):
        for name in os.listdir(_EDGE_DIR):
            if name.endswith(".conf") or name.endswith(".example"):
                text = _read(os.path.join(_EDGE_DIR, name))
                self.assertNotIn("8446", text, name)
                self.assertNotIn("hysteria", text.lower(), name)

    def test_env_template_documents_stockholm_values_but_ships_blank(self):
        env = _read(_API_ENV_EXAMPLE)
        self.assertRegex(env, r"(?m)^POCVPN_API_HYSTERIA2_AUTH_BACKEND_PORT=$")
        self.assertRegex(env, r"(?m)^POCVPN_API_HYSTERIA2_SERVER_PORT=$")
        self.assertIn("Do NOT expose TCP/UDP 8446 publicly", env)

    def test_no_private_key_material_in_any_new_artifact(self):
        for path in (_STOCKHOLM_CONFIG, _VERSION, _FETCH, _HY_UNIT, _AUTH_UNIT, _HOOK):
            self.assertNotIn("PRIVATE KEY", _read(path), path)


if __name__ == "__main__":
    unittest.main()
