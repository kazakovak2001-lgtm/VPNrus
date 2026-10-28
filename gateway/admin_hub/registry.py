"""Node registry for the local admin hub.

A registry file lists the gateways the hub may query. It contains NO secrets:
only where each node's admin API is reachable (always a loopback address -
an SSH tunnel on the operator's machine) and the path of a file holding that
node's read-only *viewer* secret. Anything malformed fails closed with
RegistryError; nothing is skipped or guessed.

    {"nodes": [{"id": "frankfurt", "name": "Frankfurt", "role": "primary",
                "url": "http://127.0.0.1:18787",
                "viewer_secret_file": "/home/me/.pocvpn-hub/frankfurt-viewer"}]}
"""
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from urllib.parse import urlsplit

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from api import admin_auth  # noqa: E402

MAX_NODES = 32
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_NAME_RE = re.compile(r"^[ -~]{1,64}$")
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_NODE_KEYS = {"id", "name", "role", "url", "viewer_secret_file"}


class RegistryError(Exception):
    """The registry (or one of its entries) is invalid."""


@dataclass(frozen=True)
class Node:
    id: str
    name: str
    role: str
    host: str
    port: int
    viewer_secret_file: str


def _parse_url(node_id, url):
    if not isinstance(url, str):
        raise RegistryError(f"node {node_id}: url must be a string")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise RegistryError(f"node {node_id}: url is malformed")
    if parts.scheme != "http":
        raise RegistryError(f"node {node_id}: url must use http:// (it is an SSH tunnel to loopback)")
    if parts.hostname not in _LOOPBACK_HOSTS:
        raise RegistryError(f"node {node_id}: url host must be loopback (127.0.0.1, localhost or ::1)")
    if parts.username or parts.password:
        raise RegistryError(f"node {node_id}: url must not contain credentials")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise RegistryError(f"node {node_id}: url must be only scheme://host:port")
    if port is None or not 1 <= port <= 65535:
        raise RegistryError(f"node {node_id}: url needs an explicit port")
    return parts.hostname, port


def _check_secret_file(node_id, path):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RegistryError(f"node {node_id}: viewer_secret_file must be an absolute path")
    try:
        admin_auth.read_admin_secret(path)
    except (admin_auth.ConfigError, ValueError) as exc:
        raise RegistryError(f"node {node_id}: viewer_secret_file: {exc}")
    if os.name == "posix" and os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RegistryError(f"node {node_id}: viewer_secret_file must not be group/other accessible (chmod 600)")


def parse_registry(raw):
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise RegistryError("registry is not valid JSON")
    if not isinstance(data, dict) or set(data) != {"nodes"} or not isinstance(data["nodes"], list):
        raise RegistryError('registry must be {"nodes": [...]}')
    if not 1 <= len(data["nodes"]) <= MAX_NODES:
        raise RegistryError(f"registry must list 1-{MAX_NODES} nodes")
    nodes, seen = [], set()
    for entry in data["nodes"]:
        if not isinstance(entry, dict) or set(entry) != _NODE_KEYS:
            raise RegistryError(f"each node needs exactly the keys {sorted(_NODE_KEYS)}")
        node_id = entry["id"]
        if not isinstance(node_id, str) or not _ID_RE.match(node_id):
            raise RegistryError("node id must match [a-z0-9][a-z0-9-]{0,31}")
        if node_id in seen:
            raise RegistryError(f"duplicate node id {node_id}")
        seen.add(node_id)
        if not isinstance(entry["name"], str) or not _NAME_RE.match(entry["name"]):
            raise RegistryError(f"node {node_id}: name must be 1-64 printable ASCII characters")
        if not isinstance(entry["role"], str) or not _ROLE_RE.match(entry["role"]):
            raise RegistryError(f"node {node_id}: role must match [a-z0-9][a-z0-9_-]{{0,31}}")
        host, port = _parse_url(node_id, entry["url"])
        _check_secret_file(node_id, entry["viewer_secret_file"])
        nodes.append(Node(node_id, entry["name"], entry["role"], host, port, entry["viewer_secret_file"]))
    return nodes


def load_registry(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read(1024 * 256)
    except OSError as exc:
        raise RegistryError(f"registry cannot be read: {type(exc).__name__}")
    return parse_registry(raw)
