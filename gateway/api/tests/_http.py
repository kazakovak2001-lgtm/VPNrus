"""Minimal raw-socket HTTP/1.1 client for tests.

Deliberately NOT http.client: we need full control over malformed/missing
headers (e.g. omitting Content-Length entirely, or sending a wrong
Content-Type) to exercise the handler's own validation, which a
higher-level client would "fix" for us before the request ever left the
process.
"""
import json
import socket


def parse_http_response(raw):
    header_blob, _, body = raw.partition(b"\r\n\r\n")
    lines = header_blob.split(b"\r\n")
    status_line = lines[0].decode("latin-1")
    status_code = int(status_line.split(" ")[1])
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            key, _, value = line.partition(b":")
            headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    return status_code, headers, body


def send_raw_lines(port, method, path, header_lines, body=b"", timeout=10):
    """Lowest-level primitive: `header_lines` is a list of preformatted
    "Key: Value" strings, sent verbatim and in order - the only way to
    put two headers with the same name on the wire (a dict can't hold
    duplicate keys, and http.client/urllib may silently normalize
    duplicates before they ever reach the socket).

    Returns (status, headers, body, closed_by_peer) - closed_by_peer is
    True only if the read loop ended because the server closed its end
    (recv() returned b""), as opposed to this client's own timeout firing.
    That distinction is what actually proves "Connection: close" is real
    transport behavior, not just a header the server claims to send.
    """
    lines = [f"{method} {path} HTTP/1.1"] + list(header_lines) + [""]
    head = ("\r\n".join(lines) + "\r\n").encode("latin-1")
    closed_by_peer = False
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(head + body)
        sock.settimeout(timeout)
        chunks = []
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                closed_by_peer = True
                break
            chunks.append(chunk)
    status, headers, resp_body = parse_http_response(b"".join(chunks))
    return status, headers, resp_body, closed_by_peer


def raw_request(port, method, path, headers=None, body=b""):
    hdrs = dict(headers or {})
    if not any(k.lower() == "host" for k in hdrs):
        hdrs["Host"] = f"127.0.0.1:{port}"
    header_lines = [f"{key}: {value}" for key, value in hdrs.items()]
    status, headers_out, resp_body, _closed_by_peer = send_raw_lines(port, method, path, header_lines, body)
    return status, headers_out, resp_body


def post_peers(
    port,
    token=None,
    body_obj=None,
    raw_body=None,
    content_type="application/json",
    set_content_length=True,
    extra_headers=None,
):
    if raw_body is not None:
        body = raw_body
    else:
        body = json.dumps({} if body_obj is None else body_obj).encode("utf-8")

    headers = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    if set_content_length:
        headers["Content-Length"] = str(len(body))
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    return raw_request(port, "POST", "/v1/peers", headers, body)


def post_activate(
    port,
    credential=None,
    body_obj=None,
    raw_body=None,
    content_type="application/json",
    set_content_length=True,
    extra_headers=None,
):
    """Same shape as post_peers, against /v1/activate (B8C1)."""
    if raw_body is not None:
        body = raw_body
    else:
        body = json.dumps({} if body_obj is None else body_obj).encode("utf-8")

    headers = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    if set_content_length:
        headers["Content-Length"] = str(len(body))
    if credential is not None:
        headers["Authorization"] = f"Bearer {credential}"
    if extra_headers:
        headers.update(extra_headers)
    return raw_request(port, "POST", "/v1/activate", headers, body)


def post_xray_profile(
    port,
    credential=None,
    body_obj=None,
    raw_body=None,
    content_type="application/json",
    set_content_length=True,
    extra_headers=None,
):
    """Same shape as post_activate, against /v1/xray-profile (B8K2)."""
    if raw_body is not None:
        body = raw_body
    else:
        body = json.dumps({} if body_obj is None else body_obj).encode("utf-8")

    headers = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    if set_content_length:
        headers["Content-Length"] = str(len(body))
    if credential is not None:
        headers["Authorization"] = f"Bearer {credential}"
    if extra_headers:
        headers.update(extra_headers)
    return raw_request(port, "POST", "/v1/xray-profile", headers, body)
