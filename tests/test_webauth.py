"""
Access token for Beatrix's web UIs (beatrix/cli/_webauth.py): every API route of the Suite,
the standalone auth GUI and the GHOST dashboard needs it; the HTML shells and OAST callbacks
stay reachable without it. Plus the input hardening that came with it: popout project ids,
project-id paths, request-body caps, WebSocket frame cap, .env line injection.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import stat
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from beatrix.cli import _webauth
from beatrix.cli.suite import SuiteServer


@pytest.fixture
def server(tmp_path):
    srv = SuiteServer(host="127.0.0.1", port=0, state_dir=tmp_path / "suite",
                      sessions_registry=tmp_path / "sessions.json")
    srv.start(open_browser=False)
    try:
        yield srv
    finally:
        srv.stop()


def _req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def _auth(srv):
    return {"X-Beatrix-Token": srv.token}


# ── The gate ──────────────────────────────────────────────────────────────────

def test_api_routes_refuse_requests_without_the_token(server):
    for method, path, body in [("GET", "/projects", None), ("GET", "/fs/list", None),
                               ("GET", "/session", None), ("POST", "/projects/new", b"{}"),
                               ("POST", "/scapy/console", b'{"code": "1"}')]:
        status, raw = _req(server.port, method, path, body)
        assert status == 401, (method, path)
        assert json.loads(raw)["auth_required"] is True
    assert _req(server.port, "GET", "/projects", headers={"X-Beatrix-Token": "x" * 43})[0] == 401
    assert len(server.projects.state()["projects"]) == 1           # the refused POST did nothing


def test_token_in_header_or_query_is_accepted(server):
    assert _req(server.port, "GET", "/projects", headers=_auth(server))[0] == 200
    assert _req(server.port, "GET", "/projects?token=" + server.token)[0] == 200
    status, raw = _req(server.port, "POST", "/projects/new", b"{}", _auth(server))
    assert status == 200 and json.loads(raw)["ok"] is True


def test_html_shells_assets_and_oast_callbacks_stay_open(server):
    for path in ("/", "/index.html", "/auth", "/browser/popout?project=1", "/msf/recon/popout?project=1"):
        status, raw = _req(server.port, "GET", path)
        assert status == 200, path
        page = raw.decode()
        assert "window.__bxUrl" in page and page.index("X-Beatrix-Token") < page.index("</head>"), path
    assert _req(server.port, "GET", "/assets/beatrix-banner.png")[0] in (200, 404)
    assert _req(server.port, "GET", "/cb/abc123")[0] == 200
    assert _req(server.port, "POST", "/cb/abc123", b"leak=1")[0] == 200
    hits = json.loads(_req(server.port, "GET", "/oast/state", headers=_auth(server))[1])["callbacks"]
    assert {h["method"] for h in hits if h["uid"] == "abc123"} == {"GET", "POST"}


def test_launch_url_carries_the_token_in_the_fragment(server):
    assert server.url.endswith("/") and "#" not in server.url
    assert server.launch_url == server.url + "#token=" + server.token


def _ws_handshake(port, path):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, key)).encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            break
        head += chunk
    return s, head.split(b"\r\n", 1)[0]


def test_websocket_needs_the_token_in_its_query(server):
    s, status = _ws_handshake(server.port, "/browser/ws?project=1")
    s.close()
    assert b" 401 " in status
    s, status = _ws_handshake(server.port, "/browser/ws?project=1&token=" + server.token)
    s.close()
    assert b" 101 " in status


def test_oversized_websocket_frame_drops_the_connection(server):
    class _Viewer:                                   # a live capture browser with no frames to send
        running = True

        def wait_frame(self, last, timeout=5):
            time.sleep(0.05)

        def input_event(self, ev):
            pass

    server.browser_controllers["1"] = _Viewer()
    s, status = _ws_handshake(server.port, "/browser/ws?project=1&token=" + server.token)
    assert b" 101 " in status
    s.sendall(bytes([0x81, 0x80 | 127]) + (2 << 20).to_bytes(8, "big"))   # claims a 2 MiB text frame
    s.settimeout(5)
    try:
        assert s.recv(10) == b""                    # server hung up instead of reading 2 MiB
    finally:
        s.close()
        server.browser_controllers.pop("1", None)


# ── Input hardening ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", ["/browser/popout", "/msf/recon/popout"])
def test_popout_project_id_is_never_markup(server, path):
    evil = "%3C%2Fscript%3E%3Cb%20id%3Dbx%3E"            # </script><b id=bx>
    page = _req(server.port, "GET", path + "?project=" + evil)[1].decode()
    assert "</script><b id=bx>" not in page and "const PID=null" in page
    assert 'const PID="1"' in _req(server.port, "GET", path + "?project=1")[1].decode()


def test_project_id_cannot_point_outside_the_session(server, tmp_path):
    root = server.projects.root.resolve()
    for bad in ("../../escape", "/etc", "-1", None, "1/../../x"):
        d = server.projects.workspace_dir(bad).resolve()
        assert str(d).startswith(str(root)) and not d.exists(), bad
    _req(server.port, "GET", "/issues?project=../../escape", headers=_auth(server))
    assert not (tmp_path / "escape").exists() and not (root.parent / "escape").exists()
    assert server.projects.workspace_dir("1") == server.projects.workspace_dir(1)


def test_oversized_body_is_refused_before_it_is_read(server):
    c = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    c.putrequest("POST", "/projects/select")
    c.putheader("Content-Length", str(17 << 20))      # nothing follows: the server mustn't wait for it
    c.putheader("X-Beatrix-Token", server.token)
    c.endheaders()
    r = c.getresponse()
    assert r.status == 413 and json.loads(r.read())["ok"] is False
    c.close()


def test_large_oast_callback_is_recorded_not_refused(server):
    assert _req(server.port, "POST", "/cb/bigone", b"A" * (100 << 10))[0] == 200
    hits = json.loads(_req(server.port, "GET", "/oast/state", headers=_auth(server))[1])["callbacks"]
    assert any(h["uid"] == "bigone" for h in hits)


# ── Token file ────────────────────────────────────────────────────────────────

def test_token_persists_across_restarts_and_rotates_on_request(tmp_path):
    f = tmp_path / "t" / "suite.token"
    a = _webauth.load_or_create_token(f)
    assert len(a) >= 40 and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert _webauth.load_or_create_token(f) == a
    b = _webauth.load_or_create_token(f, rotate=True)
    assert b != a and f.read_text() == b


def test_suite_uses_the_saved_token_and_new_token_rotates_it(tmp_path):
    def run(**kw):
        s = SuiteServer(host="127.0.0.1", port=0, state_dir=tmp_path / "s",
                        sessions_registry=tmp_path / "r.json", **kw)
        s.start(open_browser=False)
        s.stop()
        return s.token
    first = run()
    assert run() == first == _webauth.TOKEN_FILE.read_text()
    assert run(new_token=True) != first


# ── Standalone auth GUI and GHOST dashboard ───────────────────────────────────

def _serve(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_standalone_auth_gui_requires_the_token(monkeypatch, tmp_path):
    from beatrix.cli import auth_gui
    monkeypatch.setattr(auth_gui, "_ENV_FILE", tmp_path / ".env")
    tok = "k" * 43
    httpd = _serve(type("H", (auth_gui._Handler,), {"token": tok}))
    port = httpd.server_address[1]
    try:
        page = _req(port, "GET", "/")[1].decode()
        assert "window.__bxUrl" in page
        assert _req(port, "GET", "/api/keys")[0] == 401
        assert _req(port, "POST", "/api/keys", b'{"keys": {}}')[0] == 401
        assert _req(port, "GET", "/api/keys", headers={"X-Beatrix-Token": tok})[0] == 200
        for length, expected in (("-5", 200), ("abc", 400)):   # -5 used to read(-5): wait for EOF
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.putrequest("POST", "/api/keys")
            c.putheader("Content-Length", length)
            c.putheader("X-Beatrix-Token", tok)
            c.endheaders()
            assert c.getresponse().status == expected, length
            c.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
    # The base handler (no token configured) refuses every API call.
    httpd = _serve(auth_gui._Handler)
    try:
        assert _req(httpd.server_address[1], "GET", "/api/keys")[0] == 401
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_saved_api_key_cannot_inject_extra_env_lines(monkeypatch, tmp_path):
    from beatrix.cli import auth_gui
    env = tmp_path / ".env"
    monkeypatch.setattr(auth_gui, "_ENV_FILE", env)
    monkeypatch.setenv("OPENAI_API_KEY", "before")       # restored after the test
    res = auth_gui._save_keys({"keys": {"OPENAI_API_KEY": "sk-abc\nBEATRIX_EVIL=1\r\n"}})
    assert res["ok"] is True
    lines = env.read_text().splitlines()
    assert "OPENAI_API_KEY=sk-abcBEATRIX_EVIL=1" in lines
    assert not any(line.startswith("BEATRIX_EVIL") for line in lines)
    assert os.environ["OPENAI_API_KEY"] == "sk-abcBEATRIX_EVIL=1"


def test_ghost_dashboard_events_need_the_token():
    from beatrix.cli.ghost_web import GhostWebServer
    srv = GhostWebServer(meta={"target": "t"}, host="127.0.0.1", port=0, token="g" * 43)
    srv.start(open_browser=False)
    try:
        assert "window.__bxUrl" in _req(srv.port, "GET", "/")[1].decode()
        assert _req(srv.port, "GET", "/events?since=0")[0] == 401
        assert _req(srv.port, "GET", "/state")[0] == 401
        assert _req(srv.port, "GET", "/events?since=0", headers={"X-Beatrix-Token": "g" * 43})[0] == 200
        assert srv.launch_url == srv.url + "#token=" + "g" * 43
    finally:
        srv.stop()
