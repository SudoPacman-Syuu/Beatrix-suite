"""
Access token for Beatrix's local web UIs (the Suite, the standalone auth GUI, the GHOST
dashboard).

These servers bind 0.0.0.0 (Codespaces port-forwarding needs it) and drive powerful tools,
so every API request must carry a per-install token: it stops other websites (CSRF, DNS
rebinding) and anyone else who can reach the port. The token is created once, kept in
``~/.beatrix/suite.token`` (0600) so bookmarks keep working across restarts, and rotated with
``--new-token``.

It travels as an ``X-Beatrix-Token`` header, not a cookie: cookies aren't scoped by port (every
127.0.0.1 port would share it) and aren't sent from the VS Code webview, which embeds the page
cross-site. The browser learns it from the launch link (``…/#token=…`` — a fragment, so it is
never sent to the server or logged) and keeps it in localStorage for that origin. Requests that
can't carry a header (WebSocket, MJPEG <img>) put it in a ``token`` query parameter instead.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

HEADER = "X-Beatrix-Token"
TOKEN_FILE = Path.home() / ".beatrix" / "suite.token"


def load_or_create_token(path: Optional[Path] = None, rotate: bool = False) -> str:
    """The persistent token, created (or replaced, with ``rotate``) on demand."""
    p = Path(path) if path else TOKEN_FILE
    if not rotate:
        try:
            existing = p.read_text().strip()
            if len(existing) >= 32:
                return existing
        except OSError:
            pass
    token = secrets.token_urlsafe(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token)
    os.replace(tmp, p)
    _give_to_sudo_user(p)
    return token


def _give_to_sudo_user(p: Path) -> None:
    # Launched through the sudo-aware wrapper, the process runs as root with HOME pointing at
    # the real user's home; keep the file theirs so a later non-sudo launch can read it.
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if hasattr(os, "geteuid") and os.geteuid() == 0 and uid and gid:
        try:
            os.chown(p, int(uid), int(gid))
        except OSError:
            pass


def presented_token(handler: Any) -> str:
    """The token a request carries: the header, else a ``token`` query parameter."""
    tok = handler.headers.get(HEADER) or ""
    if not tok:
        tok = (parse_qs(urlparse(handler.path).query).get("token") or [""])[0]
    return tok


def token_ok(expected: Optional[str], handler: Any) -> bool:
    if not expected:
        return False
    return hmac.compare_digest(presented_token(handler).encode(), expected.encode())


def launch_url(base_url: str, token: Optional[str]) -> str:
    """``base_url`` with the token in the fragment — never sent to the server or logged."""
    return base_url + ("#token=" + token if token else "")


# Injected at the top of every served HTML page, before any other script runs.
SHIM_JS = r"""(function () {
  var K = "beatrix.token", t = "";
  try {
    var m = /[#&]token=([A-Za-z0-9_\-]+)/.exec(location.hash);
    if (m) {
      localStorage.setItem(K, m[1]);
      history.replaceState(null, "", location.pathname + location.search);
    }
    t = localStorage.getItem(K) || "";
  } catch (e) {}
  function tok() { try { return localStorage.getItem(K) || t; } catch (e) { return t; } }
  function sameOrigin(input) {
    try { return new URL(typeof input === "string" || input instanceof URL ? String(input) : input.url, location.href).origin === location.origin; }
    catch (e) { return false; }
  }
  window.__bxToken = tok;
  window.__bxUrl = function (u) { return u + (u.indexOf("?") >= 0 ? "&" : "?") + "token=" + encodeURIComponent(tok()); };
  var shown = false;
  function askForToken() {
    if (shown || !document.body) return;
    shown = true;
    var d = document.createElement("div");
    d.setAttribute("style", "position:fixed;inset:0;z-index:2147483647;background:rgba(5,10,8,.93);display:flex;" +
      "align-items:center;justify-content:center;font:14px system-ui,sans-serif;color:#dbe5da");
    d.innerHTML = '<form style="background:#10180f;border:1px solid #39dd89;border-radius:10px;padding:22px 24px;max-width:460px">' +
      '<h3 style="margin:0 0 8px;color:#39dd89">Beatrix needs its access token</h3>' +
      '<p style="margin:0 0 12px;line-height:1.5">Open the link Beatrix printed in your terminal, or paste the token ' +
      'here (it is also saved in ~/.beatrix/suite.token).</p>' +
      '<input name="t" autocomplete="off" spellcheck="false" placeholder="token" style="width:100%;box-sizing:border-box;' +
      'padding:8px;background:#080c0a;color:#dbe5da;border:1px solid #243329;border-radius:6px">' +
      '<button style="margin-top:12px;padding:7px 16px;background:#39dd89;color:#071008;border:0;border-radius:6px;' +
      'font-weight:600;cursor:pointer">Unlock</button></form>';
    d.querySelector("form").onsubmit = function (e) {
      e.preventDefault();
      var v = d.querySelector("input").value.trim();
      if (v) { try { localStorage.setItem(K, v); } catch (x) {} location.reload(); }
    };
    document.body.appendChild(d);
  }
  var origFetch = window.fetch;
  window.fetch = function (input, init) {
    var same = sameOrigin(input);
    if (same) {
      init = Object.assign({}, init || {});
      var h = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
      h.set("X-Beatrix-Token", tok());
      init.headers = h;
    }
    return origFetch.call(this, input, init).then(function (r) {
      if (same && r.status === 401) askForToken();
      return r;
    });
  };
})();"""


def inject_shim(html: str) -> str:
    """``html`` with the token shim as the first script in <head>."""
    tag = "<script>" + SHIM_JS + "</script>"
    i = html.find("<head>")
    if i < 0:
        return tag + html
    i += len("<head>")
    return html[:i] + tag + html[i:]
