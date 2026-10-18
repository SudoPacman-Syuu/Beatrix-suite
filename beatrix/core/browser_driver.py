"""
BEATRIX — native capture browser driver.

Drives a real, headful Chromium through Playwright and reads its HTTP traffic
*in-process* via the DevTools protocol (`context.on("request"/"response")`).
Because the browser makes genuine native TLS connections, the traffic the server
sees has Chromium's own JA3/JA4 + HTTP/2 fingerprint — there is no proxy on the
wire and no CA cert to install, so there is nothing for anti-bot/WAF systems to
flag as "intercepted". This is the collector behind the Suite's HTTP module
(history + site map); it is for authorized, scope-gated testing.

Burp-style interception is still available: `context.route` pauses in-scope
requests *inside the browser* so the operator can edit/forward/drop them, and the
browser still originates the connection — the native fingerprint is preserved.

Threading model: Playwright's async API runs on its own event loop in a dedicated
thread (so background `on("response")` capture keeps flowing while the operator
browses). The synchronous Suite HTTP handlers drive it via
`asyncio.run_coroutine_threadsafe` / `loop.call_soon_threadsafe`, mirroring how
`_ScapyWorker` fronts the packet worker.
"""

from __future__ import annotations

import asyncio
import base64
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only where playwright is absent
    PLAYWRIGHT_AVAILABLE = False

# A current desktop-Chrome UA so the header matches the real Chromium fingerprint.
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

_MAX_BODY = 512 * 1024          # cap captured bodies so history stays bounded
_HOLD_TIMEOUT = 300             # seconds a held (intercepted) request waits for a decision


def _host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split("@")[-1].split(":")[0]
    except Exception:  # noqa: BLE001
        return ""


class BrowserController:
    """One headful Chromium per project, with native capture + optional intercept.

    ``sink(event)`` is called (on the driver thread) for every ``transaction`` and
    ``held`` event; the Suite wires it to the project's history store + `_Broker`.
    ``scope_check(host) -> bool`` gates intercept and tags each transaction.
    """

    def __init__(self, sink: Callable[[Dict[str, Any]], None],
                 scope_check: Optional[Callable[[str], bool]] = None,
                 headless: bool = False):
        self._sink = sink
        self._scope_check = scope_check or (lambda _host: True)
        self._headless = headless
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._started = threading.Event()
        self._start_error: Optional[str] = None
        self._intercept = False
        self._routed = False       # whether context.route is currently installed
        self._held: Dict[int, Dict[str, Any]] = {}
        self._held_lock = threading.Lock()
        self._held_seq = 0
        self.running = False
        # Screencast state — the browser renders offscreen (headless) and streams
        # JPEG frames over CDP, which the dashboard shows and drives; no display
        # on the host is required.
        self._cdp = None
        self._vw, self._vh = 1280, 800
        self._frame_bytes = b""
        self._frame_seq = 0
        self._frame_cond = threading.Condition()   # notified on each new frame

    # ── lifecycle ────────────────────────────────────────────────────────────
    def launch(self, timeout: float = 45) -> Dict[str, Any]:
        if not PLAYWRIGHT_AVAILABLE:
            return {"ok": False, "error": "Playwright not installed — "
                    "pip install playwright && playwright install chromium"}
        if self.running:
            return {"ok": True, "already": True}
        self._start_error = None
        self._started.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._started.wait(timeout):
            return {"ok": False, "error": "browser did not start in time"}
        if self._start_error:
            return {"ok": False, "error": self._start_error}
        self.running = True
        return {"ok": True}

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._boot())
        except Exception as e:  # noqa: BLE001
            # Headful launch without a display lands here with a clear message.
            low = str(e)
            if ("Executable doesn't exist" in low or "playwright install" in low
                    or "looks like Playwright" in low):
                self._start_error = ("Chromium isn't installed for Playwright. In the "
                                     "environment running Beatrix, run:  "
                                     "python -m playwright install chromium")
            elif not self._headless and ("Missing X server" in low or "DISPLAY" in low
                                         or "XServer" in low or "without having a X" in low):
                self._start_error = ("no display on this host — a headful browser needs "
                                     "one. Run Beatrix on your desktop, or set "
                                     "BEATRIX_BROWSER_HEADLESS=1 to run it headless.")
            else:
                self._start_error = f"{type(e).__name__}: {e}"
            # Tear down the half-started playwright connection so we don't leak a
            # subprocess or leave pending tasks ("Event loop is closed" noise).
            try:
                self._loop.run_until_complete(self._shutdown())
            except Exception:  # noqa: BLE001
                pass
            self._close_loop()
            self._started.set()
            return
        self._started.set()
        try:
            self._loop.run_forever()
        finally:
            try:
                self._loop.run_until_complete(self._shutdown())
            except Exception:  # noqa: BLE001
                pass
            self._close_loop()

    def _close_loop(self) -> None:
        # Let the Playwright driver's subprocess transports finish closing before we
        # close the loop, so their __del__ doesn't fire "Event loop is closed" on
        # the server console.
        try:
            self._loop.run_until_complete(asyncio.sleep(0.25))
        except Exception:  # noqa: BLE001
            pass
        try:
            self._loop.close()
        except Exception:  # noqa: BLE001
            pass

    async def _boot(self) -> None:
        self._pw = await async_playwright().start()
        # Drop the automation tells so in-scope sites (and the bot-challenge widgets
        # they gate flows with) treat this like a normal browser: no
        # navigator.webdriver, no "controlled by automated software" surface. This
        # is the same reason browser_transport.py exists — a real browser for real
        # testing — not a CAPTCHA solver; the operator still clicks challenges by hand.
        self._browser = await self._pw.chromium.launch(
            headless=self._headless,
            args=["--no-sandbox", "--disable-blink-features=AutomationControlled"],
            ignore_default_args=["--enable-automation"])
        # Notice a crash/close so the controller is torn down cleanly instead of
        # leaving the UI thinking it's running (and a later launch starting a
        # second browser on the same controller — a process leak).
        self._browser.on("disconnected", self._on_disconnected)
        self._context = await self._browser.new_context(
            user_agent=_UA, viewport={"width": self._vw, "height": self._vh})
        await self._context.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
        # Context-level events catch every tab/popup in the window.
        self._context.on("response", lambda r: asyncio.ensure_future(self._on_response(r)))
        # NB: request interception (context.route) starves CDP screencast frame
        # delivery, so it is installed only while intercept is ON (set_intercept),
        # not here — otherwise the live view freezes during normal browsing.
        self._page = await self._context.new_page()
        await self._start_screencast(self._page)
        # Follow popups / new tabs — registered AFTER the first page so it only
        # fires for *subsequent* pages (otherwise the initial page would be
        # screencast twice and its frames dropped as "stale").
        self._context.on("page", lambda pg: asyncio.ensure_future(self._on_new_page(pg)))

    _SC_PARAMS = {"format": "jpeg", "quality": 55, "everyNthFrame": 1}

    async def _start_screencast(self, page) -> None:
        """(Re)start the screencast on ``page`` and make it the active page for
        input. Called on boot, on navigation (screencast stops on cross-origin
        nav — a CDP quirk), and when a popup/tab becomes the active page."""
        if self._cdp is not None:
            try:
                await self._cdp.send("Page.stopScreencast")
            except Exception:  # noqa: BLE001
                pass
        self._page = page
        cdp = await self._context.new_cdp_session(page)
        self._cdp = cdp
        cdp.on("Page.screencastFrame",
               lambda p, c=cdp: asyncio.ensure_future(self._on_frame(p, c)))
        params = dict(self._SC_PARAMS, maxWidth=self._vw, maxHeight=self._vh)
        try:
            await cdp.send("Page.startScreencast", params)
        except Exception:  # noqa: BLE001
            pass
        # The screencast stops on navigation; restart it on every main-frame
        # navigation (framenavigated fires reliably, unlike load) and again on load
        # as a backstop. A restart resumes the stream and captures subsequent paints.
        page.on("framenavigated",
                lambda fr, pg=page, c=cdp: asyncio.ensure_future(self._rekick(pg, c, params, fr)))
        page.on("load", lambda pg=page, c=cdp: asyncio.ensure_future(self._rekick(pg, c, params)))

    async def _rekick(self, page, cdp, params, frame=None) -> None:
        # A clean stop→start cycle: re-issuing startScreencast while one is already
        # running wedges the stream, so stop first, then start on the new document.
        try:
            if frame is not None and frame != page.main_frame:
                return                      # ignore subframe navigations
            if page is self._page and cdp is self._cdp:
                try:
                    await cdp.send("Page.stopScreencast")
                except Exception:  # noqa: BLE001
                    pass
                await cdp.send("Page.startScreencast", params)
        except Exception:  # noqa: BLE001
            pass

    async def _on_new_page(self, page) -> None:
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:  # noqa: BLE001
            pass
        await self._start_screencast(page)

    def _on_disconnected(self, *a) -> None:
        # Fired on the loop when Chromium closes/crashes. Mark not-running, wake any
        # streamers, and stop the loop so _shutdown runs and a later launch is clean.
        self.running = False
        with self._frame_cond:
            self._frame_cond.notify_all()
        try:
            self._loop.call_soon_threadsafe(self._loop.stop)
        except Exception:  # noqa: BLE001
            pass

    async def _shutdown(self) -> None:
        # Per-close timeout so a hung close can't block teardown and leak the rest.
        for closer in (getattr(self._context, "close", None),
                       getattr(self._browser, "close", None),
                       getattr(self._pw, "stop", None)):
            if closer is None:
                continue
            try:
                await asyncio.wait_for(closer(), timeout=8)
            except Exception:  # noqa: BLE001
                pass

    # ── capture ──────────────────────────────────────────────────────────────
    async def _on_response(self, response) -> None:
        try:
            req = response.request
            url = response.url
            host = _host_of(url)
            try:
                body = await response.body()
            except Exception:  # noqa: BLE001
                body = b""      # body can be gone on redirect/abort — keep the row
            try:
                resp_headers = dict(await response.all_headers())
            except Exception:  # noqa: BLE001
                resp_headers = dict(response.headers)
            try:
                req_headers = dict(await req.all_headers())
            except Exception:  # noqa: BLE001
                req_headers = dict(req.headers)
            tx = {
                "method": req.method,
                "url": url,
                "host": host,
                "path": urlparse(url).path or "/",
                "status": response.status,
                "mime": resp_headers.get("content-type", "").split(";")[0],
                "resource_type": req.resource_type,
                "req_headers": req_headers,
                "req_body": (req.post_data or "")[:_MAX_BODY],
                "resp_headers": resp_headers,
                "resp_body": body[:_MAX_BODY].decode("utf-8", "replace"),
                "length": len(body),
                "ts": time.time(),
                "in_scope": bool(self._scope_check(host)),
            }
            self._sink({"type": "transaction", "detail": tx})
        except Exception:  # noqa: BLE001
            pass            # a capture failure must never break browsing

    # ── screencast + input (the embedded viewer) ─────────────────────────────
    async def _on_frame(self, params: Dict[str, Any], cdp: Any = None) -> None:
        if cdp is not None and cdp is not self._cdp:
            return          # a stale page's screencast — ignore its frames
        try:
            data = base64.b64decode(params.get("data", "") or "")
        except Exception:  # noqa: BLE001
            data = b""
        with self._frame_cond:
            self._frame_seq += 1
            self._frame_bytes = data
            self._frame_cond.notify_all()
        # Ack on the frame's own session so CDP sends the next frame (backpressure).
        try:
            await (cdp or self._cdp).send("Page.screencastFrameAck", {"sessionId": params["sessionId"]})
        except Exception:  # noqa: BLE001
            pass

    def get_frame(self, since: int = 0) -> Optional[Dict[str, Any]]:
        """Latest frame as base64 (the JSON poll fallback)."""
        with self._frame_cond:
            if self._frame_seq > int(since or 0) and self._frame_bytes:
                return {"seq": self._frame_seq,
                        "data": base64.b64encode(self._frame_bytes).decode("ascii")}
        return None

    def wait_frame(self, since: int = 0, timeout: float = 10) -> Optional[Dict[str, Any]]:
        """Block until a frame newer than ``since`` (raw bytes) — the MJPEG push path."""
        with self._frame_cond:
            if not (self._frame_seq > int(since or 0) and self._frame_bytes):
                self._frame_cond.wait(timeout)
            if self._frame_seq > int(since or 0) and self._frame_bytes:
                return {"seq": self._frame_seq, "bytes": self._frame_bytes}
        return None

    def viewport(self) -> Dict[str, int]:
        return {"width": self._vw, "height": self._vh}

    def input_event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        return self._call(self._dispatch_input(ev), timeout=10)

    async def _dispatch_input(self, ev: Dict[str, Any]) -> None:
        page, t = self._page, ev.get("t")
        btn = ev.get("button", "left")
        x, y = float(ev.get("x", 0)), float(ev.get("y", 0))
        if t == "move":
            await page.mouse.move(x, y)
        elif t == "down":
            await page.mouse.move(x, y)
            await page.mouse.down(button=btn)
        elif t == "up":
            await page.mouse.up(button=btn)
        elif t == "click":
            await page.mouse.click(x, y, button=btn, click_count=int(ev.get("count", 1)))
        elif t == "wheel":
            await page.mouse.move(x, y)
            await page.mouse.wheel(float(ev.get("dx", 0)), float(ev.get("dy", 0)))
        elif t == "type":
            await page.keyboard.insert_text(ev.get("text", ""))
        elif t == "press":
            await page.keyboard.press(ev.get("key", ""))

    def nav(self, action: str) -> Dict[str, Any]:
        return self._call(self._nav(action))

    async def _nav(self, action: str) -> None:
        page = self._page
        if action == "back":
            await page.go_back()
        elif action == "forward":
            await page.go_forward()
        elif action == "reload":
            await page.reload()

    # ── intercept ──────────────────────────────────────────────────────────────
    async def _route_handler(self, route) -> None:
        req = route.request
        host = _host_of(req.url)
        if not self._intercept or not self._scope_check(host):
            try:
                await route.continue_()
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            headers = dict(await req.all_headers())
        except Exception:  # noqa: BLE001
            headers = dict(req.headers)
        fut = self._loop.create_future()
        with self._held_lock:
            self._held_seq += 1
            hid = self._held_seq
            self._held[hid] = {"future": fut, "method": req.method, "url": req.url,
                               "headers": headers, "post_data": req.post_data or "",
                               "ts": time.time()}
        self._sink({"type": "held", "detail": {"id": hid, "method": req.method,
                                               "url": req.url, "host": host}})
        try:
            decision = await asyncio.wait_for(fut, timeout=_HOLD_TIMEOUT)
        except asyncio.TimeoutError:
            decision = {"action": "forward"}
        with self._held_lock:
            self._held.pop(hid, None)
        if decision.get("action") == "drop":
            try:
                await route.abort()
            except Exception:  # noqa: BLE001
                pass
            return
        ov = decision.get("overrides") or {}
        kwargs: Dict[str, Any] = {}
        for k in ("url", "method", "post_data"):
            if ov.get(k):
                kwargs[k] = ov[k]
        if ov.get("headers") is not None:
            kwargs["headers"] = ov["headers"]
        try:
            await route.continue_(**kwargs)
        except Exception:  # noqa: BLE001
            try:
                await route.continue_()
            except Exception:  # noqa: BLE001
                pass

    # ── commands (called from Suite HTTP handler threads) ──────────────────────
    def _call(self, coro, timeout: float = 35) -> Dict[str, Any]:
        if not self.running or self._loop is None:
            return {"ok": False, "error": "browser not running"}
        try:
            fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
            fut.result(timeout=timeout)
            return {"ok": True}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def navigate(self, url: str) -> Dict[str, Any]:
        if not (url or "").strip():
            return {"ok": False, "error": "enter a URL"}
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return self._call(self._navigate(url))

    async def _navigate(self, url: str) -> None:
        page = self._page or await self._context.new_page()
        self._page = page
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)

    def set_intercept(self, on: bool) -> Dict[str, Any]:
        r = self._call(self._set_intercept(bool(on)))
        return {"ok": r.get("ok", False), "intercept": self._intercept,
                **({"error": r["error"]} if r.get("error") else {})}

    async def _set_intercept(self, on: bool) -> None:
        self._intercept = on
        if on and not self._routed:
            await self._context.route("**/*", self._route_handler)
            self._routed = True
        elif not on and self._routed:
            try:
                await self._context.unroute("**/*", self._route_handler)
            except Exception:  # noqa: BLE001
                pass
            self._routed = False
            # Interception degrades the screencast; restart it so the live view
            # is smooth again once the operator leaves intercept mode.
            if self._cdp is not None:
                params = dict(self._SC_PARAMS, maxWidth=self._vw, maxHeight=self._vh)
                try:
                    await self._cdp.send("Page.stopScreencast")
                    await self._cdp.send("Page.startScreencast", params)
                except Exception:  # noqa: BLE001
                    pass

    def held(self) -> List[Dict[str, Any]]:
        with self._held_lock:
            return [{"id": k, "method": v["method"], "url": v["url"],
                     "headers": v["headers"], "post_data": v["post_data"], "ts": v["ts"]}
                    for k, v in sorted(self._held.items())]

    def _resolve(self, hid: Any, decision: Dict[str, Any]) -> Dict[str, Any]:
        with self._held_lock:
            entry = self._held.get(int(hid))
        if not entry:
            return {"ok": False, "error": "no such held request (already forwarded?)"}
        fut = entry["future"]
        self._loop.call_soon_threadsafe(
            lambda: None if fut.done() else fut.set_result(decision))
        return {"ok": True}

    def forward(self, hid: Any, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._resolve(hid, {"action": "forward", "overrides": overrides or {}})

    def drop(self, hid: Any) -> Dict[str, Any]:
        return self._resolve(hid, {"action": "drop"})

    def state(self) -> Dict[str, Any]:
        with self._held_lock:
            held = len(self._held)
        return {"running": self.running, "intercept": self._intercept, "held": held,
                "available": PLAYWRIGHT_AVAILABLE,
                "viewport": {"width": self._vw, "height": self._vh}}

    def stop(self) -> Dict[str, Any]:
        if not self.running:
            return {"ok": True}
        self.running = False
        with self._frame_cond:          # wake any MJPEG streamers so they can exit
            self._frame_cond.notify_all()
        # release any held requests so the route handlers unwind cleanly
        with self._held_lock:
            futs = [v["future"] for v in self._held.values()]
        if self._loop is not None:
            for fut in futs:
                self._loop.call_soon_threadsafe(
                    lambda f=fut: None if f.done() else f.set_result({"action": "forward"}))
            self._loop.call_soon_threadsafe(self._loop.stop)
        return {"ok": True}
