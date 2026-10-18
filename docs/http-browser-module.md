# HTTP module — native-capture browser + history / site map

A Burp-style manual-testing surface for **authorized, scope-gated** web testing: a
real browser whose traffic Beatrix reads and organizes, with one-click hand-off to
Repeater / AutoRepeater. It is the operator-driven counterpart to the automated
Ghost/Hunt path.

## Why not an intercepting proxy

The usual "point a browser at a MITM proxy" design is detectable — not because a
proxy is visible, but because MITM **terminates and re-originates TLS**, so the
ClientHello (JA3/JA4) and HTTP/2 fingerprint the server sees come from the proxy's
stack while the User-Agent still says Chrome. Anti-bot/WAF systems (Akamai,
Cloudflare, DataDome…) flag that mismatch and disrupt legitimate testing.

This module **doesn't intercept on the wire at all.** It drives a real Chromium with
Playwright and reads the traffic *in-process* via the DevTools protocol
(`BrowserContext.on("request"/"response")`). The browser makes genuine native TLS
connections — the fingerprint *is* Chromium's, because it is Chromium — so there is
nothing on the wire to detect and no CA cert to install. This is the same reason
[`browser_transport.py`](../beatrix/core/browser_transport.py) already exists ("for
targets that fingerprint scripted HTTP clients").

Burp-style **interception is still available**: `context.route` pauses in-scope
requests *inside the browser* so the operator can edit / forward / drop them, and the
browser still originates the connection — the native fingerprint is preserved.

## Driver — `beatrix/core/browser_driver.py`

`BrowserController` runs Playwright's async API on its own event loop in a dedicated
thread (so background capture keeps flowing while the operator browses); the
synchronous Suite HTTP handlers drive it via `run_coroutine_threadsafe` /
`call_soon_threadsafe`, mirroring how `_ScapyWorker` fronts the packet worker.

- `launch()` — `chromium.launch(headless=True)` + a context with a desktop-Chrome UA
  and a fixed 1280×800 viewport. **Automation tells are stripped** so in-scope sites
  (and the bot-challenge widgets that gate their flows) treat it like a normal
  browser: `--disable-blink-features=AutomationControlled`,
  `ignore_default_args=["--enable-automation"]`, and an init script that hides
  `navigator.webdriver`. This is normalization for authorized testing — the operator
  still solves any challenge by hand; it is not a solver.
- **Embedded viewer (screencast over WebSocket):** the page renders offscreen
  (headless) and is streamed as JPEG frames over CDP (`Page.startScreencast` →
  `Page.screencastFrame`, each decoded to bytes and acked). A single **WebSocket**
  (`/browser/ws`, a hand-rolled RFC 6455 upgrade on the existing threaded server)
  carries it bidirectionally: `wait_frame(since)` pushes each raw JPEG **down** as a
  binary frame, and operator input (mouse/keys) goes **up** as text JSON on the same
  socket. The client renders frames to a `<canvas>` via `createImageBitmap`. One
  bidirectional socket means much lower input latency and clean reconnects.
- **MJPEG fallback:** some proxies don't forward WebSockets — notably **GitHub
  Codespaces port-forwarding**, where plain HTTP passes but a WS upgrade does not. So
  the client tries the WS first and, if no frame arrives within ~2.5 s (or it closes
  without ever delivering one), transparently falls back to an **MJPEG `<img>`**
  (`/browser/stream`, `multipart/x-mixed-replace`) which rides any HTTP proxy; input
  then goes over `/browser/input` POSTs. So it's fast (WS) on a direct/real-browser
  connection and still works (MJPEG) behind a WS-hostile forward. Non-realtime actions
  (`navigate`, `nav`, `intercept`, history) are always plain HTTP. Because the browser
  renders headless, **no display is needed on the host** — desktop or Codespace alike.
- **Reliability:** the screencast stops whenever the page navigates, so it is
  restarted (clean `stopScreencast`→`startScreencast`) on every main-frame
  `framenavigated` (and `load`), and the view follows popups/new tabs
  (`context.on("page")`). On the client, the WebSocket reconnects on close/error and
  whenever the Browser tab is re-opened — so a dropped stream recovers on its own
  instead of needing a browser restart.
- **Capture** — `context.on("response")` assembles a transaction `{method, url, host,
  path, status, mime, resource_type, req_headers, req_body, resp_headers, resp_body,
  length, ts, in_scope}` and hands it to the sink. Bodies are capped (512 KiB) and
  guarded (they can be gone on redirect/abort).
- **Intercept** — `set_intercept(on)` installs a `context.route("**/*")` handler **only
  while intercept is on** (request interception adds overhead during normal browsing,
  so it isn't left on). With intercept on, an **in-scope** request is held (the handler
  blocks on a future, 300 s cap) until the operator forwards (optionally with edited
  method/headers/body → `route.continue_(...)`) or drops (`route.abort()`); turning it
  off unroutes and restarts the screencast. Out-of-scope requests continue untouched.

## Suite glue — `beatrix/cli/suite.py`

- `browser_controllers` + `browser_brokers` per project (created/cleared in
  `mount_session` next to the nmap/capture ones; live windows are closed on session
  switch). `_browser_for` wires the controller's sink to append each transaction into
  the history store and emit it on the project's `_Broker`, and injects a
  `scope_check` backed by the project scope (`_host_in_scope` / `get_scope`).
- `_HttpHistoryStore` → `<project>/http-history.json` (ring-buffered, cap 5000):
  `append`, `list` (filter by host / scope / URL substring), `get` (full record),
  `sitemap` (host → path tree with per-node counts), `clear`.
- Routes:
  `/browser/{state,launch,stop,navigate,nav,events,frame,ws,popout,input,intercept/{set,list,forward,drop}}`,
  `/http/{history,detail,sitemap,clear}`. `/browser/ws` is the screencast+input
  WebSocket and `/browser/popout` is a standalone page (below); both run on their own
  threads (`ThreadingHTTPServer`), so a long-lived socket never blocks other requests.

The surface is split into three focused modules (three nav tabs):

## UI — the **Browser** tab (`pane-browser`)

The interactive capture browser. Toolbar: Back / Forward / Reload, a URL bar,
**Launch** / **Stop**, an **intercept** toggle, **Fullscreen**, and **Pop out**.
Below it, the live screen (a `<canvas id="br-screen">` fed by the WebSocket) shows the
page; mouse moves/clicks/scroll and keystrokes on it are forwarded to the real
browser. While intercept is on, an **intercept bar** shows the held request with
**Forward** / **Edit…** / **Drop**.

- **Fullscreen** uses the Fullscreen API on the screen wrapper.
- **Pop out** (`window.open` → `/browser/popout`) opens the browser in its own OS
  window — natively drag-resizable — so you can browse there while the main window
  stays on the **HTTP** tab watching traffic. Both windows drive the same browser
  over the same `/browser/*` routes.

## UI — the **HTTP** tab (`pane-http`)

Focused on one thing: **listing captured web traffic.** Requests are routed to other
modules from a **right-click context menu**, not inline buttons.

- **Toolbar:** a URL search box, a **scope only** toggle (on by default), **Clear**.
- **Request list** (the hero): the HTTP history table (#, method, host, path, status,
  type, length) — rows stream in live over the broker; out-of-scope rows are dimmed.
  **Right-click a row** → **Send to Repeater** (reuses the Issues→Repeater bridge,
  `POST /repeater/new`), **Send to AutoRepeater**, **Copy URL**. A filter chip appears
  when the list is scoped to a host/path from the Site map (with a one-click clear).
- **Detail:** selecting a row shows the reconstructed raw request + response below.

## UI — the **Site map** module (`pane-sitemap`)

A separate module (its own nav tab) that organizes the captured hosts into a
host → path **tree** with per-node request counts, over the same `/http/sitemap` data
(scope-only toggle + Refresh). Clicking a node jumps to the HTTP tab filtered to that
host/path, so the map is a navigation front-end onto the request list.

## Scope & authorization

Every transaction is tagged `in_scope` against the project scope; the history and site
map default to a scope-only view, and intercept only holds in-scope requests. The
browser stays inside Beatrix's end-to-end scope enforcement — it is for testing targets
you are authorized to test.

## Requirements

`playwright>=1.40.0` (already a dependency) plus its Chromium
(`playwright install chromium`). The browser runs **headless** and is viewed through
the screencast, so **no display is required** on the Beatrix host — it works the same
on a desktop and in a headless Codespace.

## Verification

- Unit (`tests/test_browser_driver.py`, `pytest.importorskip("playwright.async_api")`,
  headless against a throwaway localhost server): passive capture emits one transaction
  per request with correct fields + `in_scope`; intercept forward/drop against held
  requests; `_HttpHistoryStore` filtering, site-map tree building, and clear with
  synthetic transactions (no browser). Set `BEATRIX_BROWSER_HEADLESS=1` to run the
  driver tests without a display.
- Integration (local, headful): launch the browser, visit an app, watch history + site
  map populate live, click a row → Send to Repeater and confirm the raw request
  round-trips. Existing `tests/test_suite.py` still passes (no route regressions).
