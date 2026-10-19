# Changelog

All notable changes to Beatrix are documented here.

## [Unreleased]

### New — Weaponization stage: Collaborator (OAST) module
- The previously-empty **Weaponization** kill-chain stage now has its first module: an **OAST /
  Collaborator** for blind-vulnerability testing. Mint a canary URL (tagged SSRF/XXE/RCE/blind-SQLi + a
  note), paste it into a target request (ready-made snippets: bare URL, `curl`, XXE entity, shell), and when
  the target reaches out, the hit appears in a **live callbacks table** correlated to what you were testing —
  proof of a blind vuln the automated scan can only infer. Canaries point at this suite by default (localhost
  / a forwarded port); set a public **base URL** for external engagements. The receiver only records inbound
  hits. One-click **Send to Repeater** to place the canary in a request. (interact.sh support to come.)

### Fixed — right-click menu now appears (everywhere)
- Right-clicking a request (HTTP, AutoRepeater, Issues, Site map, Network, Repeater) produced no menu. Two
  causes: a duplicate `id="ctxmenu"` let the project-tab menu's click-to-dismiss force inline
  `display:none` on the shared routing menu (which toggles via the `hidden` attribute, so it stayed
  invisible after the first click), and `showCtxMenu` positioned the menu with un-zoomed coordinates so it
  rendered off-screen at any UI zoom ≠ 1. The two menus are now separate elements and the menu is
  zoom-correctly placed and clamped on-screen. Verified at multiple zooms and click positions.

### New — JWT module (Exploitation; kill-chain Phase 1)
- **A JWT workbench** in the Exploitation stage: **Decode** any token locally (header, claims with
  `exp`/`iat`/`nbf` as readable time, signature, alg-specific guidance — all offline, nothing sent),
  **Analyze** it with jwt_tool's full test suite (alg confusion, none-alg, blank/weak secret, known CVEs —
  findings also file into Issues), and **Forge** tokens (alg=none, HMAC re-sign with a secret via WebCrypto,
  or jwt_tool claim injection) then send straight to the Repeater. Right-click any request carrying a JWT →
  **Send JWT to JWT workbench** (it swaps a forged token back into the original request for replay).
  jwt_tool features degrade gracefully when it isn't installed; decode + forge always work. This is the first
  of the Phase-1 operator tool modules and establishes the reusable module scaffold.

### Fixed — AutoRepeater landscape + HTTP row selection
- **AutoRepeater is usable in landscape.** In a wide/short window the vertical stack squeezed the results
  area to nothing; it now switches to a grid (toolbar across the top, config on the left, results filling
  the right) in landscape while keeping the stacked layout in portrait.
- **HTTP: highlight = selection (OS/office style).** Selecting rows in the HTTP history no longer depends on
  the checkboxes — click to select (and preview), Ctrl/Cmd-click to toggle, Shift-click for a range; the
  highlighted rows ARE the selection that "Send to Repeater" / Delete / right-click act on. Right-click opens
  the full context menu on the selection; checkboxes remain as a mirror.

### Fixed — suite-wide layout & readability
- **No more right-edge cutoff — now rail-aware.** The global UI scaler caps zoom by a width ceiling so the
  *module content area* (the workspace, i.e. viewport minus the 54px project rail) can never be narrower
  than modules need (`viewport − rail ≥ MODULE_MIN`), with a root `overflow-x:clip` guard and wrapping
  sub-tab strips. Reserving the rail in the scaling budget was the missing piece — content tuned near
  full-width used to come up ~54px short and get clipped by the `overflow:hidden` panes. Verified headless:
  zero clipped content across every module at the worst-case workspace width and text-scale 1.6, in both themes.
- **Subtle depth in every table.** Rows and columns now use low-alpha, matrix-themed blending — a faint
  phosphor zebra on alternate rows, a brighter hover/selection wash, a raised header "shelf", and hairline
  column separation — so the eye can group the data without hard gridlines or boxed-in cells. Special row
  states (Issues severity bars / false-positive dimming, Sitemap signal tints) are preserved.
- **Smarter, fully-dynamic column sizing.** Tables now distribute width intelligently: short columns
  (ids, status, counts, dates) stay tight while wide text columns share the remaining space
  proportionally, filling the container exactly instead of one column ballooning or others getting
  cramped. Re-balances on window/zoom/pane resize; drag-resize, double-click auto-fit, and persisted
  widths still work.
- **Consistent dynamic padding** — panes use the shared responsive `--gutter` symmetrically; the
  background effect no longer overflows the viewport.
- **Removed emoji button icons** in favor of plain text labels (traditional glyphs like the menu and
  sort arrows are kept).

### New — Repeater: predictive parameters for *every* parameterized query (Params)
- **Stop guessing parameters — on any endpoint.** The Repeater's **Params** button discovers an endpoint's
  parameters from the best source available and drops a ready-to-send, correctly-typed **stencil** into the
  editor (the params written into the right place — query string, JSON body, form body, or GraphQL document):
  - **GraphQL introspection** — every operation, each argument's exact type, required/optional, default, and
    for enums the complete set of accepted values.
  - **OpenAPI / Swagger** — fetches the spec (well-known paths or one already captured), matches the current
    (possibly templated, e.g. `/users/{id}`) path, and expands query/path params + the JSON request body.
  - **HTML `<form>`** — reads declared fields from the response: names, required, hidden defaults, and
    `<select>` options as enums.
  - **Observed** — aggregates parameters seen in captured traffic (and the current request), inferring type,
    example, and a confidence/required guess by frequency — sends no new requests.
  Each parameter shows its **source** and **confidence**; the stencil reuses the request's auth so
  authenticated endpoints are discovered as the current session.
- **Verify (active) — confirm what the server actually accepts.** An explicit, scope-gated action that
  reuses **Arjun** (hidden-parameter discovery; falls back to the built-in miner) for REST/JSON/form
  endpoints, and **Clairvoyance** to recover a GraphQL schema when introspection is disabled — folding the
  confirmed params back into the panel as new stencils. Out-of-scope targets prompt first.
- **Honest about locked-down servers.** When introspection is disabled it says so and surfaces any
  `Did you mean <field>` names leaked in errors, pointing you at Verify.
- `install.sh` now also installs `arjun` and `clairvoyance` (both optional — active verify degrades
  gracefully to the built-in miner / a clear note when they're absent).

## v2.1.0 — The Black Mamba · 2026-10-18

**v2.1.0 turns the Suite from a handful of tabs into a full, kill-chain-staged pentesting workbench in the
browser.** v2.0 shipped the Dashboard, Issues, Repeater, AutoRepeater, Auth, Ghost, and Scope; v2.1 adds a
whole Reconnaissance stage, two new Exploitation modules, and a deep layer of cross-cutting polish — and
re-centers the project on its GUI.

### Licensing
- **Beatrix is now Apache-2.0** — relicensed from source-available to **Apache License 2.0**: free and open
  source, for commercial and non-commercial use alike (see `LICENSE` and `NOTICE`).

### New — Reconnaissance modules
- **OSINT** — keyless external-asset discovery: DNS records, Certificate Transparency (crt.sh + CertSpotter),
  passive-DNS and archive sources (AlienVault OTX, HackerTarget, Wayback Machine, RapidDNS), RDAP/WHOIS,
  Shodan InternetDB (exposed ports + CVEs), GeoIP, and origin-IP/CDN-bypass. Includes a one-button,
  **resumable Full Sweep** (Standard / Aggressive) that fans each stage out over the hosts, IPs, and
  netblocks discovered so far, and a **pannable entity map** that shows the entire dataset (scrollable,
  always clickable) instead of truncating.
- **Network** — an nmap / Zenmap workbench in the browser: an 82-preset à-la-carte catalog (9 groups), a
  **resumable Full Sweep** (passive / active) with native `--resume`, a deduped ports/hosts/services
  inventory, and a traceroute **topology** view.
- **Passive Scan**, **Site map** (collapsible, color-coded, scope-aware), and a **Packets** lab (scapy
  crafting + cheat sheet).

### New — Exploitation modules
- **Nuclei** — multi-phase template scanning with a searchable template explorer and per-finding routing.
- **Metasploit** — an msfrpcd-backed console + module bridge.

### Improved — across the Suite
- **Cross-module request routing** — right-click anywhere (HTTP history, Repeater, Issues, Nuclei,
  AutoRepeater, Network, Site map) to **Send to Repeater / AutoRepeater / Nuclei**, add/exclude **scope**,
  **open in Browser**, or **Copy as curl**. Every request-bearing view now reads the same.
- **Never-lose-data** — aggregation **merges** instead of overwriting, and every destructive **Clear** is
  confirmed and **undoable** (browser-history-style delete / clear, with an on-disk single-slot undo).
- **Node-link maps** — left-drag empty space to **pan** with flick **momentum**; the OSINT map renders the
  full dataset (large groups become a scrollable, still-clickable panel).
- **"Support the developer"** — a gold header button + donation popup, and an opening title card (the GUI
  is free; this is the one tasteful ask).
- Premium **design elevation** (bevels / glow / elevation tokens), a **global UI zoom**, uniform controls,
  and spreadsheet-grade tables (auto-fit / drag-resize / wrap) across every module.
- Resilient **project lifecycle** — scan continuity and re-attach, per-project teardown and port cleanup,
  and a live cross-project "scanning" activity glow.

### Improved — scanning engine
- **Resumable scans** with a persistent, clearable event log and a debug toggle.
- Findings now carry the **real captured request/response bytes** — not reconstructed guesses.
- **False-positive** marking, response beautify, expanded HTTP tips, resizable panes, and per-request
  debug lines (via an httpx response event-hook).

### Docs & housekeeping
- README reworked into a concise, **GUI-forward** landing page with fresh screenshots.
- Removed the stale `docs/ARCHITECTURE.md` and `docs/SWEET_SCANNER_MAP.md`; parked unwired modules under
  `wip/`; tightened `.gitignore`.

**Full changelog:** https://github.com/SudoPacman-Syuu/Beatrix-suite/compare/v2.0.0...v2.1.0

## v2.0.0 — The Black Mamba

The first release of **the Suite** — a local web workbench alongside the original CLI: a scanning
dashboard, a triageable Issues board, a raw-HTTP Repeater and an automated AutoRepeater fuzzer, one-drop
authenticated scanning, the Ghost autonomous AI pentester, and end-to-end target Scope, all behind a single
command.
