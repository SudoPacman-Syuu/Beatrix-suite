# Changelog

All notable changes to Beatrix are documented here.

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
