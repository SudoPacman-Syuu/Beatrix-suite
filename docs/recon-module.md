# Recon module (the free, useful parts of recon-ng, as a GUI)

A per-project OSINT workspace in the Beatrix Suite. Keyless only — no paid services.
Components each take a target and return typed entities that merge into an organized,
deduped workspace, and the rows wire into the Network and Repeater modules.

## Engine — `beatrix/core/recon_engine.py`

A component registry (`COMPONENTS`, `component_catalog`, `run_component`). Each component
`run(target, opts, on_log) -> {entities, log}`; entity kinds: `domain, subdomain, ip,
netblock, contact, origin`. Thirteen components in five clusters:

- **DNS & Hosts** — DNS records (reuses `recon_helpers.dns_recon`, incl. SPF `ip4:` → origin
  hints), DNS brute-force (threaded resolver + wildcard detection + built-in ~90-word list),
  zone transfer (AXFR via dnspython), resolve, reverse.
- **Subdomains** — Certificate Transparency (crt.sh JSON, keyless), TLS SANs (reuses
  `extract_ssl_sans`).
- **Ownership** — **RDAP** for IP (org / netblock CIDR / country / abuse contact, via the free
  `rdap.org` bootstrap) and domain (registrar / dates / contacts); ASN/netblock (reuses
  `whois_asn_lookup` → Team Cymru); WHOIS (binary → contact emails). CDN orgs are flagged.
- **Netblock** — reverse-DNS sweep of a CIDR (threaded, capped at 4096) → hosts.
- **Origin-IP** — surfaces the free Cloudflare-bypass engine
  `beatrix.scanners.origin_ip_discovery.OriginIPDiscovery`. Built-ins: crt.sh, viewdns DNS
  history, MX, common-subdomain probing, historical WHOIS. **Added free passive-DNS / scan
  sources** for broader origin coverage: **HackerTarget** hostsearch (confirmed returning data),
  **urlscan.io** search (observed IPs), and **AlienVault OTX** passive DNS (best-effort —
  keyless responses can be empty). CDN filtering now also pulls **Cloudflare's live published
  ranges** (free) and merges them with the static CDN/hosting ranges. Candidates are validated
  by ASN (reject hosting/CDN ASNs via Team Cymru) and **Host-header** request (the IP must
  actually serve the site), and carry a confidence score + evidence + verified flag.

Async helpers are driven with `asyncio.run` from the component thread; HTTP via `requests`.

## Suite glue — `beatrix/cli/suite.py`

- `_ReconStore` → `<project>/recon.json`: entity tables keyed per kind, merged by natural key
  with enrichment (list fields unioned; `verified` OR-ed; `score` max-ed; scalars first-wins;
  `sources` accumulated) + a run history.
- `start_recon_component` runs a component on a thread, streams its log to `recon_brokers[pid]`
  (`_Broker`), merges returned entities, records the run — the Ghost/nmap pattern.
- `recon_import_nmap` pulls IPs/hosts the Network module discovered into the workspace.
- Routes: `/recon/{catalog,workspace,events,run,stop,delete,clear,import_nmap}`.

## UI (`pane-recon`, "Recon" tab)

- **Runner:** component dropdown grouped by cluster, free-fire target (with an
  "authorized only" placeholder), per-component options (e.g. brute wordlist), Run/Stop, and a
  live activity log. Also "⬇ nmap IPs" (import) and "Clear".
- **Workspace:** a counts panel + entity sub-tabs (IPs · Subdomains · Origins · Netblocks ·
  Contacts · Domains) with a row filter. The IP table shows org/netblock/ASN/country and a CDN
  badge; Origins show score + a "✓ Host-header" verified badge + evidence.
- **Cross-module row actions:** IP → RDAP (verify ownership) · Scan (hand to Network/nmap) ·
  Repeater (Host-header request straight to the IP). Subdomain → Resolve · Scan. Origin →
  **Verify** (opens the Repeater with `Host: <domain>` pointed at the candidate IP — confirms a
  true origin behind Cloudflare) · Scan. Netblock → Sweep.

## Honest limits
- **Origin-IP is best-effort.** It finds the origin when something leaks (non-proxied
  subdomain, MX on origin infra, SPF `ip4:`, historical DNS, or a candidate IP that serves the
  site via the Host header). A well-locked-down origin can be un-findable without paid data —
  the UI shows the evidence and says so.
- **Contacts** are WHOIS/RDAP abuse/registrant only (keyless, reliable); no search-engine
  email scraping (fragile, blocked).

## Verification
- Engine tested directly: resolve/reverse (localhost), **RDAP 8.8.8.8 → Google LLC / 8.8.8.0/24
  / abuse contact / CDN flag**, crt.sh subdomains.
- Suite e2e (live server): `/recon/run` → poll `/recon/events` → entities land in
  `/recon/workspace` (enriched), run history recorded; `import_nmap` pulls prior-scan IPs.
- Origin-IP wraps the already-working `OriginIPDiscovery` engine; exercised manually against a
  real CDN-fronted domain (network-dependent).
- No regressions: `tests/test_suite.py` passes except the pre-existing
  `test_auth_gui_mounted_same_origin`.
