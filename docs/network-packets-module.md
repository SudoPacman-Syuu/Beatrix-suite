# Network (Zenmap) + Packets/Scapy (Wireshark) modules

Two per-project tabs in the Beatrix Suite, driven by the `nmap` + `scapy` engines
(no desktop apps, no remote-desktop streaming). Built on the suite's existing
patterns: the `_Broker` event stream (from `ghost_web`), the per-project JSON
store (`_RepeaterStore`-style), and the `do_GET`/`do_POST` route dispatch.

## Network tab (Zenmap-style)

A command builder + streamed results over the real `nmap` binary.

- **Backend:** `beatrix/core/nmap_runner.py` runs `nmap -oX <file>` via subprocess
  (argv list, never a shell), parses the XML (`xml.etree`) into hosts / ports /
  services / OS / NSE scripts / traceroute hops, and diffs two scans. Privileged
  profiles (`-sS/-sU/-O/-A/--traceroute`) run under `sudo -n` automatically.
- **Suite glue:** `_NmapStore` → `<project>/nmap.json` (scan history + raw XML);
  `start_nmap_scan` streams stdout to `nmap_brokers[pid]` on a thread, like Ghost.
  Routes: `/nmap/{state,run,stop,events,result,diff,delete}`.
- **Live results:** `nmap -oX` appends each `<host>` as that host finishes, so an
  `xml.etree.XMLPullParser` (`LiveHostStream`) reads only new bytes each poll and
  yields a host once its closing tag has arrived — never a half-written host, never
  twice. Those hosts stream to the UI as `hosts` broker events while the scan runs,
  so the Ports/Hosts list populates live. Each completed host goes through the same
  `_parse_host` the final parse uses, so the live view and the authoritative
  whole-file result are identical; the stale XML file is removed before each scan
  so a prior scan's hosts can't replay.
- **UI (`pane-network`):** Target + Zenmap profile dropdown + editable options +
  Scan/Stop + "capture traffic"; left = a filterable hosts list (`#net-hostsearch`
  matches ip/name/port/service) + scan history; right tabs = Ports/Hosts,
  **Services**, **Topology**, Host Details, Nmap Output. The host list and the
  selected host's ports update live as hosts complete, preserving the operator's
  current selection.
  - **Services** aggregates open ports across the whole inventory (service → ports
    → which hosts), the pivot Zenmap's Services pane gives.
  - **Topology** is an SVG graph: every host's traceroute is merged into one tree
    rooted at "you" (shared hop prefixes collapse, branches show where paths
    diverge), laid out in columns by TTL — not the old flat hop list.
- **Saved profiles + export:** `_NmapProfileStore` → `<project>/nmap-profiles.json`
  holds custom named profiles that merge into the dropdown under "Saved" (built-in
  `NMAP_PROFILES` can't be shadowed); "Save as…" captures the current options,
  "Delete profile" removes a saved one. "Export" downloads the selected (or latest)
  scan as raw XML, CSV (`to_csv`, one row per host/port), or greppable `.gnmap`
  (`to_gnmap`). Routes: `/nmap/{profiles,profiles/save,profiles/delete,export}`.
- **Scan diff** (`diff_scans`, surfaced via `/nmap/diff`): per host, reports port
  added/removed/changed (changed on state, service, version, **product or tunnel**),
  a change in the best **OS** guess, host-**script** add/remove/change, and whether a
  host is present in one scan only.
- **Merged host inventory (one row per host, not per scan):** `_NmapStore` keeps a
  persistent `hosts` map keyed by IP in `nmap.json`. `complete_scan` folds each
  scan's hosts into it via `_merge_host` — a rescan *refines* rather than
  duplicates: ports merge by (proto,port) with the newer observation winning and
  earlier ports kept, OS matches union (best accuracy), host scripts merge, a fresh
  traceroute replaces the old one, hostname fills in. The Hosts column reads this
  inventory (`/nmap/hosts`), so Ports/Hosts, Topology, and Host Details all show the
  single accumulated host. The scan-history list still records every run; clicking
  one shows that run's raw output without touching the inventory. (`/nmap/delete_host`
  prunes an entry.)

## Packets tab (Wireshark-style + full scapy)

- **Read/dissect (unprivileged):** `beatrix/core/packet_engine.py` uses scapy's
  `PcapReader` for the packet list, layer tree, and hex, plus the structured packet
  builder shared with the worker. Opening a pcap needs no root.
- **Display filter (a real boolean grammar):** `_compile_filter` parses a filter
  once into a predicate applied per packet. It supports fields (`ip.addr/src/dst`,
  `eth.addr`, `tcp|udp.port/srcport/dstport`, `tcp.flags/seq/ack/window`,
  `dns.qname`, `frame.len`), comparators `== != < > >= <=`, and boolean
  `&&`/`||`/`!` with parentheses; a bare protocol keyword is an existence test and
  anything unparseable degrades to a summary substring (so old one-word filters
  still work).
- **Follow stream / statistics / export:** `follow_stream` reassembles the TCP/UDP
  conversation a packet belongs to (segments tagged client/server); `statistics`
  tallies protocols, conversations and endpoints; `export_subset` writes the packets
  matching a display filter to a new pcap.
- **Privileged worker:** `beatrix/core/scapy_worker.py` is launched per project as
  `sudo -n <venv-python> -m beatrix.core.scapy_worker`, speaking JSON lines over
  stdin/stdout: `sniff_start/stop`, `send` (structured spec or scapy expression;
  send / sendp / sr1, plus `fragsize` → IP fragmentation via `_do_send_fragmented`),
  `replay`, and `eval` (the console). It streams packet rows and writes a pcap; the
  suite (`_ScapyWorker`) routes streamed packets to `capture_brokers[pid]` and
  command acks to a reply queue.
- **Suite glue:** `_CaptureStore` → `<project>/captures/*.pcap` + `index.json`.
  Routes: `/packets/{env,upload,list,detail,stream,stats,export,capture/start,capture/stop,capture/events,delete}`,
  `/scapy/{send,tls,replay,console,traceroute,resend}`. (`/scapy/tls` is a plain
  socket + `ssl` probe, so it needs no worker.)
- **UI (`pane-packets`):** a capture bar (open pcap, interface, filter, Start/Stop
  live, **Export**) and four sub-tabs — **Viewer** (packet list → layer tree → hex,
  with **Follow stream ↔**), **Stats** (protocol/conversation/endpoint tables),
  **Crafter** (guided recipes, below), and **Console** (scapy REPL). The filter box
  is a *display* filter while viewing but a libpcap *BPF* filter when you press
  Capture — its tooltip spells out the difference.

### Crafter — guided recipes (built for someone who doesn't know scapy)

The Crafter is a recipe picker, not a bare expression box. You choose *what you
want to do* and fill plain-English blanks; it builds a real packet, shows the
exact scapy it generated (the learning bridge), sends it, and reads the reply
back as a plain verdict.

- **Recipes** (JS `PK_RECIPES`, each `{kind, fields, build, scapy, verdict}`):
  *Ping* (ICMP echo), *Check a TCP port* (SYN), *Custom TCP* (flag checkboxes +
  ports/seq), *UDP probe*, *DNS lookup* (server/name/type), *ARP who-has*,
  *Traceroute*, a **Firewall analysis** cluster — *TTL probe* (sets `IP.ttl`),
  *Source-port probe* (SYN from a chosen source port), *Fragmented SYN* (IP-fragment
  reassembly test, via the worker `fragsize` path) — a **TLS probe** (version +
  cipher + certificate, over `/scapy/tls`), *Resend a captured packet*, and *Raw
  scapy expression* (the advanced box, with quick-fill presets). Grouped by cluster
  in the dropdown. The TTL/source-port/fragmentation/TLS recipes surface, in the
  manual Crafter, techniques already implemented in `packet_crafter.py` (the
  automated kill chain's firewall analysis).
- **Safe build path:** guided recipes assemble a structured `spec` and send it via
  the existing `/scapy/send` `spec` branch — **no eval**. To keep DNS on that path,
  `packet_engine.build_packet` now builds *nested* allowlisted layers from the spec
  (`qd: {"_layer":"DNSQR","fields":{…}}`), so `DNS(qd=DNSQR(...))` needs no string
  eval. Only the *Raw* recipe uses the eval path (operator-supplied, as before).
- **Live scapy preview:** the generated scapy (e.g. `IP(dst="x")/TCP(dport=80,
  flags="S")`) is shown and updates as you type; "see the scapy ✎" drops the current
  recipe into the Raw box, pre-filled, to tweak by hand. A collapsible cheat-sheet
  explains stacking with `/`, send vs sr1 vs sendp/srp1, and the TCP-flag letters.
- **Verdicts:** the reply's layer tree is read client-side into a plain banner —
  "✓ Port OPEN (SYN-ACK)", "CLOSED (RST)", "filtered / no reply", "Host is ALIVE",
  ARP MAC, DNS answer count, ICMP port-unreachable — with the full Sent/Reply trees
  still shown below.
- **Traceroute** (`/scapy/traceroute` → worker `traceroute`): one probe per TTL
  (TCP-SYN / ICMP / UDP), stopping at the target; renders the hop list with RTTs.
  Synchronous in the worker (bounded by `maxttl × per-hop timeout`).
- **Replay editor** (`/scapy/resend` → worker `resend`): in the Viewer, select a
  packet and hit "Resend ✎" — it loads into the Crafter with the editable
  IP/TCP/UDP/Raw fields pre-filled; blank keeps the original, lengths/checksums are
  recomputed, and it re-sends (optionally waiting for a reply). The worker's
  `_do_send` helper is shared by `send` and `resend`.

## Switching projects (per-project view isolation)

Each pane holds its live view in single-project JS globals — output/log buffers,
the selected host, the broker event cursors (`netSince`/`pkCapSince`/`rcSince`),
and the poll timers. `onProjectSwitch` therefore calls `resetToolViews()` to drop
that transient state and stop the pollers before rebuilding each pane from the
newly-active project (`loadNetworkFor`/`loadPacketsFor`/`loadReconFor`). Without
it the previous project's hosts/output/log bled through — and a stale poller kept
firing against the new project — until a manual refresh or tab toggle. The
authoritative data (scan history + merged host inventory, captures, recon
workspace) reloads from the server; a scan or recon component still live in the
new project is re-attached (its event stream replays from seq 0 to rebuild the
log).

## The combination

A scan can tick "capture traffic": the Network tab starts a worker capture
filtered to the target (`lo` for localhost, else the default iface) while the
scan runs, saves it as a `source: scan` capture, and it opens in the Packets tab.

## Environment & privileges

Verified in this Codespace: `nmap` 7.94, scapy 2.7.0 in the venv, passwordless
`sudo`, and raw capture working on `lo`/`eth0`. Live capture, packet send, and
privileged scans therefore all function here. Where sudo/privileges are absent,
those controls disable with a one-line reason and **pcap open/analyze still
works** (it needs no root). `tshark` is optional (a richer dissection tier later).

## Security note (runs as root)

Privileged operations go through fixed, validated entrypoints (nmap argv; the
worker's sniff/send/replay with validated iface/filter/paths). **The scapy
console deliberately executes operator-supplied scapy Python as root** — it is a
console, not a sandbox. The suite is local and session-gated; keep it bound to
the operator's own host.

## Verification

- Unit (committed): `tests/test_nmap_runner.py` — command build, XML parse,
  `LiveHostStream`, `diff_scans`, CSV/gnmap export (pure stdlib, no nmap binary);
  `tests/test_packet_engine.py` — the display-filter grammar, the `build_packet`
  allowlist boundary, `follow_stream`, `statistics`, `export_subset` against a
  generated pcap (`pytest.importorskip` skips cleanly if scapy isn't importable;
  scapy is a runtime dependency of the module — `scapy>=2.5.0` in `pyproject.toml`).
- Integration (live server): `/nmap/*` scan → stream → history → result, plus
  `/nmap/{profiles,export}`; `/packets/*` upload → list → detail → stream → stats →
  export; `/scapy/*` console + sr1 + tls; live capture on `lo`; scan-linked capture.
- Crafter recipes (live, root worker): ping → ICMP echo-reply; TCP SYN to an open
  port → `SA`; to a closed port → `RA`; DNS nested build via the structured spec;
  traceroute reaches localhost; replay editor re-sends a captured packet with a
  `dport` override and gets a SYN-ACK. The verdict logic reads the exact reply
  fields these produce (`flags`, ICMP `type`, ARP `op`).
- No regressions: full `tests/test_suite.py` passes except the pre-existing
  `test_auth_gui_mounted_same_origin` (unrelated to this module).
