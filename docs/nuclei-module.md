# Nuclei module (manual, operator-controlled templated scanning)

A per-project GUI for running nuclei *by hand* — the "Repeater for nuclei" to the
automated engine's scanner. The engine (`beatrix.scanners.nuclei.NucleiScanner`)
drives nuclei with opinionated, tech-aware tag auto-selection across phases; this
module instead runs nuclei with the **operator's own** flags (templates / tags /
ids / severity) against an ad-hoc target, streams results, and shows the matched
request/response — while still landing findings in the shared Issues store.

## Engine — `beatrix/core/nuclei_runner.py`
Reuses `NucleiScanner` for binary resolution, template directories, and its
`_parse_nuclei_finding(dict) -> Finding` (so manual findings are identical to the
engine's and dedupe the same way). It adds only the on-demand pieces:
- `available()` — binary path/version + template dirs.
- `template_catalog(query, severity, limit=200)` — fast browse of the on-disk
  template set (community + custom + external), filtering by path/id/name/tag and
  severity, capped so a multi-thousand-file tree stays snappy (cheap header read,
  no YAML parser).
- `read_template(path)` — YAML preview, traversal-guarded to the template dirs.
- `save_custom_template(name, text)` — writes to a **writable** custom dir,
  `~/.beatrix/suite-nuclei-templates` (the engine's `~/.beatrix/nuclei-templates`
  can be **root-owned** from a privileged scan, so manual saves go elsewhere).
- `build_command(targets, opts)` — argv from operator flags (no shell); always
  `-jsonl -silent -no-color -disable-update-check -no-interactsh -include-rr
  -stats`. `-include-rr` carries the matched request/response for the detail view
  and "Send to Repeater". OOB is off by default (predictable; no external
  callbacks).
- `run(target, opts, on_line, on_finding, stop_event)` — streams stderr progress
  (nuclei's JSON `-stats` lines reformatted as readable progress; ANSI stripped)
  and each parsed Finding; returns a summary.

## Suite glue — `beatrix/cli/suite.py`
- `_NucleiStore` → `<project>/nuclei.json`: run history + each run's findings
  (serialized via `_nuclei_finding_dict`, which keeps template id, matched-at,
  tags, evidence, curl, and the request/response).
- `nuclei_brokers` / `nuclei_stops`; `start_nuclei_run` runs on a thread, streams
  log + `finding` events to the broker, appends to the store, and calls
  `issues.add_finding(pid, finding, "nuclei", "manual")` (deduped in the Issues
  store). `_run_nuclei`, `nuclei_events`, `stop_nuclei` mirror the recon pattern.
- Routes: GET `/nuclei/{env,catalog,template,state,result,events}`,
  POST `/nuclei/{run,stop,custom/save}`.

## UI (`pane-nuclei`, "Nuclei" tab)
- **Toolbar:** target (free-fire, authorized-only reminder) + tags + severity +
  template ids + "custom templates" toggle + Run/Stop; a selected-templates count
  with a clear link.
- **Scan sub-tab:** run history (left) + right sub-tabs **Findings** (severity-
  colored, sorted table → click a row for a detail panel: description, evidence,
  cURL, references, and **⇥ Send to Repeater**) and **Output** (live log).
- **Template browser sub-tab:** quick search (id/name/path/tag + severity) → results
  list → YAML preview; **＋ scan** adds a template to the run selection. A **⛶ Browse
  folders** button opens the **template explorer**.
- **Template explorer (modal):** for someone who doesn't know where to look. A lazy
  **folder tree** of the repo — whose structure already organizes templates by
  protocol/exploit type (http · network · dns · ssl; within http: cves ·
  exposed-panels · exposures · misconfiguration · takeovers · default-logins ·
  technologies · fuzzing …), with recursive counts per folder — plus a row of
  **curated category lenses** (Web/HTTP, Network, DNS, TLS/SSL, CVEs, Exposed panels,
  Default logins, Exposures/secrets, Misconfig, Takeovers, Auth/access,
  Payment/financial, Technologies, Fuzzing/DAST) that run a catalog search. Backed by
  `browse_tree(path)` (`/nuclei/tree`, one lazy level per expand, session-cached
  counts). Clicking a template previews its YAML; **＋** adds it to the shared scan
  selection.
- **Custom template sub-tab:** name + YAML editor + Save → appears in the browser
  as a `custom` template; tick "custom templates" on Scan to run it.

## Cross-module wiring
Findings flow into **Issues** (deduped). A finding's **⇥ Send to Repeater** opens a
Repeater tab with the matched request (`-include-rr`), or a synthesized GET to the
matched URL when nuclei didn't capture one.

## Verification
- Engine (live): catalog search; a real run against a local HTTP service parsed 10
  findings; custom-save writes + appears in the catalog; `build_command` includes
  the custom dir.
- Suite e2e (live HTTP, scanning a **separate** target to avoid self-scan
  contention): `/nuclei/run` → poll `/nuclei/events` (10 findings) → `done`,
  `/nuclei/state` + `/nuclei/result` populated, and **1 deduped Issue** landed.
- GUI (jsdom, real render fns): findings table (severity-sorted, colored, detail +
  Send-to-Repeater), run history, template browser (search → list → preview → add
  to selection → clear), sub-tab/rtab switching; nav tab + pane present in the
  served page; `node --check` + DOM-init eval clean.
- No regressions: `tests/test_suite.py` 146 pass / the pre-existing
  `test_auth_gui_mounted_same_origin`.

## Notes / limits
- Don't point it at the suite's own URL while watching it — scanning the server
  you're polling self-contends. Real targets are external.
- With no tags/ids/templates/custom and only a severity (or nothing), nuclei runs
  its whole template set — slow and noisy, but a deliberate operator choice.
