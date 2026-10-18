"""
BEATRIX — on-demand (manual) nuclei runner for the Suite's Nuclei module.

The automated engine (`beatrix.scanners.nuclei.NucleiScanner`) drives nuclei with
opinionated, tech-aware tag selection across scan phases. This module is the
*manual* counterpart: it runs nuclei with the **operator's own** flags (chosen
templates / tags / ids / severity) against an ad-hoc target, streams results, and
parses each JSONL hit into a Beatrix ``Finding`` — reusing the scanner's binary
resolution, template directories, and ``_parse_nuclei_finding`` so findings look
identical to the automated engine's (and dedupe in the same Issues store).

Nothing here auto-selects templates; the point is precise, hands-on control — the
"Repeater for nuclei" to the engine's automated scanner.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

_SCANNER = None
_ANSI = re.compile(r"\x1b\[[0-9;]*m")   # strip color codes from nuclei's stderr
_COUNT_CACHE: Dict[str, int] = {}       # dir path -> recursive .yaml count (session cache)


def _user_custom_dir() -> Path:
    """Writable custom-template dir for the MANUAL module. The engine's
    ``~/.beatrix/nuclei-templates`` can be root-owned (created by a privileged
    scan), so manual saves go to a dir this (unprivileged) process owns."""
    return Path.home() / ".beatrix" / "suite-nuclei-templates"


def _scanner():
    """Lazily build one NucleiScanner — cheap (resolves the binary + template
    dirs; runs no scan) — and reuse it for path/template/parse helpers."""
    global _SCANNER
    if _SCANNER is None:
        from beatrix.scanners.nuclei import NucleiScanner
        _SCANNER = NucleiScanner()
    return _SCANNER


def available() -> Dict[str, Any]:
    """Binary + template inventory, for the module's env/state view."""
    sc = _scanner()
    info: Dict[str, Any] = {"nuclei": bool(sc.available), "path": sc.nuclei_path or ""}
    if not sc.available:
        return info
    try:
        out = subprocess.run([sc.nuclei_path, "-version"], capture_output=True,
                             text=True, timeout=10)
        raw = _ANSI.sub("", (out.stdout or "") + "\n" + (out.stderr or ""))
        m = re.search(r"v?\d+\.\d+\.\d+", raw)
        info["version"] = m.group(0) if m else ""
    except Exception:  # noqa: BLE001
        info["version"] = ""
    dirs = _template_dirs()
    info["template_dirs"] = [{"label": lbl, "path": str(p)} for lbl, p in dirs]
    info["custom_dir"] = str(_user_custom_dir())
    return info


def _template_dirs() -> List[Tuple[str, Path]]:
    """(label, dir) for every template source nuclei will read."""
    sc = _scanner()
    out: List[Tuple[str, Path]] = []
    if sc._template_dir and sc._template_dir.exists():
        out.append(("community", sc._template_dir))
    ucd = _user_custom_dir()
    if ucd.exists():
        out.append(("custom", ucd))
    # The engine's custom dir (read-only here) if it exists and isn't the same.
    if sc._custom_template_dir and sc._custom_template_dir.exists() and sc._custom_template_dir.resolve() != ucd.resolve():
        out.append(("custom", sc._custom_template_dir))
    for d in getattr(sc, "_extra_template_dirs", []) or []:
        if d.exists():
            out.append(("external", d))
    return out


def _within(path: Path, roots: List[Path]) -> bool:
    """True if `path` resolves inside one of `roots` (path-traversal guard)."""
    try:
        rp = path.resolve()
    except Exception:  # noqa: BLE001
        return False
    for r in roots:
        try:
            rp.relative_to(r.resolve())
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


_ID_RE = re.compile(r"(?m)^id:\s*([^\n#]+)")
_NAME_RE = re.compile(r"(?m)^\s*name:\s*(.+)")
_SEV_RE = re.compile(r"(?m)^\s*severity:\s*([A-Za-z|]+)")
_TAGS_RE = re.compile(r"(?m)^\s*tags:\s*(.+)")


def _parse_template_header(path: Path) -> Dict[str, Any]:
    """Cheap header read of a template YAML (id / name / severity / tags) — reads
    only the first couple KB, no YAML parser, so a big catalog stays fast."""
    hdr: Dict[str, Any] = {"id": path.stem, "name": "", "severity": "", "tags": []}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(2048)
    except Exception:  # noqa: BLE001
        return hdr
    m = _ID_RE.search(head)
    if m:
        hdr["id"] = m.group(1).strip().strip("\"'")
    m = _NAME_RE.search(head)
    if m:
        hdr["name"] = m.group(1).strip().strip("\"'")
    m = _SEV_RE.search(head)
    if m:
        hdr["severity"] = m.group(1).strip().lower()
    m = _TAGS_RE.search(head)
    if m:
        hdr["tags"] = [t.strip().strip("\"'") for t in m.group(1).strip().strip("[]").split(",") if t.strip()]
    return hdr


def template_catalog(query: str = "", severity: str = "", limit: int = 200) -> Dict[str, Any]:
    """Browse the on-disk template set. `query` is a case-insensitive substring
    matched against the relative path, id, name, and tags; `severity` filters by
    the template's severity. Stops at `limit` matches so it stays snappy over a
    multi-thousand-file tree."""
    q = (query or "").strip().lower()
    sev = (severity or "").strip().lower()
    items: List[Dict[str, Any]] = []
    scanned = 0
    capped = False
    for label, root in _template_dirs():
        for path in root.glob("**/*.yaml"):
            scanned += 1
            rel = str(path.relative_to(root))
            if q and q not in rel.lower():
                hdr = _parse_template_header(path)
                hay = " ".join([rel, hdr.get("id", ""), hdr.get("name", ""),
                                " ".join(hdr.get("tags", []))]).lower()
                if q not in hay:
                    continue
            else:
                hdr = _parse_template_header(path)
            if sev and hdr.get("severity", "") != sev:
                continue
            items.append({"source": label, "rel": rel, "path": str(path),
                          "id": hdr["id"], "name": hdr["name"],
                          "severity": hdr["severity"], "tags": hdr["tags"]})
            if len(items) >= limit:
                capped = True
                break
        if capped:
            break
    items.sort(key=lambda it: (it["source"] != "custom", it["rel"]))
    return {"templates": items, "count": len(items), "capped": capped}


def _count_yaml(d: Path) -> int:
    """Recursive .yaml count under a dir, cached for the session (the repo
    doesn't change under us except custom saves, which clear the cache)."""
    key = str(d)
    if key in _COUNT_CACHE:
        return _COUNT_CACHE[key]
    try:
        n = sum(1 for _ in d.glob("**/*.yaml"))
    except Exception:  # noqa: BLE001
        n = 0
    _COUNT_CACHE[key] = n
    return n


def browse_tree(path: str = "") -> Dict[str, Any]:
    """One level of the template file tree, for the explorer's lazy-loaded tree.

    `path` empty → the source roots (community / custom / external). Otherwise a
    directory path (validated inside a template root) → its immediate subfolders
    (each with a recursive template count) and the templates directly in it. The
    folder structure itself is the repo's organization by protocol/exploit type
    (http, network, dns, ssl; cves, exposures, misconfiguration, takeovers, …)."""
    roots = _template_dirs()
    if not path:
        nodes = [{"name": lbl, "path": str(p), "count": _count_yaml(p),
                  "source": lbl, "dir": True} for lbl, p in roots]
        nodes = [n for n in nodes if n["count"] > 0]   # drop empty source roots
        return {"root": True, "dirs": nodes, "templates": []}
    d = Path(path)
    root_paths = [p for _, p in roots]
    if not _within(d, root_paths) or not d.is_dir():
        return {"dirs": [], "templates": [], "error": "folder not found"}
    src = ""
    for lbl, p in roots:
        try:
            d.resolve().relative_to(p.resolve())
            src = lbl
            break
        except Exception:  # noqa: BLE001
            continue
    dirs: List[Dict[str, Any]] = []
    templates: List[Dict[str, Any]] = []
    try:
        for child in sorted(d.iterdir(), key=lambda c: (not c.is_dir(), c.name.lower())):
            if child.is_dir():
                dirs.append({"name": child.name, "path": str(child),
                             "count": _count_yaml(child), "source": src, "dir": True})
            elif child.suffix in (".yaml", ".yml"):
                hdr = _parse_template_header(child)
                templates.append({"name": hdr["name"] or child.stem, "id": hdr["id"],
                                  "severity": hdr["severity"], "tags": hdr["tags"],
                                  "rel": child.name, "path": str(child), "source": src})
    except Exception as e:  # noqa: BLE001
        return {"dirs": [], "templates": [], "error": str(e)}
    return {"dirs": dirs, "templates": templates}


def read_template(path: str) -> Dict[str, Any]:
    """Return a template's YAML text for preview — only if it lives inside a
    known template directory (traversal-guarded)."""
    roots = [p for _, p in _template_dirs()]
    p = Path(path)
    if not _within(p, roots) or not p.is_file():
        return {"ok": False, "error": "template not found"}
    try:
        return {"ok": True, "path": str(p), "text": p.read_text(encoding="utf-8", errors="replace")}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def save_custom_template(name: str, text: str) -> Dict[str, Any]:
    """Write a custom template into the custom template dir (sanitized name)."""
    base = _SAFE_NAME.sub("-", (name or "custom").strip()) or "custom"
    if not base.endswith((".yaml", ".yml")):
        base += ".yaml"
    ucd = _user_custom_dir()
    ucd.mkdir(parents=True, exist_ok=True)
    dest = (ucd / base).resolve()
    if not _within(dest, [ucd]):
        return {"ok": False, "error": "invalid template name"}
    try:
        dest.write_text(text or "", encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    _COUNT_CACHE.clear()   # custom-dir counts changed
    return {"ok": True, "path": str(dest), "rel": base}


def build_command(targets: List[str], opts: Dict[str, Any]) -> Tuple[List[str], Optional[str]]:
    """Assemble the nuclei argv from operator options. Returns (argv, tmp_target_file).

    Options (all optional): severity, tags, ids (comma strings); templates (list of
    absolute paths from the catalog); custom (bool → include the custom dir);
    headers (list of "Name: value"); rate (int); timeout (int). No shell is used,
    so values are passed as literal argv items."""
    sc = _scanner()
    roots = [p for _, p in _template_dirs()]
    cmd: List[str] = [sc.nuclei_path, "-jsonl", "-silent", "-no-color",
                      "-disable-update-check", "-no-interactsh", "-include-rr",
                      "-timeout", str(int(opts.get("timeout") or 20)),
                      "-retries", "1",
                      "-rate-limit", str(int(opts.get("rate") or 150)),
                      "-stats", "-stats-interval", "5"]
    tmp_file: Optional[str] = None
    if len(targets) == 1:
        cmd += ["-u", targets[0]]
    else:
        fd, tmp_file = tempfile.mkstemp(prefix="nuclei-targets-", suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(targets) + "\n")
        cmd += ["-l", tmp_file]
    sev = (opts.get("severity") or "").strip()
    if sev:
        cmd += ["-severity", sev]
    tags = (opts.get("tags") or "").strip()
    if tags:
        cmd += ["-tags", tags]
    ids = (opts.get("ids") or "").strip()
    if ids:
        cmd += ["-id", ids]
    for tpl in (opts.get("templates") or []):
        p = Path(str(tpl))
        if _within(p, roots) and p.is_file():
            cmd += ["-t", str(p)]
    if opts.get("custom"):
        for lbl, d in _template_dirs():
            if lbl == "custom":
                cmd += ["-t", str(d)]
    for h in (opts.get("headers") or []):
        if isinstance(h, str) and h.strip():
            cmd += ["-H", h]
    return cmd, tmp_file


def run(target: str, opts: Dict[str, Any],
        on_line: Optional[Callable[[str], None]] = None,
        on_finding: Optional[Callable[[Any, Dict[str, Any]], None]] = None,
        stop_event: Optional[threading.Event] = None,
        timeout: Optional[float] = None) -> Dict[str, Any]:
    """Run nuclei once with operator flags, streaming stderr progress to `on_line`
    and each parsed Finding to `on_finding(finding, raw_json)`. Returns a summary."""
    sc = _scanner()
    if not sc.available:
        return {"ok": False, "error": "nuclei binary not found on PATH"}
    targets = [t for t in re.split(r"\s+", (target or "").strip()) if t]
    if not targets:
        return {"ok": False, "error": "no target given"}
    # Require some scoping so a manual run can't silently launch the entire
    # template set unless the operator really asked (empty selection + no
    # custom = everything; allow it, but it's an explicit choice).
    cmd, tmp_file = build_command(targets, opts)
    display = " ".join(cmd)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
    except Exception as e:  # noqa: BLE001
        if tmp_file:
            try: os.remove(tmp_file)
            except Exception: pass  # noqa: BLE001
        return {"ok": False, "error": f"could not launch nuclei: {e}", "command": display}
    if on_line:
        on_line("$ " + display)
    started = time.time()

    def _drain_err() -> None:
        try:
            for ln in proc.stderr:  # type: ignore[union-attr]
                s = _ANSI.sub("", ln).rstrip()
                if not s.strip():
                    continue
                if s.lstrip().startswith("{") and '"percent"' in s:   # nuclei -stats JSON → readable
                    try:
                        d = json.loads(s.strip())
                        s = ("progress %s%% · matched %s · requests %s · errors %s"
                             % (d.get("percent", "?"), d.get("matched", "0"),
                                d.get("requests", "?"), d.get("errors", "0")))
                    except Exception:  # noqa: BLE001
                        pass
                if on_line:
                    on_line(s)
        except Exception:  # noqa: BLE001
            pass

    terr = threading.Thread(target=_drain_err, daemon=True)
    terr.start()

    count = 0
    findings: List[Dict[str, Any]] = []
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            if stop_event is not None and stop_event.is_set():
                proc.terminate()
                break
            if timeout and (time.time() - started) > timeout:
                proc.terminate()
                if on_line:
                    on_line("[timed out]")
                break
            line = line.strip()
            if not line or line[0] != "{":
                continue
            try:
                data = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            finding = sc._parse_nuclei_finding(data)
            if finding is None:
                continue
            count += 1
            findings.append({"finding": finding, "raw": data})
            if on_finding:
                try:
                    on_finding(finding, data)
                except Exception:  # noqa: BLE001
                    pass
    finally:
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try: proc.kill()
            except Exception: pass  # noqa: BLE001
        if tmp_file:
            try: os.remove(tmp_file)
            except Exception: pass  # noqa: BLE001
    return {"ok": True, "count": count, "findings": findings, "command": display,
            "elapsed": round(time.time() - started, 1)}
