"""
Passive site-map builder.

Discovers a target's URLs/endpoints from *passive* sources — declared files
(robots.txt, sitemap.xml), the homepage's own links/comments, JavaScript endpoint
mining, and zero-touch OSINT (Wayback Machine, crt.sh) — without the aggressive
link-by-link BFS the active crawler performs. Every discovery is handed to an
``on_endpoint`` sink (the suite writes it into the HTTP-history / Site-map store),
so running a passive scan first builds the full Site map that the active scanner
can then seed from instead of re-crawling.

Reuses the existing passive primitives in ``beatrix.core.recon_helpers`` and the
JS-mining / crt.sh helpers on ``beatrix.recon.ReconRunner`` — this module only
orchestrates, dedupes, optionally liveness-probes, and streams progress.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

# Every source this module knows how to run, in display order. The caller enables
# any subset; presets (defined in the suite catalog) are just named subsets.
ALL_SOURCES = ["robots", "sitemap", "links", "js", "common", "wayback", "crtsh"]

# Sources that never touch the target (pure third-party OSINT).
ZERO_TOUCH = {"wayback", "crtsh"}

_HREF_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#>]+)["\']', re.IGNORECASE)
_EXT_RT = {
    "js": "script", "mjs": "script", "css": "stylesheet",
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image",
    "svg": "image", "webp": "image", "ico": "image",
    "woff": "font", "woff2": "font", "ttf": "font", "otf": "font", "eot": "font",
    "json": "xhr", "xml": "xhr",
    "html": "document", "htm": "document", "php": "document", "asp": "document",
    "aspx": "document", "jsp": "document",
}


def _mime_to_rt(mime: str) -> str:
    m = (mime or "").split(";", 1)[0].strip().lower()
    if not m:
        return ""
    if "html" in m:
        return "document"
    if "json" in m or ("xml" in m and "html" not in m):
        return "xhr"
    if "javascript" in m or "ecmascript" in m:
        return "script"
    if "css" in m:
        return "stylesheet"
    if m.startswith("image/"):
        return "image"
    if "font" in m:
        return "font"
    return "other"


def _rt_from_url(url: str) -> str:
    path = urlparse(url).path
    i = path.rfind(".")
    if i > 0 and "/" not in path[i:]:
        return _EXT_RT.get(path[i + 1:].lower(), "")
    return ""


class PassiveMapper:
    """Orchestrates the passive sources and feeds discoveries to ``on_endpoint``."""

    def __init__(
        self,
        target: str,
        *,
        sources: Optional[List[str]] = None,
        probe: bool = True,
        scope_only: bool = False,
        same_host_only: bool = False,
        max_urls: int = 3000,
        concurrency: int = 12,
        timeout: int = 15,
        emit: Optional[Callable[..., None]] = None,
        on_endpoint: Optional[Callable[[Dict[str, Any]], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
        scope_check: Optional[Callable[[str], bool]] = None,
    ):
        raw = (target or "").strip()
        if raw and not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        self.target = raw
        parsed = urlparse(raw)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else raw
        self.host = parsed.netloc or raw

        self.sources = [s for s in (sources or ALL_SOURCES) if s in ALL_SOURCES]
        self.probe = probe
        self.scope_only = scope_only
        self.same_host_only = same_host_only
        self.max_urls = max_urls
        self.concurrency = max(1, concurrency)
        self.timeout = timeout

        self._emit = emit or (lambda *a, **k: None)
        self._on_endpoint = on_endpoint or (lambda rec: None)
        self._should_stop = should_stop or (lambda: False)
        self._scope_check = scope_check or (lambda host: True)

        # url -> source key that first discovered it
        self._found: Dict[str, str] = {}
        self._hosts: Set[str] = set()
        self._by_source: Dict[str, int] = {}

    # ── helpers ───────────────────────────────────────────────────────────
    def log(self, text: str, kind: str = "info") -> None:
        self._emit(kind, text=text)

    def _add(self, url: str, source: str) -> bool:
        """Register a discovered URL (deduped, scope/host filtered). Returns True if new."""
        url = (url or "").strip()
        if not url or not url.startswith(("http://", "https://")):
            return False
        url = url.split("#", 1)[0]
        host = urlparse(url).netloc
        if not host:
            return False
        if self.same_host_only and host != self.host:
            return False
        if self.scope_only and not self._scope_check(host):
            return False
        if url in self._found:
            return False
        if len(self._found) >= self.max_urls:
            return False
        self._found[url] = source
        self._hosts.add(host)
        self._by_source[source] = self._by_source.get(source, 0) + 1
        return True

    def _session(self):
        import aiohttp
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency * 2)
        headers = {"User-Agent": "Mozilla/5.0 (BeatrixPassive)"}
        return aiohttp.ClientSession(connector=connector, headers=headers)

    # ── sources ───────────────────────────────────────────────────────────
    async def _run_robots(self, session) -> List[str]:
        """robots.txt → Disallow/Allow paths + declared sitemap URLs (returned)."""
        from beatrix.core.recon_helpers import parse_robots_txt
        sitemaps: List[str] = []
        try:
            robots = await parse_robots_txt(session, self.base_url, timeout=self.timeout)
        except Exception as e:  # noqa: BLE001
            self.log(f"robots.txt error: {e}", "scanner_error")
            return sitemaps
        n = 0
        for u in robots.get("paths", []):
            if self._add(u, "robots"):
                n += 1
        sitemaps = list(robots.get("sitemaps", []))
        inter = robots.get("interesting", [])
        self.log(f"robots.txt: {n} paths"
                 + (f", {len(robots.get('disallowed', []))} Disallow" if robots.get("disallowed") else "")
                 + (f" · interesting: {', '.join(inter[:8])}" if inter else ""))
        return sitemaps

    async def _run_sitemap(self, session, extra_sitemaps: Optional[List[str]] = None) -> None:
        from beatrix.core.recon_helpers import parse_sitemap
        candidates = list(extra_sitemaps or [])
        for p in ("/sitemap.xml", "/sitemap_index.xml"):
            u = self.base_url.rstrip("/") + p
            if u not in candidates:
                candidates.append(u)
        n = 0
        for sm in candidates[:8]:
            if self._should_stop():
                break
            try:
                urls = await parse_sitemap(session, sm, timeout=self.timeout, max_urls=self.max_urls)
            except Exception:
                continue
            for u in urls:
                if self._add(u, "sitemap"):
                    n += 1
        self.log(f"sitemap.xml: {n} URLs from {len(candidates[:8])} sitemap file(s)")

    async def _run_links(self, session) -> None:
        """Fetch the homepage and harvest its own links + comment URLs (no BFS)."""
        from beatrix.core.recon_helpers import extract_html_intel
        import aiohttp
        html = ""
        base = self.base_url
        try:
            async with session.get(self.target, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                   allow_redirects=True) as resp:
                base = str(resp.url)
                if resp.status == 200 and "html" in (resp.headers.get("content-type", "") or "").lower():
                    html = await resp.text(errors="replace")
        except Exception as e:  # noqa: BLE001
            self.log(f"homepage fetch failed: {e}", "scanner_error")
            return
        n = 0
        for m in _HREF_RE.findall(html):
            cand = m.strip()
            if cand.startswith(("mailto:", "javascript:", "tel:", "data:")):
                continue
            full = urljoin(base, cand)
            if self._add(full, "links"):
                n += 1
        try:
            intel = extract_html_intel(html, base)
            for u in intel.get("internal_urls", set()):
                if self._add(u, "links"):
                    n += 1
        except Exception:
            pass
        self.log(f"homepage links + comments: {n} URLs")

    async def _run_js(self) -> None:
        """Reuse ReconRunner's JS discovery + endpoint mining (httpx, self-contained)."""
        try:
            from beatrix.recon import ReconRunner
        except Exception:
            return
        rr = ReconRunner(self.host)
        try:
            js_files = await rr.find_js_files(self.target)
        except Exception as e:  # noqa: BLE001
            self.log(f"JS discovery error: {e}", "scanner_error")
            return
        for j in js_files:
            self._add(j, "js")
        eps: Set[str] = set()
        for j in list(js_files)[:20]:
            if self._should_stop():
                break
            try:
                eps |= await rr._mine_js_endpoints(j)
            except Exception:
                continue
        n = 0
        for ep in eps:
            ep = ep.strip()
            if not ep or ep.startswith(("data:", "javascript:")):
                continue
            full = ep if ep.startswith(("http://", "https://")) else urljoin(self.base_url, ep)
            if self._add(full, "js"):
                n += 1
        self.log(f"JS mining: {len(js_files)} script(s), {n} endpoint(s)")

    async def _run_common(self) -> None:
        """Well-known paths worth having in the map (reuses ReconRunner.COMMON_PATHS)."""
        try:
            from beatrix.recon import ReconRunner
        except Exception:
            return
        n = 0
        for p in getattr(ReconRunner, "COMMON_PATHS", []):
            if self._add(urljoin(self.base_url.rstrip("/") + "/", p.lstrip("/")), "common"):
                n += 1
        self.log(f"common paths: {n} candidate(s)")

    async def _run_wayback(self) -> None:
        from beatrix.core.recon_helpers import wayback_urls
        try:
            urls = await wayback_urls(self.host, timeout=max(self.timeout, 20), max_urls=self.max_urls)
        except Exception as e:  # noqa: BLE001
            self.log(f"Wayback error: {e}", "scanner_error")
            return
        n = 0
        for u in urls:
            if self._add(u, "wayback"):
                n += 1
        self.log(f"Wayback Machine: {n} archived URL(s)")

    async def _run_crtsh(self) -> None:
        try:
            from beatrix.recon import ReconRunner
        except Exception:
            return
        rr = ReconRunner(self.host)
        try:
            hosts = await rr._enum_crtsh()
        except Exception as e:  # noqa: BLE001
            self.log(f"crt.sh error: {e}", "scanner_error")
            return
        n = 0
        for h in hosts:
            if self._add(f"https://{h}/", "crtsh"):
                n += 1
        self.log(f"crt.sh: {len(hosts)} host(s), {n} new root(s)")

    # ── liveness probe ──────────────────────────────────────────────────
    async def _probe_one(self, session, sem, url: str) -> Dict[str, Any]:
        import aiohttp
        rec = {"url": url, "status": None, "mime": "", "length": 0}
        async with sem:
            if self._should_stop():
                return rec
            for method in ("head", "get"):
                try:
                    call = getattr(session, method)
                    async with call(url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                    allow_redirects=True) as resp:
                        rec["status"] = resp.status
                        rec["mime"] = (resp.headers.get("content-type", "") or "").split(";", 1)[0].strip()
                        try:
                            rec["length"] = int(resp.headers.get("content-length") or 0)
                        except (TypeError, ValueError):
                            rec["length"] = 0
                        if method == "get":
                            body = await resp.read()
                            if not rec["length"]:
                                rec["length"] = len(body)
                        # HEAD worked (not 405/501) → done
                        if method == "head" and resp.status not in (403, 405, 501):
                            return rec
                        if method == "get":
                            return rec
                except Exception:
                    continue
        return rec

    # ── run ───────────────────────────────────────────────────────────────
    async def run(self) -> Dict[str, Any]:
        started = time.time()
        self.log(f"Passive map → {self.host}  (sources: {', '.join(self.sources) or 'none'})", "phase")
        declared_sitemaps: List[str] = []

        session = None
        needs_session = any(s in ("robots", "sitemap", "links") for s in self.sources) or self.probe
        if needs_session:
            session = self._session()
        try:
            # Target-touch discovery (ordered so robots feeds sitemap).
            if "robots" in self.sources and not self._should_stop():
                declared_sitemaps = await self._run_robots(session)
            if "sitemap" in self.sources and not self._should_stop():
                await self._run_sitemap(session, declared_sitemaps)
            if "links" in self.sources and not self._should_stop():
                await self._run_links(session)
            if "js" in self.sources and not self._should_stop():
                await self._run_js()
            if "common" in self.sources and not self._should_stop():
                await self._run_common()
            # Zero-touch OSINT.
            if "wayback" in self.sources and not self._should_stop():
                await self._run_wayback()
            if "crtsh" in self.sources and not self._should_stop():
                await self._run_crtsh()

            urls = list(self._found.keys())
            self.log(f"Discovered {len(urls)} unique URL(s) across {len(self._hosts)} host(s)"
                     + (" — probing liveness…" if self.probe and urls else ""))

            # Liveness probe (optional) then emit every endpoint to the sink.
            probed: Dict[str, Dict[str, Any]] = {}
            if self.probe and urls and not self._should_stop():
                sem = asyncio.Semaphore(self.concurrency)
                done = 0
                for i in range(0, len(urls), 100):
                    if self._should_stop():
                        break
                    batch = urls[i:i + 100]
                    results = await asyncio.gather(
                        *[self._probe_one(session, sem, u) for u in batch],
                        return_exceptions=True)
                    for r in results:
                        if isinstance(r, dict):
                            probed[r["url"]] = r
                    done += len(batch)
                    self.log(f"probed {done}/{len(urls)}")

            emitted = 0
            now = time.time()
            for u in urls:
                src = self._found[u]
                pr = probed.get(u, {})
                p = urlparse(u)
                rt = _mime_to_rt(pr.get("mime", "")) or _rt_from_url(u)
                self._on_endpoint({
                    "method": "GET",
                    "url": u,
                    "host": p.netloc,
                    "path": p.path or "/",
                    "status": pr.get("status"),
                    "mime": pr.get("mime", ""),
                    "length": pr.get("length", 0),
                    "ts": now,
                    "resource_type": rt,
                    "source": "passive:" + src,
                })
                emitted += 1

            summary = {
                "discovered": len(urls),
                "emitted": emitted,
                "hosts": sorted(self._hosts),
                "by_source": dict(self._by_source),
                "probed": len(probed),
                "duration": round(time.time() - started, 1),
                "stopped": bool(self._should_stop()),
            }
            self.log(f"Passive map complete — {emitted} endpoint(s) → Site map "
                     f"({summary['duration']}s)"
                     + (" · stopped" if summary["stopped"] else ""), "phase")
            return summary
        finally:
            if session is not None:
                try:
                    await session.close()
                except Exception:
                    pass
