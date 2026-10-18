"""
BEATRIX Target Crawler

Crawls the target to build a proper attack surface before scanners run.
This is the FOUNDATION — without crawling, scanners only see a bare URL
with zero parameters, zero endpoints, zero forms. Useless.

What this does:
1. Fetch the target (following redirects, with proper User-Agent)
2. Extract all links from HTML
3. Extract form actions and parameters
4. Extract script src attributes (JS bundles)
5. Follow same-origin links (depth-limited)
6. Build a map of: URLs, parameters, forms, JS files, technologies
7. Feed everything into ScanContext for downstream scanners
8. Run registered passive scan checks on every fetched response
"""

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

logger = logging.getLogger("beatrix.scanners.crawler")

# Browser-like User-Agent — critical for SPAs that serve different content to bots
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass
class CrawlResult:
    """Everything discovered during crawling"""
    # The final resolved URL (after redirects)
    resolved_url: str = ""
    base_url: str = ""

    # Discovered URLs with their parameters
    urls: Set[str] = field(default_factory=set)
    urls_with_params: Set[str] = field(default_factory=set)  # URLs that have query params

    # Parameters discovered (param_name -> set of URLs where it appears)
    parameters: Dict[str, Set[str]] = field(default_factory=dict)

    # Forms discovered
    forms: List[Dict] = field(default_factory=list)

    # JavaScript files
    js_files: Set[str] = field(default_factory=set)

    # Technology fingerprints
    technologies: List[str] = field(default_factory=list)

    # Response data from the initial fetch
    initial_response_headers: Dict[str, str] = field(default_factory=dict)
    initial_response_body: str = ""
    initial_status_code: int = 0

    # Cookies set by the target
    cookies: Dict[str, str] = field(default_factory=dict)

    # Interesting paths (from link extraction)
    paths: Set[str] = field(default_factory=set)

    # Error responses — 4xx/5xx bodies captured for tech fingerprinting
    # and error_disclosure scanner targeting. List of {url, status, headers, body}.
    error_responses: List[Dict] = field(default_factory=list)

    # Soft-404 signature for dedup
    soft_404_hash: str = ""

    # Stats
    pages_crawled: int = 0
    total_links_found: int = 0


class TargetCrawler:
    """
    Crawls a target to build the attack surface.

    This is NOT a vulnerability scanner — it's the recon phase that
    feeds data INTO scanners. Without this, scanners see nothing.

    Supports async context manager protocol so it can be used via
    the generic engine.strike() / _run_scanner() path:
        async with crawler:
            async for finding in crawler.scan(ctx): ...
    """

    name: str = "crawl"

    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 50,
        timeout: int = 15,
        rate_limit: int = 10,
        follow_redirects: bool = True,
        scope: Optional[List[str]] = None,
    ):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.follow_redirects = follow_redirects
        self.semaphore = asyncio.Semaphore(rate_limit)
        self._visited: Set[str] = set()
        self._log_callback = None
        # Scope patterns — when set, the crawler follows links whose
        # hostname matches any pattern (supports leading wildcards like
        # *.example.com). When empty, only same-origin links are followed.
        self._scope: List[str] = scope or []
        # Hosts strictly OUT of scope — never followed/added, even same-origin.
        self._scope_deny: List[str] = []
        # When False, the crawler visits its frontier (seeds + the root's own
        # links) once but does NOT follow newly-discovered links (no BFS) — used
        # by the "seed from site map" path so the active scan reuses a pre-built map.
        self._expand: bool = True

        # Passive scan pipeline — when set, every fetched response is
        # passed through registered PassiveScanChecks in real time.
        self._scan_check_registry = None
        self._passive_findings: List = []

        # Debug/verbosity sink — the engine sets these (like it does on every
        # scanner) when a run is in debug mode, so every crawl request surfaces
        # a live ``http`` line. Off by default and fully guarded.
        self._debug: bool = False
        self._debug_emit = None

    def set_scan_check_registry(self, registry):
        """
        Attach a ScanCheckRegistry so passive checks run during crawling.

        Usage (in kill_chain.py or engine.py):
            from beatrix.core.scan_check_types import ScanCheckRegistry
            registry = ScanCheckRegistry()
            registry.register_passive(HeaderPassiveCheck())
            crawler.set_scan_check_registry(registry)
        """
        self._scan_check_registry = registry

    async def _run_passive_checks(
        self, url: str, status_code: int, headers: Dict[str, str], body: str
    ) -> None:
        """
        Run all registered passive scan checks against a fetched response.
        Findings are accumulated in self._passive_findings.
        """
        if not self._scan_check_registry:
            return

        checks = self._scan_check_registry.get_passive_checks()
        for rc in checks:
            try:
                findings = await rc.check.do_passive_check(
                    url=url,
                    status_code=status_code,
                    headers=headers,
                    body=body,
                )
                if findings:
                    self._passive_findings.extend(findings)
                    rc.findings_produced += len(findings)
            except Exception as e:
                rc.errors += 1
                logger.debug(
                    f"Passive check '{rc.name}' failed on {url}: "
                    f"{type(e).__name__}: {e}"
                )

    async def __aenter__(self):
        """Async context manager entry (no-op — crawler manages its own httpx client)."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        pass

    async def scan(self, context) -> 'AsyncIterator[Finding]':
        """
        Adapter so TargetCrawler works through the generic scanner path.

        Runs crawl() under the hood and yields INFO-level findings
        summarising the discovered attack surface, plus any findings
        from passive scan checks run during the crawl.
        """
        from beatrix.core.types import Confidence, Finding, Severity

        # Pass auth from context.extra so authenticated crawling works
        # even when invoked through the generic _run_scanner() path.
        auth = None
        if hasattr(context, 'extra') and isinstance(context.extra, dict):
            auth = context.extra.get("auth")

        # Reset passive findings for this scan
        self._passive_findings = []

        result = await self.crawl(context.url, auth=auth)
        if result.pages_crawled > 0:
            yield Finding(
                title=f"Crawl complete: {result.pages_crawled} pages, {len(result.urls)} URLs, {len(result.urls_with_params)} with params",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                url=result.resolved_url or context.url,
                description=(
                    f"Discovered {len(result.urls)} URLs, "
                    f"{len(result.urls_with_params)} with parameters, "
                    f"{len(result.js_files)} JS files, "
                    f"{len(result.forms)} forms, "
                    f"{len(result.technologies)} technologies."
                ),
                evidence={
                    "pages_crawled": result.pages_crawled,
                    "urls": len(result.urls),
                    "urls_with_params": len(result.urls_with_params),
                    "js_files": len(result.js_files),
                    "forms": len(result.forms),
                    "technologies": result.technologies,
                },
                scanner_module="crawl",
            )

        # Yield any findings from passive scan checks run during crawling
        for finding in self._passive_findings:
            yield finding

    def set_log_callback(self, callback):
        """Set a callback for progress logging"""
        self._log_callback = callback

    def log(self, message: str):
        if self._log_callback:
            self._log_callback(message)
        else:
            print(f"[crawler] {message}")

    async def _debug_response_hook(self, response):
        """httpx response event-hook: in debug mode, emit one ``http`` line per
        crawl request. Registered on the client so it covers EVERY fetch (initial
        page, followed links, soft-404 probe, tech enrichment) in one place."""
        if not (self._debug and self._debug_emit):
            return
        try:
            el = int(response.elapsed.total_seconds() * 1000)
        except Exception:
            el = 0
        try:
            self._debug_emit("http", {
                "scanner": "crawl",
                "method": response.request.method if response.request else "GET",
                "url": str(response.url),
                "status": response.status_code,
                "elapsed_ms": el,
            })
        except Exception:
            pass

    async def crawl(self, target: str, auth=None, seeds: Optional[List[str]] = None,
                    expand: bool = True) -> CrawlResult:
        """
        Crawl the target and build the attack surface.

        Args:
            target: URL or domain to crawl
            auth: Optional AuthCredentials — when provided, the crawler
                  sends auth headers/cookies on every request so it can
                  discover authenticated pages (dashboards, settings, APIs).
            seeds: Known URLs (e.g. from a pre-built site map) to drop straight
                  into the frontier so the scan reuses prior recon instead of
                  rediscovering from the root.
            expand: When False, visit the frontier once (root + seeds, for
                  tech/forms/params) but do NOT follow newly-found links — the
                  efficient "seed from site map" mode.

        Returns:
            CrawlResult with all discovered data
        """
        result = CrawlResult()
        self._visited = set()  # Reset for reuse safety
        self._expand = expand

        # Normalize target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        result.base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Site-map seeding: known URLs become part of the frontier up front, so
        # _crawl_links visits them directly (no BFS needed to rediscover them).
        response = None
        if seeds:
            for s in seeds:
                if isinstance(s, str) and s.startswith(("http://", "https://")):
                    result.urls.add(s)
                    _sp = urlparse(s)
                    result.paths.add(_sp.path)
                    if _sp.query:
                        result.urls_with_params.add(s)
            self.log(f"Seeded {len(result.urls)} URLs from site map (expand={expand})")

        # ── Build auth-aware headers and cookies ────────────────────────
        client_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        client_cookies = {}
        if auth:
            if hasattr(auth, 'merged_headers'):
                client_headers.update(auth.merged_headers())
            if hasattr(auth, 'cookies') and auth.cookies:
                client_cookies = dict(auth.cookies)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            verify=False,
            cookies=client_cookies,
            headers=client_headers,
            event_hooks={"response": [self._debug_response_hook]},
        ) as client:
            # Initial fetch
            self.log(f"Fetching {target}")
            try:
                response = await client.get(target)
                result.resolved_url = str(response.url)
                result.initial_status_code = response.status_code
                result.initial_response_headers = dict(response.headers)
                result.initial_response_body = response.text
                result.urls.add(result.resolved_url)

                # Update base URL to resolved URL (handle redirects)
                resolved_parsed = urlparse(result.resolved_url)
                result.base_url = f"{resolved_parsed.scheme}://{resolved_parsed.netloc}"

                # Extract cookies (handle CookieConflict from duplicate
                # names across domains, e.g. Cloudflare's __cf_bm)
                try:
                    for cookie_name, cookie_value in client.cookies.items():
                        result.cookies[cookie_name] = cookie_value
                except Exception:
                    # CookieConflict: iterate the raw jar instead
                    for cookie in client.cookies.jar:
                        result.cookies[cookie.name] = cookie.value

                # Fingerprint technologies
                self._fingerprint_tech(response, result)

                # Run passive scan checks on the initial response
                await self._run_passive_checks(
                    url=result.resolved_url or target,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text or "",
                )

                # Enrich with external tools (whatweb, webanalyze) — non-blocking
                try:
                    await self._enrich_tech_fingerprint(result.resolved_url or target, result)
                except Exception:
                    pass  # External tools are optional

                # Build soft-404 signature
                await self._build_soft_404(client, result)

            except Exception as e:
                self.log(f"Initial fetch failed: {type(e).__name__}: {e}")
                if not seeds:
                    return result

            # Parse the initial page
            if response is not None and response.status_code == 200 and "text/html" in response.headers.get("content-type", ""):
                self._extract_from_html(response.text, result.resolved_url, result)
                self.log(f"Extracted {len(result.urls)} URLs, {len(result.js_files)} JS files, {len(result.forms)} forms from initial page")

            # Crawl discovered same-origin links (depth-limited)
            await self._crawl_links(client, result, depth=1)

            result.pages_crawled = len(self._visited)
            result.total_links_found = len(result.urls)

        self.log(
            f"Crawl complete: {result.pages_crawled} pages, "
            f"{len(result.urls)} URLs, {len(result.urls_with_params)} with params, "
            f"{len(result.js_files)} JS files, {len(result.forms)} forms"
        )

        return result

    def _hostname_in_scope(self, hostname: str) -> bool:
        """Check if a hostname matches any scope pattern."""
        if not self._scope:
            return False
        for pattern in self._scope:
            if pattern.startswith("*."):
                # Wildcard: *.example.com matches sub.example.com
                suffix = pattern[1:]  # .example.com
                if hostname.endswith(suffix) or hostname == pattern[2:]:
                    return True
            elif hostname == pattern:
                return True
        return False

    def _hostname_in_deny(self, hostname: str) -> bool:
        """True if hostname matches any strict out-of-scope pattern (deny wins)."""
        for pattern in (self._scope_deny or []):
            if pattern.startswith("*."):
                if hostname.endswith(pattern[1:]) or hostname == pattern[2:]:
                    return True
            elif hostname == pattern:
                return True
        return False

    async def _crawl_links(self, client: httpx.AsyncClient, result: CrawlResult, depth: int):
        """Crawl same-origin and in-scope links up to max_depth"""
        if depth > self.max_depth:
            return

        base_parsed = urlparse(result.base_url)

        # Get URLs to crawl (same origin OR in-scope, not yet visited)
        to_crawl = []
        for url in list(result.urls):
            if url in self._visited:
                continue
            parsed = urlparse(url)
            # Allow same-origin links unconditionally
            is_same_origin = parsed.netloc == base_parsed.netloc
            # Allow in-scope subdomains if scope patterns are set
            is_in_scope = self._hostname_in_scope(parsed.hostname or "")
            if self._hostname_in_deny(parsed.hostname or ""):   # strict out-of-scope wins
                continue
            if not is_same_origin and not is_in_scope:
                continue
            # Skip non-HTML resources
            if any(url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map']):
                continue
            to_crawl.append(url)

        if not to_crawl:
            return

        # Limit pages to crawl
        to_crawl = to_crawl[:self.max_pages - len(self._visited)]

        if to_crawl:
            self.log(f"Crawling {len(to_crawl)} pages (depth {depth})")

        for url in to_crawl:
            if len(self._visited) >= self.max_pages:
                break

            self._visited.add(url)

            try:
                async with self.semaphore:
                    resp = await client.get(url)

                # Capture 4xx/5xx error responses for tech fingerprinting
                if resp.status_code >= 400 and len(result.error_responses) < 50:
                    result.error_responses.append({
                        "url": str(resp.url),
                        "status": resp.status_code,
                        "headers": dict(resp.headers),
                        "body": (resp.text or "")[:5000],
                    })

                if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                    # Check for soft-404
                    body_hash = hashlib.md5(resp.text[:2000].encode()).hexdigest()
                    if body_hash == result.soft_404_hash:
                        continue

                    self._extract_from_html(resp.text, str(resp.url), result)

                    # Run passive scan checks on each crawled page
                    await self._run_passive_checks(
                        url=str(resp.url),
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                        body=resp.text or "",
                    )

            except Exception:
                continue

        # Recurse for newly discovered links (skipped in seed-only / no-expand mode)
        if self._expand and depth < self.max_depth and len(self._visited) < self.max_pages:
            await self._crawl_links(client, result, depth + 1)

    def _extract_from_html(self, html: str, page_url: str, result: CrawlResult):
        """Extract URLs, forms, and JS files from HTML"""
        base_parsed = urlparse(result.base_url)

        # Extract links from <a href="...">
        for match in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.IGNORECASE):
            href = match.group(1)
            if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("tel:"):
                continue
            full_url = urljoin(page_url, href)
            parsed = urlparse(full_url)

            # Track same-origin URLs unconditionally + in-scope subdomain URLs
            is_same_origin = parsed.netloc == base_parsed.netloc
            is_in_scope = self._hostname_in_scope(parsed.hostname or "")
            if (is_same_origin or is_in_scope) and not self._hostname_in_deny(parsed.hostname or ""):
                result.urls.add(full_url)
                result.paths.add(parsed.path)

                # Track URLs with parameters
                if parsed.query:
                    result.urls_with_params.add(full_url)
                    for param_name in parse_qs(parsed.query).keys():
                        if param_name not in result.parameters:
                            result.parameters[param_name] = set()
                        result.parameters[param_name].add(full_url)

        # Extract script src
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1)
            full_url = urljoin(page_url, src)
            if full_url.endswith(('.js', '.mjs')) or '.js?' in full_url:
                result.js_files.add(full_url)

        # Extract inline script references to JS files
        for match in re.finditer(r'["\']((?:https?://[^"\']+|/[^"\']+)\.(?:js|mjs)(?:\?[^"\']*)?)["\']', html):
            src = match.group(1)
            if src.startswith('/'):
                src = urljoin(page_url, src)
            if src.startswith('http'):
                result.js_files.add(src)

        # Extract forms
        for form_match in re.finditer(
            r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE
        ):
            form_html = form_match.group(0)
            form_data = self._parse_form(form_html, page_url)
            if form_data:
                result.forms.append(form_data)
                # Track form parameters
                for param in form_data.get("params", []):
                    if param["name"] not in result.parameters:
                        result.parameters[param["name"]] = set()
                    result.parameters[param["name"]].add(form_data.get("action", page_url))

        # Extract links from common JS patterns (React Router, Angular, etc.)
        for match in re.finditer(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', html):
            path = match.group(1)
            if len(path) > 1 and not path.endswith(('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico')):
                if re.match(r'^/[a-z]', path):  # Starts with lowercase letter after /
                    result.paths.add(path)

    def _parse_form(self, form_html: str, page_url: str) -> Optional[Dict]:
        """Parse a form element for action, method, and parameters"""
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)

        action = urljoin(page_url, action_match.group(1)) if action_match else page_url
        method = method_match.group(1).upper() if method_match else "GET"

        params = []
        for input_match in re.finditer(
            r'<(?:input|textarea|select)[^>]+name=["\']([^"\']+)["\']([^>]*)',
            form_html, re.IGNORECASE
        ):
            name = input_match.group(1)
            attrs = input_match.group(2)

            input_type = "text"
            type_match = re.search(r'type=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if type_match:
                input_type = type_match.group(1)

            value = ""
            value_match = re.search(r'value=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            if value_match:
                value = value_match.group(1)

            params.append({
                "name": name,
                "type": input_type,
                "value": value,
            })

        if params:
            return {
                "action": action,
                "method": method,
                "params": params,
            }
        return None

    def _fingerprint_tech(self, response: httpx.Response, result: CrawlResult):
        """Fingerprint technologies from response"""
        headers = response.headers
        body = response.text[:10000] if response.text else ""

        # Header-based — preserve full version strings
        if "x-powered-by" in headers:
            result.technologies.append(headers["x-powered-by"].strip())

        server_raw = headers.get("server", "").strip()
        if server_raw:
            # Append the raw Server value (e.g. "nginx/1.20.1", "Apache/2.4.52 (Ubuntu)")
            # so that version info is preserved through the pipeline.
            result.technologies.append(server_raw)

        if "x-aspnet-version" in headers:
            result.technologies.append(f"ASP.NET {headers['x-aspnet-version']}")

        # Body-based fingerprinting
        if "__NEXT_DATA__" in body:
            result.technologies.append("Next.js")
        if "react" in body.lower() or "_reactRootContainer" in body:
            result.technologies.append("React")
        if "ng-app" in body or "ng-controller" in body:
            result.technologies.append("Angular")
        if "vue" in body.lower() and "__vue__" in body:
            result.technologies.append("Vue.js")
        if "wp-content" in body:
            result.technologies.append("WordPress")
        if "drupal" in body.lower():
            result.technologies.append("Drupal")
        if "laravel" in body.lower() or "csrf-token" in body:
            result.technologies.append("Laravel")

        # Cookie-based
        cookies_str = headers.get("set-cookie", "").lower()
        if "aspnet" in cookies_str or "asp.net" in cookies_str:
            result.technologies.append("ASP.NET")
        if "phpsessid" in cookies_str:
            result.technologies.append("PHP")
        if "jsessionid" in cookies_str:
            result.technologies.append("Java")

        # Deduplicate
        result.technologies = list(set(result.technologies))

    async def _enrich_tech_fingerprint(self, url: str, result: 'CrawlResult'):
        """
        Enrich technology fingerprints using external tools (whatweb, webanalyze).
        Called after the initial crawl to add deeper fingerprinting.
        """
        try:
            from beatrix.core.external_tools import WhatwebRunner, WebanalyzeRunner

            existing = set(result.technologies)

            # WhatWeb — 1800+ plugin fingerprinting
            whatweb = WhatwebRunner()
            if whatweb.available:
                try:
                    techs = await whatweb.fingerprint(url)
                    for name, version in techs.items():
                        entry = f"{name} {version}".strip() if version else name
                        if entry not in existing:
                            result.technologies.append(entry)
                            existing.add(entry)
                except Exception:
                    pass

            # Webanalyze — Wappalyzer fingerprint database
            webanalyze = WebanalyzeRunner()
            if webanalyze.available:
                try:
                    techs = await webanalyze.fingerprint(url)
                    for name, version in techs.items():
                        entry = f"{name} {version}".strip() if version else name
                        if entry not in existing:
                            result.technologies.append(entry)
                            existing.add(entry)
                except Exception:
                    pass

        except ImportError:
            pass  # external_tools module not available

    async def _build_soft_404(self, client: httpx.AsyncClient, result: CrawlResult):
        """Build a soft-404 signature to filter out false endpoint discoveries"""
        try:
            canary = f"{result.base_url}/beatrix-nonexistent-{hashlib.md5(b'canary').hexdigest()[:8]}"
            resp = await client.get(canary)
            if resp.status_code == 200:
                result.soft_404_hash = hashlib.md5(resp.text[:2000].encode()).hexdigest()
        except Exception:
            pass
