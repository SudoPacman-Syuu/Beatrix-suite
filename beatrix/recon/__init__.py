"""
BEATRIX Recon Module

Consolidated from standalone recon.py into the framework.
Provides async subdomain enumeration, tech detection, JS analysis,
endpoint discovery, and parameter mining.

Can be used via CLI: beatrix recon target.com
Or programmatically: recon = ReconRunner(domain); await recon.run()

NOTE: The kill chain's _handle_recon now supersedes ReconRunner for
full scans.  ReconRunner is preserved for standalone CLI recon and
as a fallback for environments without the full engine.
"""

import asyncio
import json  # noqa: F401
import re
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set  # noqa: F401
from urllib.parse import urljoin, urlparse

import httpx

from beatrix.core.types import Confidence, Finding, Severity
from beatrix.utils.helpers import in_domain


@dataclass
class ReconResult:
    """Reconnaissance results"""
    domain: str
    subdomains: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    form_urls: Set[str] = field(default_factory=set)
    js_files: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    technologies: Dict[str, str] = field(default_factory=dict)
    interesting_findings: List[str] = field(default_factory=list)
    alive_subdomains: Set[str] = field(default_factory=set)
    accessible_endpoints: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict"""
        return {
            "domain": self.domain,
            "subdomains": sorted(self.subdomains),
            "endpoints": sorted(self.endpoints),
            "form_urls": sorted(self.form_urls),
            "js_files": sorted(self.js_files),
            "parameters": sorted(self.parameters),
            "technologies": self.technologies,
            "interesting_findings": self.interesting_findings,
            "alive_subdomains": sorted(self.alive_subdomains),
            "accessible_endpoints": self.accessible_endpoints,
            "timestamp": datetime.now().isoformat(),
        }


class ReconRunner:
    """
    Async reconnaissance runner.

    Consolidates subdomain enumeration, tech detection, JS analysis,
    endpoint discovery, and parameter mining.
    """

    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain.lower().strip()
        if self.domain.startswith("http"):
            self.domain = urlparse(self.domain).netloc
        self.domain = self.domain.replace("www.", "")
        self.verbose = verbose
        self.result = ReconResult(domain=self.domain)

        # Detect IP targets — skip domain-only operations (subdomain enum, crt.sh)
        from beatrix.utils.helpers import is_ip_address
        self.is_ip = is_ip_address(self.domain)

    def log(self, msg: str, level: str = "INFO") -> None:
        if level == "INFO" and not self.verbose:
            return
        colors = {"INFO": "\033[94m", "WARN": "\033[93m", "SUCCESS": "\033[92m", "FOUND": "\033[95m"}
        reset = "\033[0m"
        print(f"{colors.get(level, '')}{msg}{reset}")

    # =========================================================================
    # SUBDOMAIN ENUMERATION
    # =========================================================================

    async def _enum_crtsh(self) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"https://crt.sh/?q=%.{self.domain}&output=json")
                if resp.status_code == 200:
                    for entry in resp.json():
                        for sub in entry.get("name_value", "").split("\n"):
                            sub = sub.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if in_domain(sub, self.domain):
                                subdomains.add(sub)
        except Exception as e:
            self.log(f"crt.sh error: {e}", "WARN")
        return subdomains

    async def _enum_hackertarget(self) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}")
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.split("\n"):
                        if "," in line:
                            sub = line.split(",")[0].strip().lower()
                            if in_domain(sub, self.domain):
                                subdomains.add(sub)
        except Exception as e:
            self.log(f"HackerTarget error: {e}", "WARN")
        return subdomains

    async def enumerate_subdomains(self) -> Set[str]:
        # IP targets have no subdomains — skip all enumeration
        if self.is_ip:
            self.log("Target is an IP address — skipping subdomain enumeration", "INFO")
            self.result.subdomains.add(self.domain)
            return self.result.subdomains

        results = await asyncio.gather(
            self._enum_crtsh(),
            self._enum_hackertarget(),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, set):
                self.result.subdomains.update(r)
        self.result.subdomains.add(self.domain)
        self.result.subdomains.add(f"www.{self.domain}")

        # ── External tools: subfinder + amass ─────────────────────────────
        try:
            from beatrix.core.subfinder import SubfinderRunner
            subfinder = SubfinderRunner()
            if subfinder.available:
                subs = await subfinder.enumerate(self.domain)
                self.result.subdomains.update(subs)
                self.log(f"Subfinder found {len(subs)} subdomains", "SUCCESS")
        except Exception:
            pass

        try:
            from beatrix.core.external_tools import AmassRunner
            amass = AmassRunner()
            if amass.available:
                subs = await amass.enumerate(self.domain, passive=True)
                self.result.subdomains.update(subs)
                self.log(f"Amass found {len(subs)} subdomains", "SUCCESS")
        except Exception:
            pass

        self.log(f"Total unique subdomains: {len(self.result.subdomains)}", "SUCCESS")
        return self.result.subdomains

    # =========================================================================
    # TECH DETECTION
    # =========================================================================

    async def detect_technologies(self, url: str) -> Dict[str, str]:
        techs: Dict[str, str] = {}
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
                headers = resp.headers
                content = resp.text.lower()

                if "server" in headers:
                    techs["Server"] = headers["server"]
                if "x-powered-by" in headers:
                    techs["Powered-By"] = headers["x-powered-by"]

                framework_headers = {
                    "x-aspnet-version": "ASP.NET", "x-aspnetmvc-version": "ASP.NET MVC",
                    "x-drupal-cache": "Drupal", "x-generator": "Generator",
                    "x-shopify-stage": "Shopify", "x-wix-request-id": "Wix",
                }
                for h, tech in framework_headers.items():
                    if h in headers:
                        techs[tech] = headers[h]

                content_patterns = {
                    "wp-content": "WordPress", "drupal.js": "Drupal",
                    "joomla": "Joomla", "laravel": "Laravel",
                    "django": "Django", "flask": "Flask",
                    "next.js": "Next.js", "nuxt": "Nuxt.js",
                    "react": "React", "angular": "Angular",
                    "vue": "Vue.js", "jquery": "jQuery",
                    "graphql": "GraphQL", "cloudflare": "Cloudflare",
                }
                for pat, tech in content_patterns.items():
                    if pat in content:
                        techs[tech] = "Detected"

                gen = re.search(r'<meta[^>]+generator[^>]+content=["\']([^"\']+)', content)
                if gen:
                    techs["Generator"] = gen.group(1)
        except Exception as e:
            self.log(f"Tech detection error: {e}", "WARN")

        self.result.technologies = techs
        return techs

    # =========================================================================
    # JS ANALYSIS
    # =========================================================================

    async def find_js_files(self, url: str) -> Set[str]:
        js_files: Set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
                for match in re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp.text, re.I):
                    if match.startswith("//"):
                        match = "https:" + match
                    elif match.startswith("/"):
                        match = urljoin(url, match)
                    elif not match.startswith("http"):
                        match = urljoin(url, match)
                    js_files.add(match)

                # Check inline for secrets patterns
                for pat in [r'api[_\-]?key\s*[:=]\s*["\']', r'api[_\-]?secret\s*[:=]\s*["\']',
                            r'token\s*[:=]\s*["\']', r'/api/v\d+/\w+', r'graphql']:
                    if re.search(pat, resp.text, re.I):
                        self.result.interesting_findings.append(f"Potential sensitive pattern: {pat}")
        except Exception as e:
            self.log(f"JS enum error: {e}", "WARN")

        self.result.js_files = js_files
        return js_files

    async def _mine_js_endpoints(self, js_url: str) -> Set[str]:
        endpoints: Set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(js_url)
                content = resp.text
                patterns = [
                    r'["\']/(api|v\d)/[^"\']+["\']',
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                    r'url:\s*["\']([^"\']+)["\']',
                    r'endpoint:\s*["\']([^"\']+)["\']',
                ]
                for pat in patterns:
                    for m in re.findall(pat, content, re.I):
                        ep = m if isinstance(m, str) else m[0]
                        ep = ep.strip("\"'")
                        if ep and not ep.startswith("data:"):
                            endpoints.add(ep)

                for m in re.findall(r'[?&]([a-zA-Z_]\w{1,28})=', content):
                    self.result.parameters.add(m)
                for m in re.findall(r'"([a-zA-Z_]\w{1,28})"\s*:', content):
                    self.result.parameters.add(m)
        except Exception:
            pass
        return endpoints

    async def analyze_js_files(self) -> Set[str]:
        tasks = [self._mine_js_endpoints(js) for js in list(self.result.js_files)[:20]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, set):
                self.result.endpoints.update(r)
        return self.result.endpoints

    # =========================================================================
    # ENDPOINT PROBING
    # =========================================================================

    COMMON_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphiql", "/playground",
        "/swagger", "/swagger-ui", "/swagger.json",
        "/openapi.json", "/api-docs", "/docs",
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/.git", "/.git/config", "/.env",
        "/config.json", "/config.yml", "/web.config",
        "/server-status", "/server-info",
        "/debug", "/actuator", "/actuator/health", "/actuator/env",
        "/metrics", "/health", "/status",
        "/robots.txt", "/sitemap.xml",
        "/.well-known/security.txt", "/.well-known/openid-configuration",
    ]

    async def check_common_endpoints(self, base_url: str) -> List[str]:
        found = []
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False) as client:
            for path in self.COMMON_PATHS:
                try:
                    url = f"{base_url.rstrip('/')}{path}"
                    resp = await client.get(url)
                    if resp.status_code in (200, 301, 302, 401, 403):
                        found.append(f"{path} ({resp.status_code})")
                        content = resp.text.lower()
                        if resp.status_code == 200:
                            if any(x in content for x in ["password", "secret", "api_key", "token"]):
                                self.result.interesting_findings.append(f"SENSITIVE: {path} may contain secrets")
                            if "swagger" in content or "openapi" in content:
                                self.result.interesting_findings.append(f"API DOCS: {path}")
                            if ".git" in path:
                                self.result.interesting_findings.append(f"GIT EXPOSED: {path}")
                        if resp.status_code in (401, 403):
                            self.result.interesting_findings.append(f"PROTECTED: {path} exists but requires auth")
                except Exception:
                    pass
        self.result.accessible_endpoints = found
        return found

    # =========================================================================
    # SUBDOMAIN LIVENESS
    # =========================================================================

    async def _check_alive(self, subdomain: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                for scheme in ("https", "http"):
                    try:
                        await client.get(f"{scheme}://{subdomain}")
                        return True
                    except Exception:
                        continue
        except Exception:
            pass
        return False

    # =========================================================================
    # MAIN RUNNER
    # =========================================================================

    async def run(self, deep: bool = False) -> ReconResult:
        """Run full reconnaissance pipeline.

        .. deprecated::
            The kill chain's ``_handle_recon`` now provides a superset of
            this pipeline with MITRE ATT&CK TA0043 coverage.  Use
            ``KillChainExecutor.execute()`` for full scans.  This method
            is retained for standalone ``beatrix recon`` CLI usage and
            lightweight quick-recon scenarios.
        """
        warnings.warn(
            "ReconRunner.run() is deprecated for full scans. "
            "Use KillChainExecutor.execute() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        base_url = f"https://{self.domain}"

        await self.enumerate_subdomains()
        await self.detect_technologies(base_url)
        await self.find_js_files(base_url)
        await self.analyze_js_files()
        await self.check_common_endpoints(base_url)

        # ── External tools: gau, katana, gospider, hakrawler ──────────────
        try:
            from beatrix.core.external_tools import ExternalToolkit
            toolkit = ExternalToolkit()

            # GAU — historical URL discovery
            if toolkit.gau.available:
                try:
                    gau_urls = await toolkit.gau.fetch_urls(self.domain, subs=True)
                    for u in gau_urls:
                        self.result.endpoints.add(u)
                    self.log(f"GAU found {len(gau_urls)} historical URLs", "SUCCESS")
                except Exception:
                    pass

            # Katana — JS endpoint extraction
            if toolkit.katana.available:
                try:
                    katana_result = await toolkit.katana.crawl(base_url, depth=2)
                    for u in katana_result.get("urls", []):
                        self.result.endpoints.add(u)
                    for js in katana_result.get("js_urls", []):
                        self.result.js_files.add(js)
                    for fu in katana_result.get("form_urls", []):
                        self.result.endpoints.add(fu)
                        self.result.form_urls.add(fu)
                    self.log(f"Katana found {len(katana_result.get('urls', []))} URLs, {len(katana_result.get('js_urls', []))} JS, {len(katana_result.get('form_urls', []))} forms", "SUCCESS")
                except Exception:
                    pass

            # Gospider — web spidering
            if toolkit.gospider.available:
                try:
                    spider_result = await toolkit.gospider.spider(base_url, depth=2)
                    for u in spider_result.get("urls", []):
                        self.result.endpoints.add(u)
                    for sub in spider_result.get("subdomains", []):
                        self.result.subdomains.add(sub)
                    for js in spider_result.get("js_files", []):
                        self.result.js_files.add(js)
                    for fu in spider_result.get("forms", []):
                        self.result.endpoints.add(fu)
                        self.result.form_urls.add(fu)
                    self.log(f"Gospider found {len(spider_result.get('urls', []))} URLs, {len(spider_result.get('js_files', []))} JS, {len(spider_result.get('forms', []))} forms", "SUCCESS")
                except Exception:
                    pass

            # Hakrawler — endpoint crawler
            if toolkit.hakrawler.available:
                try:
                    hak_urls = await toolkit.hakrawler.crawl(base_url, depth=2)
                    for u in hak_urls:
                        self.result.endpoints.add(u)
                    self.log(f"Hakrawler found {len(hak_urls)} URLs", "SUCCESS")
                except Exception:
                    pass

            # WhatWeb + Webanalyze — deeper tech fingerprinting
            if toolkit.whatweb.available:
                try:
                    techs = await toolkit.whatweb.fingerprint(base_url)
                    for name, version in techs.items():
                        self.result.technologies[name] = version
                    self.log(f"WhatWeb identified {len(techs)} technologies", "SUCCESS")
                except Exception:
                    pass

            if toolkit.webanalyze.available:
                try:
                    techs = await toolkit.webanalyze.fingerprint(base_url)
                    for name, version in techs.items():
                        self.result.technologies[name] = version
                    self.log(f"Webanalyze identified {len(techs)} technologies", "SUCCESS")
                except Exception:
                    pass

            # Dirsearch — directory brute-force (adaptive extensions)
            if deep and toolkit.dirsearch.available:
                try:
                    techs_lower = " ".join(k.lower() for k in self.result.technologies)
                    ext_parts = ["html", "js", "json", "txt", "xml", "env", "bak", "old"]
                    if any(t in techs_lower for t in ("php", "wordpress", "drupal", "joomla", "laravel")):
                        ext_parts.extend(["php", "phtml", "inc"])
                    if any(t in techs_lower for t in ("asp", ".net", "iis")):
                        ext_parts.extend(["asp", "aspx", "ashx", "config"])
                    if any(t in techs_lower for t in ("java", "spring", "tomcat")):
                        ext_parts.extend(["jsp", "jspa", "do", "action"])
                    if any(t in techs_lower for t in ("python", "django", "flask")):
                        ext_parts.extend(["py", "pyc"])
                    extensions = ",".join(sorted(set(ext_parts)))
                    ds_result = await toolkit.dirsearch.scan(base_url, extensions=extensions)
                    for entry in ds_result.get("found", []):
                        path = entry.get("path", "")
                        status = entry.get("status", 0)
                        if path:
                            full = f"{base_url.rstrip('/')}{path}"
                            self.result.endpoints.add(full)
                            # Flag sensitive discoveries
                            path_lower = path.lower()
                            if any(s in path_lower for s in (".env", ".git", ".bak", "backup", ".sql", "wp-config")):
                                self.result.interesting_findings.append(f"SENSITIVE: {path} (HTTP {status})")
                            elif any(s in path_lower for s in ("admin", "dashboard", "panel", "phpmyadmin")):
                                self.result.interesting_findings.append(f"ADMIN PANEL: {path} (HTTP {status})")
                    self.log(f"Dirsearch found {ds_result.get('total_found', 0)} paths (extensions: {extensions})", "SUCCESS")
                except Exception:
                    pass

        except ImportError:
            pass  # external_tools not available

        if deep and len(self.result.subdomains) <= 50:
            subs_list = sorted(self.result.subdomains)
            tasks = [self._check_alive(sub) for sub in subs_list]
            results = await asyncio.gather(*tasks)
            for sub, alive in zip(subs_list, results):
                if alive:
                    self.result.alive_subdomains.add(sub)

        # Convert interesting findings to proper Findings
        for note in self.result.interesting_findings:
            severity = Severity.INFO
            if note.startswith("SENSITIVE") or note.startswith("GIT EXPOSED"):
                severity = Severity.HIGH
            elif note.startswith("API DOCS"):
                severity = Severity.MEDIUM
            self.result.findings.append(Finding(
                title=note,
                severity=severity,
                confidence=Confidence.TENTATIVE,
                url=base_url,
                scanner_module="recon",
            ))

        return self.result
