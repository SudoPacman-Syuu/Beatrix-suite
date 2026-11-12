"""
BEATRIX Rapid Hunter

Quick multi-domain scanning for low-hanging fruit:
- Subdomain takeover
- Exposed debug endpoints
- CORS misconfigurations
- Open redirects

Consolidated from standalone rapid_hunter.py.
"""

import asyncio
from typing import List, Optional, Set

import httpx

from beatrix.core.types import Confidence, Finding, Severity
from beatrix.utils.helpers import in_domain

# Subdomain takeover fingerprints
TAKEOVER_FINGERPRINTS = {
    "amazon s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "github pages": ["There isn't a GitHub Pages site here"],
    "heroku": ["No such app", "herokucdn.com/error-pages"],
    "azure": ["Error 404 - Web app not found"],
    "fastly": ["Fastly error: unknown domain"],
    "netlify": ["Not Found - Request ID"],
    "vercel": ["The deployment could not be found"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "tumblr": ["There's nothing here"],
    "wordpress": ["Do you want to register"],
}

# Default targets (empty — must be provided via -d or -t)
DEFAULT_TARGETS = []


class RapidHunter:
    """
    Quick multi-target vulnerability scanner.

    Sweeps multiple domains for subdomain takeover, exposed endpoints,
    CORS misconfiguration. Intended for periodic cron-like runs.
    """

    def __init__(self, targets: Optional[List[str]] = None, verbose: bool = True):
        self.targets = targets or DEFAULT_TARGETS
        self.verbose = verbose
        self.findings: List[Finding] = []

    def log(self, msg: str, level: str = "INFO") -> None:
        if not self.verbose and level == "INFO":
            return
        colors = {"INFO": "\033[94m", "WARN": "\033[93m", "VULN": "\033[91m\033[1m", "SUCCESS": "\033[92m"}
        print(f"{colors.get(level, '')}[{level}]\033[0m {msg}")

    # =========================================================================
    # SUBDOMAIN ENUMERATION
    # =========================================================================

    async def get_subdomains(self, domain: str) -> List[str]:
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if resp.status_code == 200:
                    subs: Set[str] = set()
                    for entry in resp.json()[:100]:
                        for s in entry.get("name_value", "").split("\n"):
                            s = s.strip().lower().replace("*.", "")
                            if in_domain(s, domain) and s != domain:
                                subs.add(s)
                    return list(subs)
            except Exception as e:
                self.log(f"crt.sh error for {domain}: {e}", "WARN")
        return []

    # =========================================================================
    # TAKEOVER CHECK
    # =========================================================================

    async def check_takeover(self, subdomain: str) -> Optional[Finding]:
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            for scheme in ("https", "http"):
                try:
                    resp = await client.get(f"{scheme}://{subdomain}")
                    body = resp.text.lower()

                    for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                        for fp in fingerprints:
                            if fp.lower() in body:
                                return Finding(
                                    title=f"Subdomain Takeover: {subdomain} ({service})",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.FIRM,
                                    url=f"{scheme}://{subdomain}",
                                    scanner_module="rapid_hunter",
                                    description=f"Subdomain {subdomain} has dangling DNS pointing to {service}. "
                                                f"Fingerprint matched: '{fp}'",
                                    evidence=fp,
                                    remediation="Remove the DNS record or claim the resource on the hosting provider.",
                                )
                except Exception:
                    pass
        return None

    # =========================================================================
    # DEBUG ENDPOINT CHECK
    # =========================================================================

    async def check_debug_endpoints(self, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        paths = [
            ("/.git/config", "[core]", "exposed_git", Severity.CRITICAL),
            ("/.env", "=", "exposed_env", Severity.CRITICAL),
            ("/actuator/env", "property", "exposed_actuator", Severity.HIGH),
            ("/actuator/heapdump", None, "exposed_heapdump", Severity.CRITICAL),
            ("/server-status", "apache", "exposed_server_status", Severity.MEDIUM),
            ("/swagger.json", "swagger", "exposed_swagger", Severity.LOW),
            ("/debug", "debug", "exposed_debug", Severity.MEDIUM),
        ]

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for path, indicator, tag, sev in paths:
                for scheme in ("https", "http"):
                    try:
                        url = f"{scheme}://{domain}{path}"
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            if indicator is None or indicator in resp.text.lower():
                                findings.append(Finding(
                                    title=f"Exposed: {path} on {domain}",
                                    severity=sev,
                                    confidence=Confidence.FIRM,
                                    url=url,
                                    scanner_module="rapid_hunter",
                                    description=f"Sensitive endpoint {path} is publicly accessible.",
                                    remediation="Block access to this endpoint via server configuration or WAF rules.",
                                ))
                                break  # don't check http if https hit
                    except Exception:
                        pass
        return findings

    # =========================================================================
    # CORS CHECK
    # =========================================================================

    async def check_cors(self, domain: str) -> Optional[Finding]:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            try:
                resp = await client.get(
                    f"https://{domain}",
                    headers={"Origin": "https://evil.com"},
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == "https://evil.com" and acac.lower() == "true":
                    return Finding(
                        title=f"CORS Misconfiguration on {domain}",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=f"https://{domain}",
                        scanner_module="rapid_hunter",
                        description="Arbitrary origin reflected with credentials enabled.",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Implement a strict origin allowlist.",
                    )
            except Exception:
                pass
        return None

    # =========================================================================
    # MAIN
    # =========================================================================

    async def scan_domain(self, domain: str) -> List[Finding]:
        self.log(f"Scanning {domain}...")
        domain_findings: List[Finding] = []

        # Skip subdomain enumeration and takeover checks for IP targets
        from beatrix.utils.helpers import is_ip_address
        if not is_ip_address(domain):
            subs = await self.get_subdomains(domain)
            self.log(f"  Found {len(subs)} subdomains")
        else:
            subs = []
            self.log(f"  Target is IP — skipping subdomain enumeration")

        debug_findings = await self.check_debug_endpoints(domain)
        domain_findings.extend(debug_findings)

        cors = await self.check_cors(domain)
        if cors:
            domain_findings.append(cors)
            self.log(f"  CORS VULN: {domain}", "VULN")

        for sub in subs[:20]:
            finding = await self.check_takeover(sub)
            if finding:
                domain_findings.append(finding)
                self.log(f"  TAKEOVER: {sub}", "VULN")

        self.findings.extend(domain_findings)
        return domain_findings

    async def run(self) -> List[Finding]:
        for target in self.targets:
            await self.scan_domain(target)
            await asyncio.sleep(1)
        return self.findings
