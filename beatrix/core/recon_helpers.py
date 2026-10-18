"""
Recon helper functions for Phase 1 reconnaissance.

MITRE ATT&CK TA0043 coverage:
  T1594  Search Victim-Owned Websites  — robots.txt, sitemap.xml, HTML comments
  T1595  Active Scanning               — subdomain probing, alt-port crawling
  T1592  Gather Host Information        — tech-version-to-CVE, favicon hash, source maps
  T1590  Gather Network Information     — DNS records, SSL SANs, internal hosts
  T1596  Search Open Technical DBs      — WHOIS/ASN, certificate SANs, passive DNS
  T1593  Search Open Websites           — GAU dedup, GitHub domain search
  T1589  Gather Identity Info           — credential extraction from source maps
"""

import asyncio
import hashlib
import re
import ssl
import struct
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse


# ═══════════════════════════════════════════════════════════════════════
# T1594 — robots.txt / sitemap.xml parsing
# ═══════════════════════════════════════════════════════════════════════

async def parse_robots_txt(session, base_url: str, *, timeout: int = 10) -> Dict[str, Any]:
    """Fetch and parse robots.txt for hidden paths.

    Returns dict with keys:
      - paths: set of discovered URL paths
      - disallowed: list of Disallow paths (high-value recon targets)
      - sitemaps: list of sitemap URLs declared in robots.txt
      - interesting: list of paths matching admin/staging/api/internal patterns
    """
    result: Dict[str, Any] = {
        "paths": set(),
        "disallowed": [],
        "sitemaps": [],
        "interesting": [],
    }
    robots_url = urljoin(base_url.rstrip("/") + "/", "/robots.txt")

    try:
        async with session.get(robots_url, timeout=timeout, allow_redirects=True) as resp:
            if resp.status != 200:
                return result
            text = await resp.text(errors="replace")
    except Exception:
        return result

    _INTERESTING_RE = re.compile(
        r'(admin|staging|stage|internal|api|debug|test|dev|backup|'
        r'manager|console|dashboard|portal|config|setup|install|'
        r'wp-admin|phpmyadmin|cgi-bin|server-status|server-info)',
        re.IGNORECASE,
    )

    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("disallow:", "allow:")):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                # Convert wildcard patterns to actual paths for probing
                clean_path = path.split("*")[0].rstrip("$")
                if clean_path:
                    full_url = urljoin(base_url.rstrip("/") + "/", clean_path)
                    result["paths"].add(full_url)
                if lower.startswith("disallow:"):
                    result["disallowed"].append(path)
                    if _INTERESTING_RE.search(path):
                        result["interesting"].append(path)
        elif lower.startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            # Handle "Sitemap: http://..." vs "Sitemap:http://..."
            if sitemap_url.startswith("//"):
                parsed = urlparse(base_url)
                sitemap_url = f"{parsed.scheme}:{sitemap_url}"
            elif not sitemap_url.startswith(("http://", "https://")):
                sitemap_url = urljoin(base_url.rstrip("/") + "/", sitemap_url)
            result["sitemaps"].append(sitemap_url)

    return result


async def parse_sitemap(session, sitemap_url: str, *, timeout: int = 15,
                        max_urls: int = 500, _depth: int = 0) -> Set[str]:
    """Fetch and parse a sitemap XML, returning discovered URLs.

    Handles:
      - Standard <urlset> with <loc> entries
      - Sitemap index (<sitemapindex>) with child sitemaps (max 1 level deep)
      - Compressed .xml.gz sitemaps (detected but not decompressed)
    """
    if _depth > 2:
        return set()

    urls: Set[str] = set()
    try:
        async with session.get(sitemap_url, timeout=timeout, allow_redirects=True) as resp:
            if resp.status != 200:
                return urls
            ct = (resp.headers.get("content-type", "") or "").lower()
            if "xml" not in ct and "text" not in ct:
                return urls
            text = await resp.text(errors="replace")
    except Exception:
        return urls

    # Extract <loc> URLs
    loc_re = re.compile(r'<loc>\s*(.*?)\s*</loc>', re.IGNORECASE | re.DOTALL)
    locs = loc_re.findall(text)

    # Detect sitemap index (contains child sitemaps)
    is_index = "<sitemapindex" in text.lower()

    if is_index:
        child_tasks = []
        for child_url in locs[:10]:  # Cap child sitemaps
            child_url = child_url.strip()
            if child_url:
                child_tasks.append(parse_sitemap(
                    session, child_url, timeout=timeout,
                    max_urls=max_urls, _depth=_depth + 1,
                ))
        if child_tasks:
            child_results = await asyncio.gather(*child_tasks, return_exceptions=True)
            for cr in child_results:
                if isinstance(cr, set):
                    urls.update(cr)
                    if len(urls) >= max_urls:
                        break
    else:
        for loc in locs:
            loc = loc.strip()
            if loc and loc.startswith(("http://", "https://")):
                urls.add(loc)
                if len(urls) >= max_urls:
                    break

    return urls


async def wayback_urls(host: str, *, timeout: int = 20, max_urls: int = 2000,
                       session=None) -> Set[str]:
    """Pull a host's historical URLs from the Wayback Machine CDX API.

    Zero-touch OSINT — the request goes to web.archive.org, never to the target.
    Returns a set of distinct original URLs (collapsed by urlkey). Any failure
    (network, rate-limit, bad JSON) yields an empty set rather than raising.
    """
    host = (host or "").strip().lower()
    if host.startswith(("http://", "https://")):
        host = urlparse(host).netloc
    if not host:
        return set()
    api = ("https://web.archive.org/cdx/search/cdx?url="
           + host + "/*&output=json&fl=original&collapse=urlkey&limit=" + str(int(max_urls)))
    urls: Set[str] = set()
    try:
        import aiohttp
    except Exception:
        return urls
    own = session is None
    try:
        if own:
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(connector=connector)
        async with session.get(api, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                return urls
            data = await resp.json(content_type=None)
        # CDX JSON is [[field header], [row], ...]; skip the header row.
        if isinstance(data, list):
            for row in data[1:]:
                if row and isinstance(row, list):
                    u = str(row[0]).strip()
                    if u.startswith(("http://", "https://")):
                        urls.add(u)
                        if len(urls) >= max_urls:
                            break
    except Exception:
        pass
    finally:
        if own and session is not None:
            try:
                await session.close()
            except Exception:
                pass
    return urls


# ═══════════════════════════════════════════════════════════════════════
# T1594 — HTML comment / hidden input extraction
# ═══════════════════════════════════════════════════════════════════════

_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)
_HIDDEN_INPUT_RE = re.compile(
    r'<input[^>]*type\s*=\s*["\']?hidden["\']?[^>]*>',
    re.IGNORECASE,
)
_INPUT_NAME_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_INPUT_VALUE_RE = re.compile(r'value\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_META_GENERATOR_RE = re.compile(
    r'<meta[^>]*name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_URL_IN_COMMENT_RE = re.compile(r'https?://[^\s<>"\']+')
_SENSITIVE_KEYWORDS = re.compile(
    r'(?:password|secret|token|api[_-]?key|credential|TODO|FIXME|HACK|'
    r'debug|staging|internal|admin|root|database|connection)',
    re.IGNORECASE,
)


def extract_html_intel(html: str, base_url: str) -> Dict[str, Any]:
    """Extract intelligence from HTML comments, hidden inputs, meta tags.

    Returns dict with keys:
      - hidden_inputs: list of {name, value} dicts
      - hidden_param_names: set of parameter names for injection testing
      - comments_with_ips: list of (comment_text, [ips])
      - comments_with_urls: list of (comment_text, [urls])
      - comments_with_secrets: list of comment_text
      - meta_generator: list of generator strings (tech fingerprint)
      - internal_urls: set of URLs found in comments
    """
    result: Dict[str, Any] = {
        "hidden_inputs": [],
        "hidden_param_names": set(),
        "comments_with_ips": [],
        "comments_with_urls": [],
        "comments_with_secrets": [],
        "meta_generator": [],
        "internal_urls": set(),
    }

    # --- Hidden inputs ---
    for match in _HIDDEN_INPUT_RE.finditer(html):
        tag = match.group(0)
        name_m = _INPUT_NAME_RE.search(tag)
        value_m = _INPUT_VALUE_RE.search(tag)
        if name_m:
            name = name_m.group(1)
            value = value_m.group(1) if value_m else ""
            result["hidden_inputs"].append({"name": name, "value": value})
            result["hidden_param_names"].add(name)

    # --- HTML comments ---
    for match in _COMMENT_RE.finditer(html):
        comment = match.group(1).strip()
        if len(comment) < 5:
            continue
        # Skip common benign comments (IE conditionals, build markers)
        if comment.startswith(("[if ", "[endif")) or "webpack" in comment.lower():
            continue

        ips = _IP_RE.findall(comment)
        if ips:
            result["comments_with_ips"].append((comment[:500], ips))

        urls = _URL_IN_COMMENT_RE.findall(comment)
        if urls:
            result["comments_with_urls"].append((comment[:500], urls))
            result["internal_urls"].update(urls)

        if _SENSITIVE_KEYWORDS.search(comment):
            result["comments_with_secrets"].append(comment[:500])

    # --- Meta generator ---
    for match in _META_GENERATOR_RE.finditer(html):
        result["meta_generator"].append(match.group(1).strip())

    return result


# ═══════════════════════════════════════════════════════════════════════
# T1593.003 — GAU URL parameter deduplication
# ═══════════════════════════════════════════════════════════════════════

def deduplicate_parameterized_urls(urls: list) -> list:
    """Deduplicate URLs by (path, sorted_param_names) tuple.

    GAU returns hundreds of URLs for the same endpoint with different
    parameter values. This keeps one representative URL per unique
    (path, param_names) combination.

    Returns deduplicated list of URLs.
    """
    seen: Dict[Tuple[str, str, str], str] = {}  # (netloc, path, params_key) → representative URL
    for u in urls:
        try:
            parsed = urlparse(u)
            params = sorted(set(
                p.split("=", 1)[0]
                for p in parsed.query.split("&")
                if p and "=" in p
            ))
            key = (parsed.netloc.lower(), parsed.path, "|".join(params))
            if key not in seen:
                seen[key] = u
        except Exception:
            # Keep unparseable URLs
            if u not in seen.values():
                seen[("_raw", u, "")] = u

    return list(seen.values())


# ═══════════════════════════════════════════════════════════════════════
# T1596.003 — SSL/TLS Certificate SAN Extraction
# ═══════════════════════════════════════════════════════════════════════

async def extract_ssl_sans(hostname: str, port: int = 443, *, timeout: int = 10) -> List[str]:
    """Extract Subject Alternative Names from the server's TLS certificate.

    Returns list of hostnames from the certificate's SAN extension.
    Wildcard entries (*.example.com) are included as-is.
    """
    sans: List[str] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        loop = asyncio.get_event_loop()

        def _get_cert():
            import socket
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # Fall back to binary cert parsing
                        return []
                    san_entries = cert.get("subjectAltName", ())
                    return [v for t, v in san_entries if t.lower() == "dns"]

        sans = await loop.run_in_executor(None, _get_cert)
    except Exception:
        pass
    return sans


# ═══════════════════════════════════════════════════════════════════════
# T1590.002 — DNS Record Analysis
# ═══════════════════════════════════════════════════════════════════════

async def dns_recon(domain: str, *, timeout: int = 10) -> Dict[str, Any]:
    """Perform comprehensive DNS reconnaissance.

    Queries: A, AAAA, MX, TXT, NS, CNAME, SOA
    Parses SPF for includes, checks DMARC policy.

    Returns dict with DNS data.
    """
    import socket
    result: Dict[str, Any] = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "txt_records": [],
        "ns_records": [],
        "cname_records": [],
        "spf_includes": [],
        "dmarc_policy": None,
        "subdomains_from_dns": [],
    }

    loop = asyncio.get_event_loop()

    # Basic A record resolution
    try:
        def _resolve_a():
            return [r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)]
        result["a_records"] = list(set(await loop.run_in_executor(None, _resolve_a)))
    except Exception:
        pass

    # AAAA records
    try:
        def _resolve_aaaa():
            return [r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET6)]
        result["aaaa_records"] = list(set(await loop.run_in_executor(None, _resolve_aaaa)))
    except Exception:
        pass

    # Try dnspython if available for MX/TXT/NS/CNAME/SOA
    try:
        import dns.resolver

        def _dns_queries():
            data = {}
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout

            # MX
            try:
                mx = resolver.resolve(domain, 'MX')
                data["mx"] = [(str(r.exchange).rstrip('.'), r.preference) for r in mx]
            except Exception:
                data["mx"] = []

            # TXT
            try:
                txt = resolver.resolve(domain, 'TXT')
                data["txt"] = [str(r).strip('"') for r in txt]
            except Exception:
                data["txt"] = []

            # NS
            try:
                ns = resolver.resolve(domain, 'NS')
                data["ns"] = [str(r).rstrip('.') for r in ns]
            except Exception:
                data["ns"] = []

            # CNAME
            try:
                cname = resolver.resolve(domain, 'CNAME')
                data["cname"] = [str(r).rstrip('.') for r in cname]
            except Exception:
                data["cname"] = []

            # SOA
            try:
                soa = resolver.resolve(domain, 'SOA')
                data["soa"] = str(soa[0]) if soa else None
            except Exception:
                data["soa"] = None

            # _dmarc TXT
            try:
                dmarc = resolver.resolve(f"_dmarc.{domain}", 'TXT')
                data["dmarc"] = [str(r).strip('"') for r in dmarc]
            except Exception:
                data["dmarc"] = []

            return data

        dns_data = await loop.run_in_executor(None, _dns_queries)

        result["mx_records"] = [h for h, p in dns_data.get("mx", [])]
        result["txt_records"] = dns_data.get("txt", [])
        result["ns_records"] = dns_data.get("ns", [])
        result["cname_records"] = dns_data.get("cname", [])

        # Parse SPF includes
        for txt in result["txt_records"]:
            if "v=spf1" in txt.lower():
                includes = re.findall(r'include:(\S+)', txt)
                result["spf_includes"] = includes
                # IP ranges from SPF
                ip4s = re.findall(r'ip4:(\S+)', txt)
                result.setdefault("spf_ip_ranges", []).extend(ip4s)

        # Parse DMARC
        for txt in dns_data.get("dmarc", []):
            if "v=dmarc1" in txt.lower():
                policy_m = re.search(r'p\s*=\s*(\w+)', txt)
                result["dmarc_policy"] = policy_m.group(1) if policy_m else "none"

        # Extract subdomains from MX/NS records
        for record_list in [result["mx_records"], result["ns_records"], result["cname_records"]]:
            for r in record_list:
                if r.endswith(f".{domain}") or r.endswith(f".{domain}."):
                    result["subdomains_from_dns"].append(r.rstrip("."))

    except ImportError:
        pass  # dnspython not installed — skip advanced DNS

    return result


# ═══════════════════════════════════════════════════════════════════════
# T1592.002 — Source Map Discovery
# ═══════════════════════════════════════════════════════════════════════

_SOURCEMAP_DIRECTIVE_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')


async def discover_source_maps(session, js_urls: list, base_url: str, *,
                                timeout: int = 10, max_maps: int = 20) -> Dict[str, Any]:
    """Probe JS URLs for corresponding .map source map files.

    For each JS URL:
      1. Try fetching {url}.map
      2. Check the JS content for //# sourceMappingURL= directive
      3. If a source map is found, parse it for intelligence

    Returns dict with:
      - exposed_maps: list of {js_url, map_url, sources, endpoints, secrets}
      - total_source_files: int (count of original source files)
    """
    result: Dict[str, Any] = {
        "exposed_maps": [],
        "total_source_files": 0,
    }

    checked = 0
    for js_url in js_urls:
        if checked >= max_maps:
            break

        map_urls_to_try = [f"{js_url}.map"]

        # Also check the JS content for sourceMappingURL
        try:
            async with session.get(js_url, timeout=timeout) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="replace")
                    # Only check last 500 chars for the directive (it's always at the end)
                    tail = body[-500:]
                    m = _SOURCEMAP_DIRECTIVE_RE.search(tail)
                    if m:
                        map_ref = m.group(1)
                        if map_ref.startswith(("http://", "https://")):
                            map_urls_to_try.insert(0, map_ref)
                        elif map_ref.startswith("/"):
                            map_urls_to_try.insert(0, urljoin(base_url, map_ref))
                        else:
                            # Relative to JS file
                            js_dir = js_url.rsplit("/", 1)[0] + "/"
                            map_urls_to_try.insert(0, urljoin(js_dir, map_ref))
        except Exception:
            pass

        for map_url in map_urls_to_try:
            try:
                async with session.get(map_url, timeout=timeout) as resp:
                    if resp.status != 200:
                        continue
                    ct = (resp.headers.get("content-type", "") or "").lower()
                    body = await resp.text(errors="replace")

                    # Must look like a source map
                    if '"mappings"' not in body and '"sources"' not in body:
                        continue

                    import json
                    try:
                        sm = json.loads(body)
                    except (json.JSONDecodeError, ValueError):
                        continue

                    sources = sm.get("sources", [])
                    sources_content = sm.get("sourcesContent", [])

                    intel = {
                        "js_url": js_url,
                        "map_url": map_url,
                        "sources": sources[:100],  # Cap for sanity
                        "source_count": len(sources),
                        "endpoints": [],
                        "secrets": [],
                        "env_vars": [],
                    }

                    # Mine the unminified source code for intelligence
                    api_re = re.compile(r'["\'](/api/[^\s"\']+)["\']')
                    env_re = re.compile(r'(?:process\.env\.|REACT_APP_|NEXT_PUBLIC_|VUE_APP_)(\w+)')
                    secret_patterns = [
                        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{10,})["\']', "api_key"),
                        (r'(?:secret|password|token)\s*[:=]\s*["\']([^"\']{8,})["\']', "secret"),
                        (r'(?:AKIA[0-9A-Z]{16})', "aws_key"),
                    ]

                    for sc in sources_content[:50]:  # Cap parsing
                        if not sc:
                            continue
                        # Extract API endpoints
                        for ep_match in api_re.finditer(sc[:50000]):
                            intel["endpoints"].append(ep_match.group(1))
                        # Extract env var names
                        for env_match in env_re.finditer(sc[:50000]):
                            intel["env_vars"].append(env_match.group(1))
                        # Extract secrets
                        for pat, stype in secret_patterns:
                            for sec_match in re.finditer(pat, sc[:50000], re.IGNORECASE):
                                intel["secrets"].append({
                                    "type": stype,
                                    "value": sec_match.group(1) if sec_match.lastindex else sec_match.group(0),
                                })

                    intel["endpoints"] = list(set(intel["endpoints"]))[:50]
                    intel["env_vars"] = list(set(intel["env_vars"]))[:30]
                    result["exposed_maps"].append(intel)
                    result["total_source_files"] += len(sources)
                    checked += 1
                    break  # Found map for this JS, move to next
            except Exception:
                continue

    return result


# ═══════════════════════════════════════════════════════════════════════
# T1590.004 — Internal Host Probing
# ═══════════════════════════════════════════════════════════════════════

async def probe_internal_hosts(internal_hosts: list, *, timeout: int = 5) -> Dict[str, Any]:
    """Check if JS-discovered internal hostnames resolve and are accessible.

    Returns dict with:
      - resolvable: list of (host, ip) that resolve via DNS
      - accessible: list of (host, status) that respond to HTTP
      - unresolvable: list of hosts that don't resolve
    """
    import socket
    result: Dict[str, Any] = {
        "resolvable": [],
        "accessible": [],
        "unresolvable": [],
    }

    loop = asyncio.get_event_loop()

    for host in internal_hosts[:20]:  # Cap to prevent abuse
        # Strip protocol if present
        clean = re.sub(r'^https?://', '', host).split("/")[0].split(":")[0]
        if not clean:
            continue
        try:
            def _resolve(h=clean):
                return socket.gethostbyname(h)
            ip = await loop.run_in_executor(None, _resolve)
            result["resolvable"].append((clean, ip))
        except socket.gaierror:
            result["unresolvable"].append(clean)
        except Exception:
            result["unresolvable"].append(clean)

    # For resolvable hosts, try HTTP access
    if result["resolvable"]:
        try:
            import aiohttp
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                for host, ip in result["resolvable"][:10]:
                    for scheme in ("https", "http"):
                        try:
                            async with session.get(
                                f"{scheme}://{host}",
                                timeout=aiohttp.ClientTimeout(total=timeout),
                                allow_redirects=False,
                            ) as resp:
                                result["accessible"].append((host, resp.status))
                                break
                        except Exception:
                            continue
        except ImportError:
            pass

    return result


# ═══════════════════════════════════════════════════════════════════════
# T1592.002 — Tech-Version-to-CVE Lookup
# ═══════════════════════════════════════════════════════════════════════

# Well-known CVE ranges for common software versions. This avoids
# external API calls while catching the most impactful outdated
# components.  Each entry is (tech, version_less_than, cve_list, severity).
_KNOWN_CVE_RANGES: List[Tuple[str, str, str, List[str], str]] = [
    # (tech_name, min_version_affected, max_version_fixed, [cves], severity)
    ("nginx", "1.0.0", "1.20.2", ["CVE-2021-23017", "CVE-2022-41741"], "HIGH"),
    ("nginx", "1.0.0", "1.22.1", ["CVE-2022-41741", "CVE-2022-41742"], "MEDIUM"),
    ("apache", "2.4.0", "2.4.52", ["CVE-2021-44790", "CVE-2022-22720"], "HIGH"),
    ("apache", "2.4.0", "2.4.55", ["CVE-2022-36760", "CVE-2023-25690"], "HIGH"),
    ("openssh", "7.0", "8.8", ["CVE-2021-41617"], "MEDIUM"),
    ("openssh", "8.5", "9.3p2", ["CVE-2023-38408"], "HIGH"),
    ("php", "7.0.0", "7.4.33", ["CVE-2022-31626", "CVE-2022-31628"], "HIGH"),
    ("php", "8.0.0", "8.0.25", ["CVE-2022-31631"], "MEDIUM"),
    ("php", "8.1.0", "8.1.14", ["CVE-2023-0568"], "MEDIUM"),
    ("jquery", "1.0.0", "3.5.0", ["CVE-2020-11022", "CVE-2020-11023"], "MEDIUM"),
    ("wordpress", "4.0.0", "6.1.1", ["CVE-2023-22622"], "MEDIUM"),
    ("django", "3.0", "3.2.16", ["CVE-2022-41323"], "MEDIUM"),
    ("express", "4.0.0", "4.17.3", ["CVE-2022-24999"], "HIGH"),
    ("spring", "5.0.0", "5.3.18", ["CVE-2022-22965"], "CRITICAL"),
    ("tomcat", "9.0.0", "9.0.68", ["CVE-2022-42252"], "MEDIUM"),
    ("iis", "7.0", "10.0", ["CVE-2021-31166"], "CRITICAL"),
]


def _version_tuple(v: str) -> Tuple[int, ...]:
    """Convert version string to comparable tuple."""
    parts = re.findall(r'\d+', v)
    return tuple(int(p) for p in parts) if parts else (0,)


def check_known_cves(technologies: Dict[str, str]) -> List[Dict[str, Any]]:
    """Check detected technologies against known CVE ranges.

    Returns list of {tech, version, cves, severity, description} dicts.
    """
    findings: List[Dict[str, Any]] = []

    for tech, version in technologies.items():
        if not version:
            continue
        tech_lower = tech.lower()
        detected_ver = _version_tuple(version)
        if detected_ver == (0,):
            continue

        for entry_tech, min_ver, max_ver, cves, severity in _KNOWN_CVE_RANGES:
            if entry_tech != tech_lower:
                continue
            min_t = _version_tuple(min_ver)
            max_t = _version_tuple(max_ver)
            if min_t <= detected_ver < max_t:
                findings.append({
                    "tech": tech,
                    "version": version,
                    "cves": cves,
                    "severity": severity,
                    "fixed_in": max_ver,
                    "description": (
                        f"{tech} {version} is affected by {', '.join(cves)}. "
                        f"Upgrade to {max_ver} or later."
                    ),
                })

    return findings


# ═══════════════════════════════════════════════════════════════════════
# T1592.002 — Favicon Hash Fingerprinting
# ═══════════════════════════════════════════════════════════════════════

# MurmurHash3-based favicon fingerprinting (Shodan-compatible)
_FAVICON_HASHES: Dict[int, str] = {
    -1293291467: "Jenkins",
    116323821: "Grafana",
    -1028703177: "cPanel",
    -335242539: "Kibana",
    1354335572: "Spring Boot",
    -162429485: "Atlassian Jira",
    1485257654: "Atlassian Confluence",
    -305179312: "phpmyadmin",
    988422585: "GitLab",
    81586312: "Apache Tomcat",
    -1507567067: "SonarQube",
    -1055858842: "Prometheus",
    1936433332: "HashiCorp Vault",
}


def _mmh3_hash(data: bytes) -> int:
    """Minimal MurmurHash3 (32-bit) for favicon fingerprinting."""
    import base64
    encoded = base64.encodebytes(data)
    # Use standard mmh3 if available, else skip
    try:
        import mmh3
        return mmh3.hash(encoded)
    except ImportError:
        # Fallback: use the base64 hash approach (less accurate)
        import hashlib
        h = hashlib.md5(encoded).hexdigest()
        return int(h[:8], 16) - (1 << 31)


async def check_favicon_hash(session, base_url: str, *, timeout: int = 10) -> Optional[str]:
    """Fetch /favicon.ico, compute hash, match against known fingerprints.

    Returns matched technology name or None.
    """
    try:
        favicon_url = urljoin(base_url.rstrip("/") + "/", "/favicon.ico")
        async with session.get(favicon_url, timeout=timeout, allow_redirects=True) as resp:
            if resp.status != 200:
                return None
            ct = (resp.headers.get("content-type", "") or "").lower()
            if "html" in ct:  # Got an HTML page, not a favicon
                return None
            data = await resp.read()
            if len(data) < 100 or len(data) > 500_000:
                return None
            h = _mmh3_hash(data)
            return _FAVICON_HASHES.get(h)
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════
# T1596.002 — WHOIS / ASN Lookup
# ═══════════════════════════════════════════════════════════════════════

async def whois_asn_lookup(domain: str, ip: str = "", *, timeout: int = 10) -> Dict[str, Any]:
    """Perform WHOIS and ASN lookup for infrastructure mapping.

    Returns dict with registrant info, ASN data, and related domains.
    """
    import socket
    result: Dict[str, Any] = {
        "asn": None,
        "asn_org": None,
        "registrar": None,
        "creation_date": None,
        "ip_ranges": [],
    }

    loop = asyncio.get_event_loop()

    # Resolve IP if not provided
    if not ip:
        try:
            def _resolve():
                return socket.gethostbyname(domain)
            ip = await loop.run_in_executor(None, _resolve)
        except Exception:
            return result

    # Team Cymru DNS lookup for ASN
    try:
        def _asn_lookup():
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            answers = socket.getaddrinfo(query, None)
            # Actually need TXT record — try via dnspython
            try:
                import dns.resolver
                txt = dns.resolver.resolve(query, 'TXT')
                for r in txt:
                    parts = str(r).strip('"').split("|")
                    if len(parts) >= 3:
                        return {
                            "asn": parts[0].strip(),
                            "prefix": parts[1].strip(),
                            "asn_org": parts[4].strip() if len(parts) > 4 else "",
                        }
            except Exception:
                pass
            return {}

        asn_data = await loop.run_in_executor(None, _asn_lookup)
        result["asn"] = asn_data.get("asn")
        result["asn_org"] = asn_data.get("asn_org")
        if asn_data.get("prefix"):
            result["ip_ranges"].append(asn_data["prefix"])

    except Exception:
        pass

    return result


# ═══════════════════════════════════════════════════════════════════════
# T1595.001 — Subdomain Liveness Probing
# ═══════════════════════════════════════════════════════════════════════

async def probe_subdomain_liveness(subdomains: list, *,
                                    timeout: int = 5,
                                    max_concurrent: int = 20,
                                    max_subdomains: int = 100) -> Dict[str, Any]:
    """HTTP(S) probe discovered subdomains for liveness.

    Returns dict with:
      - alive: list of {subdomain, url, status, server, technologies}
      - dead: list of subdomains that didn't respond
    """
    result: Dict[str, Any] = {
        "alive": [],
        "dead": [],
    }

    try:
        import aiohttp
    except ImportError:
        return result

    sem = asyncio.Semaphore(max_concurrent)

    async def _probe(subdomain: str) -> Optional[Dict[str, Any]]:
        async with sem:
            for scheme in ("https", "http"):
                url = f"{scheme}://{subdomain}"
                try:
                    connector = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(connector=connector) as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=timeout),
                            allow_redirects=True,
                        ) as resp:
                            server = resp.headers.get("server", "")
                            powered_by = resp.headers.get("x-powered-by", "")
                            return {
                                "subdomain": subdomain,
                                "url": str(resp.url),
                                "status": resp.status,
                                "server": server,
                                "technologies": [t for t in (server, powered_by) if t],
                            }
                except Exception:
                    continue
            return None

    # Deduplicate and cap
    unique_subs = list(dict.fromkeys(subdomains))[:max_subdomains]

    tasks = [_probe(sub) for sub in unique_subs]
    probe_results = await asyncio.gather(*tasks, return_exceptions=True)

    for sub, pr in zip(unique_subs, probe_results):
        if isinstance(pr, dict):
            result["alive"].append(pr)
        else:
            result["dead"].append(sub)

    return result


# ═══════════════════════════════════════════════════════════════════════
# T1592.002 — Tech-Driven Scanner Selection
# ═══════════════════════════════════════════════════════════════════════

# Maps detected technologies to recommended additional probing paths
TECH_PROBE_PATHS: Dict[str, List[Tuple[str, str]]] = {
    # tech_name: [(path, description), ...]
    "wordpress": [
        ("/wp-json/wp/v2/users", "WordPress user enumeration"),
        ("/wp-json/", "WordPress REST API root"),
        ("/xmlrpc.php", "WordPress XML-RPC (brute force vector)"),
        ("/wp-content/debug.log", "WordPress debug log"),
        ("/wp-config.php.bak", "WordPress config backup"),
        ("/wp-admin/install.php", "WordPress installer"),
    ],
    "spring": [
        ("/actuator", "Spring Boot actuator root"),
        ("/actuator/env", "Spring Boot environment"),
        ("/actuator/configprops", "Spring Boot config properties"),
        ("/actuator/heapdump", "Spring Boot heap dump"),
        ("/actuator/mappings", "Spring Boot URL mappings"),
        ("/actuator/beans", "Spring Boot bean registry"),
        ("/actuator/health", "Spring Boot health endpoint"),
    ],
    "php": [
        ("/phpinfo.php", "PHP info page"),
        ("/info.php", "PHP info page (alt)"),
        ("/.phps", "PHP source exposure"),
        ("/composer.json", "Composer dependencies"),
        ("/composer.lock", "Composer lock file"),
    ],
    "node": [
        ("/.env", "Node environment config"),
        ("/package.json", "Node package manifest"),
        ("/package-lock.json", "Node lock file"),
        ("/__webpack_dev_server__/sockjs-node", "Webpack dev server"),
    ],
    "express": [
        ("/.env", "Express environment config"),
        ("/package.json", "Express package manifest"),
    ],
    "django": [
        ("/admin/", "Django admin panel"),
        ("/__debug__/", "Django debug toolbar"),
        ("/static/admin/", "Django admin static files"),
    ],
    "flask": [
        ("/console", "Flask Werkzeug debugger"),
        ("/static/", "Flask static files"),
    ],
    "nextjs": [
        ("/_next/data/", "Next.js data directory"),
        ("/api/", "Next.js API routes"),
        ("/_next/static/chunks/", "Next.js chunks"),
    ],
    "laravel": [
        ("/.env", "Laravel environment config"),
        ("/storage/logs/laravel.log", "Laravel log file"),
        ("/telescope", "Laravel Telescope debugger"),
        ("/_ignition/health-check", "Laravel Ignition"),
    ],
    "rails": [
        ("/rails/info", "Rails info page"),
        ("/rails/mailers", "Rails mailer previews"),
        ("/sidekiq", "Sidekiq dashboard"),
    ],
    "tomcat": [
        ("/manager/html", "Tomcat manager"),
        ("/host-manager/html", "Tomcat host manager"),
        ("/status", "Tomcat status page"),
    ],
    "grafana": [
        ("/api/admin/stats", "Grafana admin stats"),
        ("/api/org", "Grafana organization info"),
        ("/api/users/search?query=&", "Grafana user enumeration"),
    ],
    "jenkins": [
        ("/script", "Jenkins script console"),
        ("/api/json", "Jenkins API"),
        ("/asynchPeople/", "Jenkins user enumeration"),
        ("/manage", "Jenkins management"),
    ],
    "graphql": [
        ("/graphql", "GraphQL endpoint"),
        ("/graphiql", "GraphiQL IDE"),
        ("/playground", "GraphQL Playground"),
        ("/altair", "Altair GraphQL Client"),
        ("/v1/graphql", "GraphQL v1"),
    ],
}


def get_tech_probe_paths(technologies: Dict[str, str]) -> List[Tuple[str, str, str]]:
    """Given detected technologies, return additional paths to probe.

    Returns list of (path, description, tech_name) tuples.
    """
    paths: List[Tuple[str, str, str]] = []
    seen: Set[str] = set()

    for tech_name in technologies:
        tech_lower = tech_name.lower()
        for probe_tech, probe_paths in TECH_PROBE_PATHS.items():
            if probe_tech in tech_lower or tech_lower in probe_tech:
                for path, desc in probe_paths:
                    if path not in seen:
                        seen.add(path)
                        paths.append((path, desc, probe_tech))

    return paths


# ═══════════════════════════════════════════════════════════════════════
# T1593.003 — GitHub Domain-Wide Code Search
# ═══════════════════════════════════════════════════════════════════════

async def github_domain_search(domain: str, *, token: str = "",
                                timeout: int = 30,
                                max_results: int = 50) -> List[Dict[str, Any]]:
    """Search GitHub code for domain-specific leaks across ALL repos.

    Searches for the target domain in code files to find:
      - Third-party repos referencing the domain
      - Leaked API keys and credentials
      - Internal URLs and configuration leaks

    Returns list of {repo, file, url, matched_line} dicts.
    """
    results: List[Dict[str, Any]] = []

    try:
        import aiohttp
    except ImportError:
        return results

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    search_queries = [
        f'"{domain}" filename:.env',
        f'"{domain}" filename:config',
        f'"{domain}" password OR secret OR key OR token',
        f'"{domain}" api_key OR apikey OR api-key',
    ]

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            for query in search_queries:
                try:
                    async with session.get(
                        "https://api.github.com/search/code",
                        params={"q": query, "per_page": 10},
                        timeout=aiohttp.ClientTimeout(total=timeout),
                    ) as resp:
                        if resp.status == 403:
                            break  # Rate limited
                        if resp.status != 200:
                            continue
                        data = await resp.json()
                        for item in data.get("items", []):
                            results.append({
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "file": item.get("path", ""),
                                "url": item.get("html_url", ""),
                                "score": item.get("score", 0),
                                "query": query,
                            })
                            if len(results) >= max_results:
                                return results
                    # Rate limit: 10 requests per minute for unauthenticated
                    await asyncio.sleep(6 if not token else 2)
                except Exception:
                    continue
    except Exception:
        pass

    return results
