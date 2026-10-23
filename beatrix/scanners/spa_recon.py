"""
BEATRIX Client-Side / SPA Recon

Recovers the client-side attack surface of modern single-page apps — the part a
plain crawler never sees because it lives inside minified JS bundles.

Technique (ported natively from reverse-engineering tooling; keyless, no Node):
  1. Discover JS bundles (reuses JSBundleAnalyzer discovery: manifests, HTML
     <script> tags, webpack chunk refs, Next.js build manifests).
  2. Recover ORIGINAL sources from source maps — external ``.map`` files, the
     ``//# sourceMappingURL=`` directive, and inline base64/data-URI maps —
     decoding ``sourcesContent`` and rebuilding the source tree.
  3. Inventory routes/endpoints from the recovered (un-minified) sources:
     fetch/axios/XHR/WebSocket URLs, API base paths, and client-side router
     route definitions (React Router / Vue Router / Angular).
  4. Extract secrets with the SHARED secret-rules engine (same tables + FP
     suppression as GitHub recon).
  5. Diff recovered source vs. the deployed bundle: internal FS paths, dev
     comments, dev-only code, and API hosts never seen live.

Every claim it emits carries an evidence-provenance record (see
beatrix.core.provenance): what was OBSERVED in the fetched bytes, what was
DERIVED by parsing, what was INFERRED heuristically, and — when sources cannot
be recovered — an explicit UNKNOWN (never silently "clean").

OWASP: A05:2021 Security Misconfiguration (sensitive info in client JS)
CWE: CWE-540 / CWE-200
"""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, unquote

from beatrix.core.types import Confidence, Finding, Severity
from beatrix.core.provenance import Provenance, ClaimType, mask_literal
from beatrix.scanners import _secret_rules as secret_rules
from beatrix.scanners.base import BaseScanner, ScanContext
from beatrix.scanners.js_bundle import JSBundleAnalyzer

try:  # reuse the single compiled directive pattern; fall back if recon_helpers is unavailable
    from beatrix.core.recon_helpers import _SOURCEMAP_DIRECTIVE_RE
except Exception:  # pragma: no cover
    _SOURCEMAP_DIRECTIVE_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')


@dataclass
class RecoveredSource:
    """One original source file reconstructed from a source map."""
    path: str                 # logical path, webpack:// stripped
    content: str = ""
    has_content: bool = False  # True if sourcesContent carried the body
    third_party: bool = False  # node_modules / vendored
    map_url: str = ""
    raw: str = ""             # original ``sources[i]`` entry (may hold FS paths)


@dataclass
class SPAReconResult:
    """Everything one SPA recon pass produced — consumed by the suite + scan()."""
    target: str = ""
    bundles: List[str] = field(default_factory=list)
    maps: List[str] = field(default_factory=list)
    sources: List[RecoveredSource] = field(default_factory=list)
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    exposures: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    recovered: bool = False   # True if any sourcemap yielded original sources


class SPAReconScanner(BaseScanner):
    """Client-side / SPA attack-surface recovery (source maps → routes/secrets)."""

    name = "spa_recon"
    description = "Client-side/SPA recon — recovers sourcemapped sources, routes, endpoints & secrets"
    version = "1.0.0"
    owasp_category = "A05:2021"
    mitre_technique = "T1592.002"  # Gather Victim Host Information: Software

    checks = [
        "Source maps publicly exposed (original source recoverable)",
        "API routes / endpoints disclosed in client JS",
        "Client-side router routes disclosed",
        "Secrets in recovered sources",
        "Internal hosts / dev-only code in client bundles",
    ]

    # ── Reuse JSBundleAnalyzer's battle-tested extraction tables ─────────────
    API_PATTERNS = JSBundleAnalyzer.API_PATTERNS
    FRAMEWORK_NOISE = JSBundleAnalyzer.FRAMEWORK_NOISE_PATTERNS
    HOST_PATTERNS = JSBundleAnalyzer.HOST_PATTERNS
    PUBLIC_TLDS = JSBundleAnalyzer.PUBLIC_TLDS
    ENV_PATTERNS = JSBundleAnalyzer.ENV_PATTERNS
    DEBUG_PATTERNS = JSBundleAnalyzer.DEBUG_PATTERNS

    # ── SPA-specific additions ───────────────────────────────────────────────
    # Client-side router route definitions (React Router / Vue Router / Angular).
    ROUTER_PATTERNS = [
        re.compile(r'''<Route\s+[^>]*\bpath=["']([^"']+)["']''', re.IGNORECASE),
        re.compile(r'''\{\s*path\s*:\s*["']([^"']+)["']'''),
        re.compile(r'''["']path["']\s*:\s*["']([^"']+)["']'''),
    ]
    BASEURL_RE = re.compile(r'''baseURL\s*[:=]\s*["']([^"']+)["']''')
    # Lazy/dynamic imports — surface additional chunks worth recovering.
    DYNAMIC_IMPORT_RE = re.compile(r'''\bimport\(\s*["']([^"']+\.m?js)["']''')
    # Internal filesystem paths leaked through webpack:// source entries.
    SENSITIVE_PATH_RE = re.compile(
        r'(/Users/[^/\s"\']+|/home/[^/\s"\']+|[A-Za-z]:\\Users\\[^\\\s"\']+)'
    )
    # Developer comments that survive into recovered sources.
    DEV_COMMENT_RE = re.compile(
        r'(?://|/\*|\*)\s*\b(TODO|FIXME|HACK|XXX|BUG|SECURITY|DEPRECATED|@deprecated)\b[:\s-]{0,3}(.{0,120})',
        re.IGNORECASE,
    )

    # Caps (coverage is logged, never silently truncated).
    MAX_BUNDLES = 80
    MAX_SOURCES_PARSED = 400
    MAX_LIST_PER_FINDING = 60

    async def __aenter__(self):
        """Follow redirects — SPA roots frequently 301/302 to a canonical host."""
        import httpx
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        return self

    # =========================================================================
    # ENTRY POINTS
    # =========================================================================
    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Kill-chain entry: recover the SPA surface, yield provenance findings."""
        base = context.base_url or context.url
        js_files = []
        if getattr(context, "extra", None):
            js_files = list(context.extra.get("js_files", []) or [])
            seen = context.extra.get("seen_hosts")
        else:
            seen = None
        result = await self.recover(base, js_files=js_files, seen_hosts=seen)
        for finding in result.findings:
            yield finding

    async def recover(
        self,
        target_url: str,
        js_files: Optional[List[str]] = None,
        seen_hosts: Optional[Set[str]] = None,
    ) -> SPAReconResult:
        """Headless entry used by the suite workbench. Safe to call with or
        without an active ``async with`` context — opens a transient client if
        the scanner has not been entered."""
        if self.client is None:
            async with self:
                return await self._recover_impl(target_url, js_files, seen_hosts)
        return await self._recover_impl(target_url, js_files, seen_hosts)

    # =========================================================================
    # CORE
    # =========================================================================
    async def _recover_impl(self, target_url, js_files, seen_hosts) -> SPAReconResult:
        base = self._normalize(target_url)
        seen = {h.lower() for h in (seen_hosts or set()) if h}
        result = SPAReconResult(target=base)

        # 1) discover bundles (reuse JSBundleAnalyzer discovery + minified fallback)
        jsb = JSBundleAnalyzer(self.config)
        async with jsb:
            bundle_set: Set[str] = set(js_files or [])
            try:
                bundle_set.update(await jsb._discover_bundles(base))
            except Exception as e:  # pragma: no cover - network dependent
                self.log(f"bundle discovery failed: {e}", "warning")

            js_urls = sorted(u for u in bundle_set if not u.endswith(".map"))
            known_maps = [u for u in bundle_set if u.endswith(".map")]
            result.bundles = js_urls
            if not js_urls and not known_maps:
                result.unknowns.append("no JavaScript bundles discovered for target")
                result.findings = self._build_findings(result)
                return result

            if len(js_urls) > self.MAX_BUNDLES:
                self.log(f"capping bundle recovery at {self.MAX_BUNDLES} of {len(js_urls)}", "info")
                result.stats["bundles_skipped"] = len(js_urls) - self.MAX_BUNDLES

            # 2) recover sources from source maps
            recovered: Dict[str, RecoveredSource] = {}
            map_urls: Set[str] = set()
            for js_url in js_urls[: self.MAX_BUNDLES]:
                sm, map_label = await self._recover_from_js(js_url, base)
                if sm is not None:
                    map_urls.add(map_label)
                    for rs in self._reconstruct_tree(sm, map_label):
                        recovered.setdefault(rs.path, rs)
            for map_url in known_maps:
                sm = await self._fetch_map(map_url)
                if sm is not None:
                    map_urls.add(map_url)
                    for rs in self._reconstruct_tree(sm, map_url):
                        recovered.setdefault(rs.path, rs)

            result.maps = sorted(map_urls)
            result.sources = list(recovered.values())
            result.recovered = bool(recovered)
            result.stats.update(
                bundles=len(js_urls), maps=len(map_urls),
                sources=len(recovered),
                sources_with_content=sum(1 for s in recovered.values() if s.has_content),
            )

            if recovered:
                self._inventory(result, recovered, seen)
            else:
                # 6) graceful fallback — analyze the minified bundles (INFERENCE),
                #    and record an explicit UNKNOWN (never "no secrets = clean").
                await self._fallback_minified(result, js_urls, seen, jsb)
                result.unknowns.append(
                    "original sources unavailable (no source maps); findings derived "
                    "from minified bundles and are heuristic"
                )

        result.findings = self._build_findings(result)
        return result

    async def _recover_from_js(self, js_url: str, base: str) -> Tuple[Optional[dict], Optional[str]]:
        """Locate + parse the source map for one JS bundle. Returns (map_dict, label)."""
        refs: List[str] = []
        try:
            resp = await self.get(js_url)
            body = resp.text if resp.status_code == 200 else ""
        except Exception:
            body = ""
        if body:
            m = _SOURCEMAP_DIRECTIVE_RE.search(body[-2000:])
            if m:
                ref = m.group(1).strip()
                if ref.startswith("data:"):
                    sm = self._decode_inline_sourcemap(ref)
                    if sm is not None:
                        return sm, js_url + " (inline map)"
                elif ref.startswith(("http://", "https://")):
                    refs.append(ref)
                elif ref.startswith("/"):
                    refs.append(urljoin(base, ref))
                else:
                    refs.append(urljoin(js_url.rsplit("/", 1)[0] + "/", ref))
        refs.append(js_url + ".map")
        for map_url in refs:
            sm = await self._fetch_map(map_url)
            if sm is not None:
                return sm, map_url
        return None, None

    async def _fetch_map(self, map_url: str) -> Optional[dict]:
        try:
            resp = await self.get(map_url)
            if resp.status_code != 200:
                return None
            body = resp.text
            if '"mappings"' not in body and '"sources"' not in body:
                return None
            sm = json.loads(body)
            return sm if isinstance(sm, dict) else None
        except Exception:
            return None

    def _decode_inline_sourcemap(self, ref: str) -> Optional[dict]:
        """Decode a ``data:`` URI source map (base64 or url-encoded JSON)."""
        try:
            header, _, data = ref.partition(",")
            if not data:
                return None
            if ";base64" in header.lower():
                raw = base64.b64decode(data).decode("utf-8", "replace")
            else:
                raw = unquote(data)
            sm = json.loads(raw)
            return sm if isinstance(sm, dict) else None
        except Exception:
            return None

    def _reconstruct_tree(self, sm: dict, map_label: str) -> List[RecoveredSource]:
        """Rebuild original source files from a parsed source map."""
        sources = sm.get("sources", []) or []
        contents = sm.get("sourcesContent", []) or []
        root = (sm.get("sourceRoot") or "").strip()
        out: List[RecoveredSource] = []
        for i, src in enumerate(sources):
            if src is None:
                continue
            path = self._clean_source_path(str(src), root)
            content = contents[i] if i < len(contents) else None
            out.append(RecoveredSource(
                path=path,
                content=content or "",
                has_content=bool(content),
                third_party=("node_modules" in str(src)) or ("node_modules" in path),
                map_url=map_label,
                raw=str(src),
            ))
        return out

    @staticmethod
    def _clean_source_path(src: str, root: str = "") -> str:
        p = src or ""
        for pre in ("webpack-internal:///", "webpack:///", "webpack://", "ng://"):
            if p.startswith(pre):
                p = p[len(pre):]
                break
        p = p.split("?", 1)[0].lstrip("/")
        while p.startswith("./") or p.startswith("../"):
            p = p[2:] if p.startswith("./") else p[3:]
        if root and not p.startswith(root.lstrip("/")):
            p = f"{root.rstrip('/')}/{p}"
        return p or (src or "")

    # =========================================================================
    # ANALYSIS (provenance-tagged)
    # =========================================================================
    def _inventory(self, result: SPAReconResult, recovered: Dict[str, RecoveredSource], seen: Set[str]) -> None:
        endpoints: Dict[str, Dict] = {}
        routes: Dict[str, Dict] = {}
        hosts: Dict[str, Dict] = {}
        secrets: List[Dict] = []
        exposures: List[Dict] = []

        parsed = 0
        own = [s for s in recovered.values() if not s.third_party and s.has_content]
        if len(own) > self.MAX_SOURCES_PARSED:
            self.log(f"capping source analysis at {self.MAX_SOURCES_PARSED} of {len(own)}", "info")
            result.stats["sources_skipped"] = len(own) - self.MAX_SOURCES_PARSED
        for rs in own[: self.MAX_SOURCES_PARSED]:
            parsed += 1
            # sensitive FS paths leaked in the ORIGINAL source entry
            mp = self.SENSITIVE_PATH_RE.search(rs.raw)
            if mp:
                exposures.append({
                    "kind": "internal-path", "detail": mp.group(1), "source": rs.path,
                    "prov": Provenance.observation(
                        "sourcemap.sources", source=rs.map_url,
                        locator=f"sources entry: {rs.raw[:120]}", literal=mp.group(1),
                        limitations=["developer filesystem path exposed via source map"],
                        confidence_basis="path present verbatim in the served .map 'sources' array",
                    ),
                })
            lines = rs.content.split("\n")
            for ln, line in enumerate(lines, 1):
                # endpoints
                for pat in self.API_PATTERNS:
                    for m in pat.finditer(line):
                        ep = m.group(1) if m.lastindex else m.group(0)
                        if len(ep) <= 3 or ep.endswith((".js", ".css", ".png", ".svg", ".ico", ".map")):
                            continue
                        if self.FRAMEWORK_NOISE.match(ep):
                            continue
                        if not ep.startswith(("/", "http")) and "/" not in ep:
                            continue
                        if ep not in endpoints:
                            endpoints[ep] = {
                                "url": self._abs(result.target, ep), "raw": ep, "kind": "api",
                                "method": "GET", "source": rs.path, "line": ln,
                                "prov": Provenance.derivation(
                                    "js.api-pattern", source=rs.path, line=ln, literal=ep,
                                    confidence_basis="string literal parsed from recovered source",
                                ),
                            }
                # api base URLs
                for m in self.BASEURL_RE.finditer(line):
                    val = m.group(1)
                    if val and val not in endpoints:
                        endpoints[val] = {
                            "url": self._abs(result.target, val), "raw": val, "kind": "api-base",
                            "method": "GET", "source": rs.path, "line": ln,
                            "prov": Provenance.derivation("js.baseURL", source=rs.path, line=ln, literal=val),
                        }
                # client-side routes
                for pat in self.ROUTER_PATTERNS:
                    for m in pat.finditer(line):
                        rp = m.group(1)
                        if not rp or not rp.startswith("/") or len(rp) > 120:
                            continue
                        if rp not in routes:
                            routes[rp] = {
                                "path": rp, "source": rs.path, "line": ln,
                                "prov": Provenance.derivation(
                                    "router.route-def", source=rs.path, line=ln, literal=rp,
                                    limitations=["client-side route; not necessarily a server endpoint"],
                                ),
                            }
                # hosts
                for pat in self.HOST_PATTERNS:
                    for m in pat.finditer(line):
                        host = m.group(1)
                        if any(s in host for s in ("googleapis.com", "gstatic.com", "fonts.", "cdn.")):
                            continue
                        if host not in hosts:
                            hosts[host] = {"host": host, "source": rs.path, "line": ln}
                # dev comments
                dc = self.DEV_COMMENT_RE.search(line)
                if dc:
                    exposures.append({
                        "kind": "dev-comment", "detail": (dc.group(1) + ": " + dc.group(2).strip())[:140],
                        "source": rs.path,
                        "prov": Provenance.observation(
                            "source.comment", source=rs.path, line=ln, literal=dc.group(0)[:140],
                            limitations=["developer comment recovered from source map"],
                        ),
                    })
                # dev-only code
                for pat in self.DEBUG_PATTERNS:
                    if pat.search(line):
                        exposures.append({
                            "kind": "debug-flag", "detail": line.strip()[:140], "source": rs.path,
                            "prov": Provenance.inference(
                                "source.debug-pattern", source=rs.path, line=ln, literal=line.strip()[:140],
                                limitations=["dead/dev code may be unreachable at runtime"],
                            ),
                        })
                        break
            # secrets via the SHARED secret-rules engine
            for hit in secret_rules.scan_text(rs.content, source=rs.path):
                stype = hit["secret_type"]
                heuristic = stype in secret_rules.ENTROPY_REQUIRED_TYPES
                claim = Provenance.inference if heuristic else Provenance.observation
                prov = claim(
                    f"regex:{stype}", source=rs.path, line=hit["line_number"],
                    literal=mask_literal(hit["value"]),
                    confidence_basis=("high-entropy generic match" if heuristic
                                      else "structural provider-prefixed credential"),
                    limitations=["value masked"],
                )
                secrets.append({
                    "secret_type": stype, "masked": mask_literal(hit["value"]),
                    "severity": hit["severity"], "source": rs.path, "line": hit["line_number"],
                    "heuristic": heuristic, "prov": prov,
                })

        # hosts never seen live = candidate dead/hidden infrastructure
        for host, meta in hosts.items():
            netloc = urlparse(host if "://" in host else "//" + host).netloc or host
            bare = netloc.split("@")[-1].split(":")[0].lower()
            if bare and bare not in seen:
                exposures.append({
                    "kind": "unseen-host", "detail": host, "source": meta["source"],
                    "prov": Provenance.derivation(
                        "diff.host-not-live", source=meta["source"], line=meta.get("line"), literal=host,
                        limitations=["host referenced in source but absent from observed traffic; "
                                     "may be internal, dead, or reachable only server-side"],
                    ),
                })

        result.endpoints = list(endpoints.values())
        result.routes = list(routes.values())
        result.hosts = sorted(hosts.keys())
        result.secrets = secrets
        result.exposures = exposures
        result.stats["sources_parsed"] = parsed

    async def _fallback_minified(self, result, js_urls, seen, jsb) -> None:
        """No source maps: mine the minified bundles (reusing JSBundleAnalyzer),
        tagging everything INFERENCE."""
        endpoints: Dict[str, Dict] = {}
        secrets: List[Dict] = []
        for url in js_urls[: self.MAX_BUNDLES]:
            try:
                resp = await self.get(url)
                if resp.status_code != 200:
                    continue
                intel = jsb._analyze_bundle(url, resp.text)
            except Exception:
                continue
            for ep in intel.api_endpoints:
                if ep not in endpoints:
                    endpoints[ep] = {
                        "url": self._abs(result.target, ep), "raw": ep, "kind": "api",
                        "method": "GET", "source": url, "line": None,
                        "prov": Provenance.inference(
                            "minified.api-pattern", source=url, literal=ep,
                            limitations=["extracted from minified bundle; no source map"],
                        ),
                    }
            for stype, val in intel.potential_secrets:
                heuristic = True
                secrets.append({
                    "secret_type": stype, "masked": mask_literal(val),
                    "severity": Severity.MEDIUM, "source": url, "line": None,
                    "heuristic": True,
                    "prov": Provenance.inference(
                        f"minified:{stype}", source=url, literal=mask_literal(val),
                        limitations=["minified bundle; original source unavailable", "value masked"],
                    ),
                })
        result.endpoints = list(endpoints.values())
        result.secrets = secrets

    # =========================================================================
    # FINDINGS
    # =========================================================================
    def _build_findings(self, result: SPAReconResult) -> List[Finding]:
        findings: List[Finding] = []
        base = result.target

        if result.maps:
            sample_sources = [s.path for s in result.sources[: self.MAX_LIST_PER_FINDING]]
            prov = Provenance.observation(
                "sourcemap.exposed", source=result.maps[0],
                literal=f"{len(result.maps)} map(s)",
                confidence_basis="source map(s) served with HTTP 200 and parsed successfully",
                limitations=["exposes original (un-minified) source to anyone"],
            )
            for mu in result.maps[1:5]:
                prov.with_evidence(source=mu, locator="source map", literal="200 OK")
            findings.append(self.create_finding(
                title="Source Maps Publicly Exposed",
                severity=Severity.LOW, confidence=Confidence.FIRM, url=base,
                description=(
                    f"{len(result.maps)} source map(s) are publicly served, recovering "
                    f"{len(result.sources)} original source file(s). Original client source "
                    f"discloses internal structure, routes, and sometimes secrets."
                ),
                evidence={"maps": result.maps[: self.MAX_LIST_PER_FINDING],
                          "recovered_sources": sample_sources,
                          "source_count": len(result.sources)},
                remediation="Stop deploying .map files to production, or restrict them by auth/IP.",
                provenance=prov.to_dict(),
            ))

        if result.endpoints or result.routes:
            eps = [e["raw"] for e in result.endpoints[: self.MAX_LIST_PER_FINDING]]
            rts = [r["path"] for r in result.routes[: self.MAX_LIST_PER_FINDING]]
            heuristic = not result.recovered
            prov = (Provenance.inference if heuristic else Provenance.derivation)(
                "spa.route-inventory", source=base,
                literal=f"{len(result.endpoints)} endpoints / {len(result.routes)} routes",
                confidence_basis=("parsed from minified bundles" if heuristic
                                  else "parsed from recovered original sources"),
                limitations=(["client-side routes are not guaranteed server endpoints"]
                             + (["no source map; heuristic extraction"] if heuristic else [])),
            )
            findings.append(self.create_finding(
                title="API Routes Disclosed",
                severity=Severity.INFO,
                confidence=Confidence.TENTATIVE if heuristic else Confidence.FIRM,
                url=base,
                description=(
                    f"Recovered {len(result.endpoints)} endpoint(s) and {len(result.routes)} "
                    f"client-side route(s) from the application's JavaScript."
                ),
                evidence={"endpoints": eps, "routes": rts,
                          "endpoint_count": len(result.endpoints),
                          "route_count": len(result.routes)},
                remediation="Review exposed endpoints for authorization gaps; routes reveal app structure.",
                provenance=prov.to_dict(),
            ))

        for sec in result.secrets[: self.MAX_LIST_PER_FINDING]:
            findings.append(self.create_finding(
                title=f"Secret in Client JS: {sec['secret_type']}",
                severity=sec["severity"],
                confidence=Confidence.TENTATIVE if sec["heuristic"] else Confidence.FIRM,
                url=base,
                description=(
                    f"A {sec['secret_type']} was found in client-side JavaScript "
                    f"({sec['source']}" + (f":{sec['line']}" if sec['line'] else "") + ")."
                ),
                evidence={"type": sec["secret_type"], "value_masked": sec["masked"],
                          "source": sec["source"], "line": sec["line"]},
                remediation="Rotate the credential and move secrets server-side; never ship them to the browser.",
                provenance=sec["prov"].to_dict(),
            ))
        if len(result.secrets) > self.MAX_LIST_PER_FINDING:
            self.log(f"{len(result.secrets) - self.MAX_LIST_PER_FINDING} further secrets not emitted as findings", "info")

        if result.exposures:
            by_kind: Dict[str, List[Dict]] = {}
            for ex in result.exposures:
                by_kind.setdefault(ex["kind"], []).append(ex)
            for kind, items in by_kind.items():
                head = items[0]
                findings.append(self.create_finding(
                    title={
                        "internal-path": "Developer Filesystem Path Exposed in Source Map",
                        "dev-comment": "Developer Comments Exposed in Recovered Source",
                        "debug-flag": "Debug / Dev-only Code in Client Bundle",
                        "unseen-host": "Internal / Unseen Host Referenced in Client JS",
                    }.get(kind, f"Client-side exposure: {kind}"),
                    severity=Severity.INFO, confidence=Confidence.TENTATIVE, url=base,
                    description=f"{len(items)} {kind} finding(s) recovered from client-side sources.",
                    evidence={"kind": kind,
                              "items": [{"detail": i["detail"], "source": i["source"]}
                                        for i in items[: self.MAX_LIST_PER_FINDING]]},
                    provenance=head["prov"].to_dict(),
                ))

        # Explicit UNKNOWNs — never let "couldn't determine" read as "clean".
        for unk in result.unknowns:
            findings.append(self.create_finding(
                title="SPA Recon: Undetermined",
                severity=Severity.INFO, confidence=Confidence.TENTATIVE, url=base,
                description=unk,
                evidence={"unknown": unk, "stats": result.stats},
                provenance=Provenance.unknown(unk, method="spa_recon").to_dict(),
            ))
        return findings

    # =========================================================================
    # HELPERS
    # =========================================================================
    @staticmethod
    def _normalize(target: str) -> str:
        t = (target or "").strip()
        if not t:
            return t
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        p = urlparse(t)
        return f"{p.scheme}://{p.netloc}" + (p.path if p.path and p.path != "/" else "")

    @staticmethod
    def _abs(base: str, ep: str) -> str:
        if ep.startswith(("http://", "https://", "ws://", "wss://")):
            return ep
        if ep.startswith("/"):
            return urljoin(base, ep)
        return ep
