"""
BEATRIX — recon engine for the Suite's Recon module.

The free, keyless parts of a recon-ng-style workflow, as a set of **components**
that each take a target and return typed **entities** to merge into a per-project
workspace. No paid services: RDAP/WHOIS/DNS/Certificate-Transparency and the
existing Cloudflare origin-IP engine, all keyless.

Each component: ``run(target, opts, on_log) -> {"entities": [...], "log": [...]}``.
Entity kinds (merged by ``key`` in the store): domain, subdomain, ip, netblock,
contact, origin.

Reuses, rather than reimplements:
- ``beatrix.core.recon_helpers``: dns_recon, whois_asn_lookup, extract_ssl_sans.
- ``beatrix.scanners.origin_ip_discovery.OriginIPDiscovery``: the whole free
  CDN-bypass engine (crt.sh, viewdns, MX, Host-header verification).
Async helpers are driven with ``asyncio.run`` from the component thread.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional

import requests

Log = Callable[[str], None]

_UA = "beatrix-recon"
_CDN_ORGS = ("cloudflare", "akamai", "fastly", "amazon", "aws", "google",
             "microsoft", "azure", "incapsula", "imperva", "sucuri", "stackpath")
_DEFAULT_SUBS = (
    "www mail smtp pop imap webmail ftp sftp cpanel whm ns1 ns2 dns dev staging "
    "test qa uat api api-dev admin portal vpn remote git gitlab jenkins ci "
    "jira confluence wiki blog shop store app apps mobile m cdn static assets "
    "img images media files download downloads db mysql postgres redis mx mx1 "
    "mx2 origin direct backend internal intranet corp secure login sso auth "
    "dashboard monitor grafana kibana status demo beta new old legacy support "
    "help docs email autodiscover owa exchange lync gateway proxy"
).split()


def _ent(kind: str, key: str, **fields: Any) -> Dict[str, Any]:
    e = {"kind": kind, "key": key}
    e.update({k: v for k, v in fields.items() if v not in (None, "", [], {})})
    return e


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _cdn_name(text: str) -> Optional[str]:
    t = (text or "").lower()
    for c in _CDN_ORGS:
        if c in t:
            return "Cloudflare" if c == "cloudflare" else c.title()
    return None


# ── RDAP (IP + domain ownership) ──────────────────────────────────────────────
def _vcard_fields(entity: Dict[str, Any]) -> Dict[str, str]:
    """Pull fn/email out of an RDAP entity's jCard."""
    out: Dict[str, str] = {}
    try:
        for item in entity.get("vcardArray", ["", []])[1]:
            if item[0] == "fn":
                out["fn"] = item[3]
            elif item[0] == "email":
                out["email"] = item[3]
    except Exception:  # noqa: BLE001
        pass
    return out


def _walk_entities(entities: List[Dict[str, Any]], want_roles: tuple) -> List[Dict[str, Any]]:
    found = []
    for e in entities or []:
        roles = [r.lower() for r in (e.get("roles") or [])]
        if any(r in roles for r in want_roles):
            vc = _vcard_fields(e)
            found.append({"roles": roles, **vc})
        found += _walk_entities(e.get("entities") or [], want_roles)
    return found


def _rdap_get(url: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(url, headers={"User-Agent": _UA, "Accept": "application/rdap+json"},
                         timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return None


def comp_rdap_ip(ip: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    ents: List[Dict[str, Any]] = []
    log(f"RDAP lookup for {ip} …")
    d = _rdap_get(f"https://rdap.org/ip/{ip}")
    if not d:
        return {"entities": [], "log": [f"no RDAP data for {ip}"]}
    name = d.get("name") or ""
    country = d.get("country") or ""
    # netblock CIDR
    cidr = ""
    if d.get("cidr0_cidrs"):
        c0 = d["cidr0_cidrs"][0]
        pref = c0.get("v4prefix") or c0.get("v6prefix")
        if pref and "length" in c0:
            cidr = f"{pref}/{c0['length']}"
    elif d.get("startAddress") and d.get("endAddress"):
        try:
            nets = list(ipaddress.summarize_address_range(
                ipaddress.ip_address(d["startAddress"]), ipaddress.ip_address(d["endAddress"])))
            cidr = str(nets[0]) if nets else ""
        except Exception:  # noqa: BLE001
            cidr = ""
    abuse = ""
    org = name
    for e in _walk_entities(d.get("entities") or [], ("abuse",)):
        if e.get("email"):
            abuse = e["email"]
            break
    for e in _walk_entities(d.get("entities") or [], ("registrant", "administrative", "owner")):
        if e.get("fn"):
            org = e["fn"]
            break
    cdn = _cdn_name(org or name)
    ents.append(_ent("ip", ip, org=org, netblock=cidr, country=country, abuse=abuse,
                     cdn=cdn, source="RDAP"))
    if cidr:
        ents.append(_ent("netblock", cidr, org=org, country=country, source="RDAP"))
    if abuse:
        ents.append(_ent("contact", abuse, role="abuse", source=f"RDAP {ip}"))
    log(f"  {ip}: {org or '?'}{' / ' + cidr if cidr else ''}{' [' + cdn + ']' if cdn else ''}")
    return {"entities": ents, "log": []}


def comp_rdap_domain(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    ents: List[Dict[str, Any]] = []
    log(f"RDAP domain lookup for {domain} …")
    d = _rdap_get(f"https://rdap.org/domain/{domain}")
    if not d:
        return {"entities": [], "log": [f"no RDAP data for {domain}"]}
    registrar = ""
    for e in _walk_entities(d.get("entities") or [], ("registrar",)):
        if e.get("fn"):
            registrar = e["fn"]
            break
    events = {ev.get("eventAction"): ev.get("eventDate") for ev in d.get("events") or []}
    for e in _walk_entities(d.get("entities") or [], ("registrant", "abuse", "administrative", "technical")):
        if e.get("email"):
            ents.append(_ent("contact", e["email"],
                             role=(e.get("roles") or ["contact"])[0], source=f"RDAP {domain}"))
    ents.append(_ent("domain", domain, registrar=registrar,
                     registered=events.get("registration"), expires=events.get("expiration"),
                     source="RDAP"))
    log(f"  {domain}: registrar={registrar or '?'} registered={events.get('registration', '?')}")
    return {"entities": ents, "log": []}


# ── Certificate Transparency (crt.sh) ─────────────────────────────────────────
def comp_crtsh(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    log(f"Querying crt.sh for %.{domain} …")
    names: set = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         headers={"User-Agent": _UA}, timeout=30)
        if r.status_code == 200:
            for row in r.json():
                for nm in (row.get("name_value") or "").splitlines():
                    nm = nm.strip().lstrip("*.").lower()
                    if nm.endswith(domain) and _valid_host(nm):
                        names.add(nm)
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"crt.sh error: {e}"]}
    log(f"  crt.sh: {len(names)} unique names")
    return {"entities": [_ent("subdomain", n, source="crt.sh") for n in sorted(names)], "log": []}


def _valid_host(h: str) -> bool:
    return bool(re.match(r"^[a-z0-9._-]+$", h)) and "." in h and len(h) <= 253


# ── DNS records (reuse dns_recon) ─────────────────────────────────────────────
def comp_dns_records(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    from beatrix.core import recon_helpers
    log(f"DNS records for {domain} …")
    data = asyncio.run(recon_helpers.dns_recon(domain))
    ents: List[Dict[str, Any]] = []
    for ip in data.get("a_records", []) + data.get("aaaa_records", []):
        ents.append(_ent("ip", ip, source=f"A/AAAA {domain}"))
    for mx in data.get("mx_records", []):
        host = mx[0] if isinstance(mx, (list, tuple)) else str(mx)
        if _valid_host(host):
            ents.append(_ent("subdomain", host.lower(), source="MX"))
    for ns in data.get("ns_records", []):
        if _valid_host(str(ns)):
            ents.append(_ent("subdomain", str(ns).lower().rstrip("."), source="NS"))
    for sd in data.get("subdomains_from_dns", []):
        if _valid_host(str(sd)):
            ents.append(_ent("subdomain", str(sd).lower(), source="DNS"))
    # SPF ip4: ranges are strong origin hints.
    for txt in data.get("txt_records", []):
        for m in re.findall(r"ip4:([0-9.]+(?:/\d+)?)", str(txt)):
            if "/" in m:
                ents.append(_ent("netblock", m, org="(from SPF)", source="SPF"))
            else:
                ents.append(_ent("ip", m, source="SPF"))
    log(f"  {len(data.get('a_records', []))} A, {len(data.get('mx_records', []))} MX, "
        f"{len(data.get('ns_records', []))} NS")
    return {"entities": ents, "log": []}


# ── DNS brute force ───────────────────────────────────────────────────────────
def _resolve(host: str, timeout: float = 3.0) -> List[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return list({r[4][0] for r in socket.getaddrinfo(host, None)})
    except Exception:  # noqa: BLE001
        return []


def comp_dns_brute(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    words = opts.get("words") or _DEFAULT_SUBS
    if isinstance(words, str):
        words = [w.strip() for w in re.split(r"[\s,]+", words) if w.strip()]
    words = words[:5000]
    # Wildcard detection: a random label that resolves means * is wildcarded.
    wildcard = set(_resolve(f"zzzzrandom-beatrix-wildcard.{domain}"))
    if wildcard:
        log(f"  wildcard DNS detected ({', '.join(sorted(wildcard))}) — filtering matches")
    log(f"Brute-forcing {len(words)} subdomains of {domain} …")
    ents: List[Dict[str, Any]] = []
    found = 0
    with ThreadPoolExecutor(max_workers=40) as ex:
        results = ex.map(lambda w: (w, _resolve(f"{w}.{domain}")), words)
        for w, ips in results:
            ips = [i for i in ips if i not in wildcard]
            if ips:
                found += 1
                ents.append(_ent("subdomain", f"{w}.{domain}", ips=ips, source="brute"))
                for ip in ips:
                    ents.append(_ent("ip", ip, source=f"brute {w}.{domain}"))
    log(f"  {found} subdomains resolved")
    return {"entities": ents, "log": []}


# ── Reverse-DNS netblock sweep ────────────────────────────────────────────────
def _ptr(ip: str, timeout: float = 3.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:  # noqa: BLE001
        return ""


def comp_reverse_sweep(cidr: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"entities": [], "log": [f"bad CIDR: {e}"]}
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    if len(hosts) > 4096:
        log(f"  {cidr} has {len(hosts)} addresses — capping sweep at 4096")
        hosts = hosts[:4096]
    log(f"Reverse-DNS sweep of {cidr} ({len(hosts)} addresses) …")
    ents: List[Dict[str, Any]] = []
    found = 0
    with ThreadPoolExecutor(max_workers=50) as ex:
        results = ex.map(lambda ip: (str(ip), _ptr(str(ip))), hosts)
        for ip, name in results:
            if name:
                found += 1
                ents.append(_ent("ip", ip, ptr=name, source=f"rDNS {cidr}"))
                if _valid_host(name.lower()):
                    ents.append(_ent("subdomain", name.lower().rstrip("."), ips=[ip], source="rDNS"))
    log(f"  {found} addresses with PTR records")
    return {"entities": ents, "log": []}


# ── Zone transfer (AXFR) ──────────────────────────────────────────────────────
def comp_zone_transfer(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    try:
        import dns.query
        import dns.resolver
        import dns.zone
    except Exception:  # noqa: BLE001
        return {"entities": [], "log": ["dnspython not available"]}
    ents: List[Dict[str, Any]] = []
    try:
        ns_list = [str(r).rstrip(".") for r in dns.resolver.resolve(domain, "NS")]
    except Exception:  # noqa: BLE001
        return {"entities": [], "log": ["could not list NS records"]}
    for ns in ns_list:
        log(f"  AXFR {domain} @ {ns} …")
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8))
            for name in z.nodes.keys():
                fqdn = str(name) + ("" if str(name).endswith(".") else "." + domain) \
                    if str(name) != "@" else domain
                fqdn = fqdn.rstrip(".").lower()
                if _valid_host(fqdn):
                    ents.append(_ent("subdomain", fqdn, source=f"AXFR {ns}"))
            log(f"    zone transfer SUCCEEDED from {ns} — misconfiguration")
        except Exception:  # noqa: BLE001 — refused transfer is the normal case
            log(f"    refused by {ns}")
    return {"entities": ents, "log": []}


# ── TLS SAN (reuse extract_ssl_sans) ──────────────────────────────────────────
def comp_tls_san(host: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    from beatrix.core import recon_helpers
    log(f"Reading TLS certificate SANs from {host} …")
    try:
        sans = asyncio.run(recon_helpers.extract_ssl_sans(host))
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"TLS error: {e}"]}
    ents = [_ent("subdomain", s.lstrip("*.").lower(), source="TLS SAN")
            for s in sans if _valid_host(s.lstrip("*.").lower())]
    log(f"  {len(ents)} SAN names")
    return {"entities": ents, "log": []}


# ── ASN / Team Cymru (reuse whois_asn_lookup) ─────────────────────────────────
def comp_asn(target: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    from beatrix.core import recon_helpers
    ip = target if _is_ip(target) else ""
    domain = "" if ip else target
    log(f"ASN lookup for {target} …")
    data = asyncio.run(recon_helpers.whois_asn_lookup(domain, ip))
    ents: List[Dict[str, Any]] = []
    resolved_ip = ip or (_resolve(domain)[:1] or [""])[0]
    if resolved_ip:
        ents.append(_ent("ip", resolved_ip, asn=data.get("asn"), asn_org=data.get("asn_org"),
                         cdn=_cdn_name(data.get("asn_org") or ""), source="ASN"))
    for rng in data.get("ip_ranges", []):
        ents.append(_ent("netblock", rng, org=data.get("asn_org"), source="ASN"))
    log(f"  ASN {data.get('asn') or '?'} — {data.get('asn_org') or '?'}")
    return {"entities": ents, "log": []}


# ── WHOIS (binary) ────────────────────────────────────────────────────────────
def comp_whois(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    log(f"WHOIS {domain} …")
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True,
                             timeout=20).stdout
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"whois error: {e}"]}
    emails = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", out)))
    ents = [_ent("contact", e, role="whois", source=f"WHOIS {domain}") for e in emails
            if not e.lower().endswith((".arpa", "example.com"))]
    reg = re.search(r"Registrar:\s*(.+)", out)
    created = re.search(r"Creat(?:ion|ed)(?:\s*Date)?:\s*(.+)", out, re.I)
    ents.append(_ent("domain", domain, registrar=(reg.group(1).strip() if reg else None),
                     registered=(created.group(1).strip() if created else None), source="WHOIS"))
    log(f"  {len(emails)} email(s)")
    return {"entities": ents, "log": []}


# ── Resolve / reverse (quick) ─────────────────────────────────────────────────
def comp_resolve(host: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    ips = _resolve(host)
    log(f"{host} → {', '.join(ips) if ips else '(no record)'}")
    ents = [_ent("subdomain", host.lower(), ips=ips, source="resolve")] if ips else []
    ents += [_ent("ip", ip, source=f"resolve {host}") for ip in ips]
    return {"entities": ents, "log": []}


def comp_reverse(ip: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    name = _ptr(ip)
    log(f"{ip} → {name or '(no PTR)'}")
    ents = [_ent("ip", ip, ptr=name, source="reverse")]
    if name and _valid_host(name.lower()):
        ents.append(_ent("subdomain", name.lower().rstrip("."), ips=[ip], source="reverse PTR"))
    return {"entities": ents, "log": []}


# ── Origin-IP discovery (reuse OriginIPDiscovery) ─────────────────────────────
def comp_origin_ip(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    from beatrix.scanners.origin_ip_discovery import OriginIPDiscovery
    log(f"Hunting origin IP for {domain} (crt.sh, DNS history, MX, Host-header verify) …")
    try:
        result = asyncio.run(OriginIPDiscovery().discover(domain))
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"origin discovery error: {e}"]}
    ents: List[Dict[str, Any]] = []
    if result.cdn_detected:
        log(f"  CDN in front: {result.cdn_detected}")
    for info in result.discovered_ips:
        ip = info.get("ip")
        if not ip:
            continue
        ents.append(_ent("origin", ip, domain=domain,
                         score=round(float(info.get("confidence", 0)) * 100),
                         verified=bool(info.get("validated")),
                         evidence=info.get("source", ""), source="origin-ip"))
        ents.append(_ent("ip", ip, source=f"origin candidate ({info.get('source', '')})"))
    verified = [e for e in ents if e["kind"] == "origin" and e.get("verified")]
    log(f"  {len([e for e in ents if e['kind']=='origin'])} candidate origin(s), "
        f"{len(verified)} verified via Host header")
    if not ents:
        log("  no origin leaked — a well-locked-down origin can be un-findable without paid data")
    return {"entities": ents, "log": []}


# ── Passive sources: keyless CT / passive-DNS / archive / exposure APIs ────────
# All free and key-free, same spirit as crt.sh: one HTTP GET, parse, return typed
# entities. Every one degrades gracefully (empty + a log line) on error, non-200,
# rate-limit or malformed body — a sweep must never die on a flaky third party.
def _host_from_url(u: str) -> str:
    """Bare hostname from a URL or host[:port] string ("" if none)."""
    try:
        from urllib.parse import urlsplit
        netloc = urlsplit(u if "//" in u else "//" + u).netloc or u
        return netloc.split("@")[-1].split(":")[0].strip().strip(".").lower()
    except Exception:  # noqa: BLE001
        return ""


def comp_certspotter(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    log(f"Querying CertSpotter CT for {domain} …")
    names: set = set()
    try:
        r = requests.get("https://api.certspotter.com/v1/issuances",
                         params={"domain": domain, "include_subdomains": "true",
                                 "expand": "dns_names"},
                         headers={"User-Agent": _UA}, timeout=30)
        if r.status_code == 429:
            return {"entities": [], "log": ["CertSpotter rate-limited (HTTP 429) — retry later"]}
        if r.status_code != 200:
            return {"entities": [], "log": [f"CertSpotter HTTP {r.status_code}"]}
        for iss in r.json() or []:
            for nm in iss.get("dns_names") or []:
                nm = str(nm).strip().lstrip("*.").lower()
                if nm.endswith(domain) and _valid_host(nm):
                    names.add(nm)
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"CertSpotter error: {e}"]}
    log(f"  CertSpotter: {len(names)} unique names")
    return {"entities": [_ent("subdomain", n, source="CertSpotter") for n in sorted(names)], "log": []}


def comp_otx(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    log(f"Querying AlienVault OTX passive DNS for {domain} …")
    ents: List[Dict[str, Any]] = []
    seen: set = set()
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers={"User-Agent": _UA}, timeout=25)
        if r.status_code != 200:
            return {"entities": [], "log": [f"OTX HTTP {r.status_code}"]}
        rows = (r.json() or {}).get("passive_dns") or []
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"OTX error: {e}"]}
    for row in rows[:3000]:
        host = str(row.get("hostname") or "").strip().strip(".").lower()
        addr = str(row.get("address") or "").strip()
        if host and host.endswith(domain) and _valid_host(host) and host not in seen:
            seen.add(host)
            ents.append(_ent("subdomain", host, ips=[addr] if _is_ip(addr) else None, source="OTX"))
        if _is_ip(addr):
            ents.append(_ent("ip", addr, source=f"OTX {host}" if host else "OTX"))
    log(f"  OTX: {len(seen)} passive-DNS hostnames")
    return {"entities": ents, "log": []}


def comp_hackertarget(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    log(f"Querying HackerTarget hostsearch for {domain} …")
    ents: List[Dict[str, Any]] = []
    try:
        r = requests.get("https://api.hackertarget.com/hostsearch/",
                         params={"q": domain}, headers={"User-Agent": _UA}, timeout=20)
        body = r.text or ""
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"HackerTarget error: {e}"]}
    low = body.lower()
    if ("api count exceeded" in low or "api limit" in low
            or low.startswith("error") or "," not in body):
        return {"entities": [], "log": ["HackerTarget: no data or rate-limited (free-tier quota)"]}
    found = 0
    for line in body.splitlines():
        parts = line.split(",")
        if len(parts) != 2:
            continue
        host, ip = parts[0].strip().strip(".").lower(), parts[1].strip()
        if host and host.endswith(domain) and _valid_host(host):
            found += 1
            ents.append(_ent("subdomain", host, ips=[ip] if _is_ip(ip) else None,
                             source="HackerTarget"))
        if _is_ip(ip):
            ents.append(_ent("ip", ip, source=f"HackerTarget {host}"))
    log(f"  HackerTarget: {found} hostnames")
    return {"entities": ents, "log": []}


def comp_wayback(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    log(f"Querying the Wayback Machine (CDX) for *.{domain} …")
    names: set = set()
    try:
        r = requests.get("http://web.archive.org/cdx/search/cdx",
                         params={"url": f"*.{domain}/*", "output": "json", "fl": "original",
                                 "collapse": "urlkey", "limit": "20000"},
                         headers={"User-Agent": _UA}, timeout=40)
        if r.status_code != 200:
            return {"entities": [], "log": [f"Wayback HTTP {r.status_code}"]}
        rows = r.json() or []
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"Wayback error: {e}"]}
    data_rows = rows[1:] if rows and isinstance(rows[0], list) and "original" in rows[0] else rows
    for row in data_rows:
        url = row[0] if isinstance(row, (list, tuple)) and row else str(row)
        host = _host_from_url(url)
        if host and host.endswith(domain) and _valid_host(host):
            names.add(host)
    log(f"  Wayback: {len(names)} unique hostnames from archived URLs")
    return {"entities": [_ent("subdomain", n, source="Wayback") for n in sorted(names)], "log": []}


def comp_rapiddns(domain: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    log(f"Scraping RapidDNS for {domain} …")
    names: set = set()
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}", params={"full": "1"},
                         headers={"User-Agent": _UA}, timeout=25)
        if r.status_code != 200:
            return {"entities": [], "log": [f"RapidDNS HTTP {r.status_code}"]}
        # Best-effort scrape: pull any <something>.<domain> host token from the HTML table.
        for m in re.findall(r"([a-z0-9][a-z0-9._-]*\." + re.escape(domain) + r")\b", r.text.lower()):
            nm = m.strip(".").lstrip("*.")
            if _valid_host(nm):
                names.add(nm)
        names.discard(domain)
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"RapidDNS error: {e}"]}
    log(f"  RapidDNS: {len(names)} unique names")
    return {"entities": [_ent("subdomain", n, source="RapidDNS") for n in sorted(names)], "log": []}


def comp_shodan_internetdb(ip: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    if not _is_ip(ip):
        return {"entities": [], "log": [f"not an IP: {ip}"]}
    log(f"Querying Shodan InternetDB (passive, keyless) for {ip} …")
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}",
                         headers={"User-Agent": _UA, "Accept": "application/json"}, timeout=20)
        if r.status_code == 404:
            log(f"  {ip}: no InternetDB record")
            return {"entities": [], "log": []}
        if r.status_code != 200:
            return {"entities": [], "log": [f"InternetDB HTTP {r.status_code}"]}
        d = r.json() or {}
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"InternetDB error: {e}"]}
    ports = sorted({int(p) for p in d.get("ports") or [] if str(p).isdigit()})
    vulns = sorted({str(v) for v in d.get("vulns") or []})
    cpes = sorted({str(c) for c in d.get("cpes") or []})
    hostnames = [str(h).strip(".").lower() for h in d.get("hostnames") or []]
    ents: List[Dict[str, Any]] = [
        _ent("ip", ip, ports=ports, vulns=vulns, cpes=cpes, source="Shodan InternetDB")]
    for h in hostnames:
        if _valid_host(h):
            ents.append(_ent("subdomain", h, ips=[ip], source="Shodan InternetDB"))
    log(f"  {ip}: {len(ports)} port(s), {len(vulns)} known CVE(s), {len(hostnames)} hostname(s)")
    return {"entities": ents, "log": []}


def comp_geoip(ip: str, opts: Dict[str, Any], log: Log) -> Dict[str, Any]:
    if not _is_ip(ip):
        return {"entities": [], "log": [f"not an IP: {ip}"]}
    log(f"GeoIP / ISP enrichment for {ip} (ip-api.com) …")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}",
                         params={"fields": "status,message,country,countryCode,regionName,"
                                           "city,isp,org,as,asname,reverse,query"},
                         headers={"User-Agent": _UA}, timeout=15)
        d = r.json() or {}
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"GeoIP error: {e}"]}
    if d.get("status") != "success":
        return {"entities": [], "log": [f"GeoIP: {d.get('message') or 'lookup failed'}"]}
    org = d.get("org") or d.get("isp") or d.get("asname") or ""
    m = re.match(r"AS(\d+)", str(d.get("as") or ""))
    asn = "AS" + m.group(1) if m else ""
    country = d.get("countryCode") or d.get("country") or ""
    loc = " / ".join(x for x in [d.get("city"), d.get("regionName"), d.get("country")] if x)
    ents = [_ent("ip", ip, org=org, country=country, asn=asn,
                 asn_org=d.get("asname") or d.get("isp"),
                 cdn=_cdn_name(f"{org} {d.get('isp') or ''} {d.get('asname') or ''}"),
                 ptr=d.get("reverse") or None, source="ip-api")]
    log(f"  {ip}: {org or '?'} · {loc or country or '?'}{' · ' + asn if asn else ''}")
    return {"entities": ents, "log": []}


# ── Registry ──────────────────────────────────────────────────────────────────
# needs: the kind of target the component expects (domain | ip | cidr | host).
COMPONENTS: Dict[str, Dict[str, Any]] = {
    "dns_records":   {"label": "DNS records (A/MX/NS/TXT/SOA)", "cluster": "DNS & Hosts", "needs": "domain", "fn": comp_dns_records},
    "dns_brute":     {"label": "DNS brute-force (subdomains)", "cluster": "DNS & Hosts", "needs": "domain", "fn": comp_dns_brute, "opts": ["words"]},
    "zone_transfer": {"label": "Zone transfer (AXFR)", "cluster": "DNS & Hosts", "needs": "domain", "fn": comp_zone_transfer},
    "resolve":       {"label": "Resolve host → IP", "cluster": "DNS & Hosts", "needs": "host", "fn": comp_resolve},
    "reverse":       {"label": "Reverse DNS (IP → PTR)", "cluster": "DNS & Hosts", "needs": "ip", "fn": comp_reverse},
    "crtsh":         {"label": "Certificate Transparency (crt.sh)", "cluster": "Subdomains", "needs": "domain", "fn": comp_crtsh},
    "certspotter":   {"label": "Certificate Transparency (CertSpotter)", "cluster": "Subdomains", "needs": "domain", "fn": comp_certspotter},
    "tls_san":       {"label": "TLS certificate SANs", "cluster": "Subdomains", "needs": "host", "fn": comp_tls_san},
    "otx":           {"label": "Passive DNS — AlienVault OTX", "cluster": "Passive DNS & archives", "needs": "domain", "fn": comp_otx},
    "hackertarget":  {"label": "Passive DNS — HackerTarget", "cluster": "Passive DNS & archives", "needs": "domain", "fn": comp_hackertarget},
    "wayback":       {"label": "Wayback Machine (archived hosts)", "cluster": "Passive DNS & archives", "needs": "domain", "fn": comp_wayback},
    "rapiddns":      {"label": "RapidDNS (scraped subdomains)", "cluster": "Passive DNS & archives", "needs": "domain", "fn": comp_rapiddns},
    "shodan_internetdb": {"label": "Exposed ports & CVEs (Shodan InternetDB)", "cluster": "Exposure", "needs": "ip", "fn": comp_shodan_internetdb},
    "rdap_ip":       {"label": "RDAP — IP ownership", "cluster": "Ownership", "needs": "ip", "fn": comp_rdap_ip},
    "rdap_domain":   {"label": "RDAP — domain registration", "cluster": "Ownership", "needs": "domain", "fn": comp_rdap_domain},
    "asn":           {"label": "ASN / netblock", "cluster": "Ownership", "needs": "host", "fn": comp_asn},
    "whois":         {"label": "WHOIS (contacts)", "cluster": "Ownership", "needs": "domain", "fn": comp_whois},
    "geoip":         {"label": "GeoIP / ISP (ip-api.com)", "cluster": "Ownership", "needs": "ip", "fn": comp_geoip},
    "reverse_sweep": {"label": "Reverse-DNS sweep (CIDR → hosts)", "cluster": "Netblock", "needs": "cidr", "fn": comp_reverse_sweep},
    "origin_ip":     {"label": "Origin-IP discovery (CDN bypass)", "cluster": "Origin-IP", "needs": "domain", "fn": comp_origin_ip},
}


def component_catalog() -> List[Dict[str, Any]]:
    return [{"name": k, "label": v["label"], "cluster": v["cluster"], "needs": v["needs"],
             "opts": v.get("opts", [])} for k, v in COMPONENTS.items()]


def run_component(name: str, target: str, opts: Optional[Dict[str, Any]] = None,
                  on_log: Optional[Log] = None) -> Dict[str, Any]:
    comp = COMPONENTS.get(name)
    log: Log = on_log or (lambda _m: None)
    if comp is None:
        return {"entities": [], "log": [f"unknown component: {name}"], "error": "unknown component"}
    target = (target or "").strip()
    if not target:
        return {"entities": [], "log": [], "error": "no target"}
    try:
        res = comp["fn"](target, opts or {}, log)
        res.setdefault("entities", [])
        res.setdefault("log", [])
        res["error"] = None
        return res
    except Exception as e:  # noqa: BLE001
        return {"entities": [], "log": [f"{type(e).__name__}: {e}"], "error": str(e)}
