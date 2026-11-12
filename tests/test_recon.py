"""
Regression tests for the Suite's OSINT recon engine and Full Sweep.

Covers the fixes for: the reverse-DNS netblock sweep materializing whole networks (an
IPv6 /32 OOM-killed the suite mid-sweep), the process-wide socket timeout the DNS
helpers used to set, Stop not landing until a whole netblock had been swept, TLS SANs
always coming back empty (CERT_NONE makes getpeercert() return {}), WHOIS failing
without the ``whois`` binary, and SPA Recon runs never lighting the nav scanning glow.

Everything is offline: DNS and WHOIS servers are faked, and the TLS test talks to a
throwaway server on 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import socket
import ssl
import threading
import time
import types

import pytest

import beatrix.cli.suite as suite_mod
from beatrix.cli.ghost_web import _Broker
from beatrix.cli.suite import SuiteServer
from beatrix.core import recon_engine, recon_helpers


def _fake_ptr(monkeypatch, delay: float = 0.0, names=None):
    """Replace the PTR lookup with a recorder; returns the list of IPs looked up."""
    calls, lock = [], threading.Lock()

    def ptr(ip):
        with lock:
            calls.append(ip)
        if delay:
            time.sleep(delay)
        return (names or {}).get(ip, "")

    monkeypatch.setattr(recon_engine, "_ptr", ptr)
    return calls


def _until(pred, timeout: float = 10.0) -> float:
    t0 = time.monotonic()
    while not pred():
        if time.monotonic() - t0 > timeout:
            pytest.fail("condition not reached in %.0fs" % timeout)
        time.sleep(0.01)
    return time.monotonic() - t0


def _keys(res):
    return {(e["kind"], e["key"]) for e in res["entities"]}


# ── Reverse-DNS netblock sweep ────────────────────────────────────────────────

@pytest.mark.parametrize("cidr", ["2606:4700::/32", "2001:db8::/115", "::/0"])
def test_reverse_sweep_skips_ipv6_blocks_too_big_to_walk(monkeypatch, cidr):
    calls = _fake_ptr(monkeypatch)
    logs = []
    t0 = time.monotonic()
    res = recon_engine.comp_reverse_sweep(cidr, {}, logs.append)
    assert time.monotonic() - t0 < 1.0
    assert calls == [] and res["entities"] == []
    assert "skipped" in logs[0] and "too sparse" in logs[0]


def test_reverse_sweep_caps_huge_ipv4_blocks_without_materializing_them(monkeypatch):
    calls = _fake_ptr(monkeypatch)
    logs = []
    t0 = time.monotonic()
    res = recon_engine.comp_reverse_sweep("10.0.0.0/8", {}, logs.append)  # 16.7M addresses
    assert time.monotonic() - t0 < 3.0   # the old code built all 16.7M address objects first
    first_4096 = {str(ipaddress.ip_address("10.0.0.0") + i) for i in range(1, 4097)}
    assert len(calls) == 4096 and set(calls) == first_4096
    assert "capping sweep at 4096" in logs[0]
    assert res["interrupted"] is False


@pytest.mark.parametrize("cidr,count", [
    ("192.0.2.0/24", 254), ("203.0.113.7/32", 1), ("203.0.113.6/31", 2),
    ("2001:db8::/120", 255),
    ("2001:db8::/116", 4095),     # exactly the cap in size: swept in full, not skipped
])
def test_reverse_sweep_covers_every_host_of_small_networks(monkeypatch, cidr, count):
    calls = _fake_ptr(monkeypatch)
    net = ipaddress.ip_network(cidr)
    expected = {str(h) for h in (net.hosts() if net.num_addresses > 2 else net)}
    recon_engine.comp_reverse_sweep(cidr, {}, lambda m: None)
    assert len(calls) == count and set(calls) == expected


def test_reverse_sweep_reports_ptr_hits(monkeypatch):
    _fake_ptr(monkeypatch, names={"192.0.2.5": "mail.example.test."})
    res = recon_engine.comp_reverse_sweep("192.0.2.0/29", {}, lambda m: None)
    assert _keys(res) == {("ip", "192.0.2.5"), ("subdomain", "mail.example.test")}
    assert res["log"] == ["  1 addresses with PTR records"]


# ── Stop lands mid-operation ──────────────────────────────────────────────────

def test_stop_lands_mid_netblock_and_keeps_partial_results(monkeypatch):
    calls = _fake_ptr(monkeypatch, delay=0.05, names={"10.0.0.1": "gw.example.test"})
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    t0 = time.monotonic()
    res = recon_engine.run_component("reverse_sweep", "10.0.0.0/20", stop=stop)  # ~4 s unstopped
    elapsed, looked_up = time.monotonic() - t0, len(calls)
    assert res["interrupted"] is True and res["error"] is None
    assert elapsed < 1.5, "Stop took %.2fs to land" % elapsed
    assert 0 < looked_up < 4094
    assert ("ip", "10.0.0.1") in _keys(res)
    assert "stopped after" in res["log"][-1]


def test_stop_lands_mid_dns_brute(monkeypatch):
    def slow_resolve(host):
        time.sleep(0.05)
        return ["192.0.2.1"] if host.startswith("w0.") else []

    monkeypatch.setattr(recon_engine, "_resolve", slow_resolve)
    words = ["w%d" % i for i in range(3000)]                      # ~4 s at 40 workers unstopped
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    t0 = time.monotonic()
    res = recon_engine.run_component("dns_brute", "example.test", {"words": words}, stop=stop)
    assert res["interrupted"] is True
    assert time.monotonic() - t0 < 1.5
    assert ("subdomain", "w0.example.test") in _keys(res)
    assert "stopped after" in res["log"][-1]


# ── No process-wide socket timeout ────────────────────────────────────────────

def test_dns_components_leave_the_global_socket_timeout_alone(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0))])
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("host.example.test", [], [ip]))
    socket.setdefaulttimeout(None)
    try:
        for name, target, opts in [("resolve", "a.example.test", {}),
                                   ("reverse", "192.0.2.10", {}),
                                   ("dns_brute", "example.test", {"words": "www mail"}),
                                   ("reverse_sweep", "192.0.2.8/29", {})]:
            # stop= is accepted for every component, stoppable or not
            res = recon_engine.run_component(name, target, opts, stop=threading.Event())
            assert res["error"] is None, (name, res)
        # The old helpers called socket.setdefaulttimeout(3.0): process-wide, so every
        # socket the suite opened afterwards (its own HTTP connections too) inherited it.
        assert socket.getdefaulttimeout() is None
    finally:
        socket.setdefaulttimeout(None)


# ── TLS SANs ──────────────────────────────────────────────────────────────────

def _cert_and_key(san_entries):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "beatrix.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)                 # self-signed
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=30))
               .not_valid_after(now - datetime.timedelta(days=1)))   # and expired
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
    return builder.sign(key, hashes.SHA256()), key


def test_tls_sans_are_read_even_from_self_signed_expired_certs(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert, key = _cert_and_key([
        x509.DNSName("beatrix.test"), x509.DNSName("*.beatrix.test"),
        x509.DNSName("forgotten.beatrix.test"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    lsock = socket.create_server(("127.0.0.1", 0))
    port = lsock.getsockname()[1]

    def serve_once():
        with lsock:
            conn, _ = lsock.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=serve_once, daemon=True).start()
    sans = asyncio.run(recon_helpers.extract_ssl_sans("127.0.0.1", port, timeout=5))
    # DNS names only (the IP SAN is dropped). Under CERT_NONE the parsed getpeercert()
    # dict is empty, which is why this used to come back [] for every host.
    assert sans == ["beatrix.test", "*.beatrix.test", "forgotten.beatrix.test"]


def test_cert_without_a_san_extension_yields_no_names():
    from cryptography.hazmat.primitives import serialization

    cert, _ = _cert_and_key(None)
    assert recon_helpers._dns_sans_from_der(cert.public_bytes(serialization.Encoding.DER)) == []


# ── WHOIS without the binary ──────────────────────────────────────────────────

def test_whois_query_speaks_rfc3912(monkeypatch):
    lsock = socket.create_server(("127.0.0.1", 0))
    port = lsock.getsockname()[1]
    received = []

    def serve_once():
        with lsock:
            conn, _ = lsock.accept()
            with conn:
                buf = b""
                while not buf.endswith(b"\r\n"):
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                received.append(buf)
                conn.sendall(b"Domain Name: XN--BCHER-KVA.TEST\r\n" + b"x" * 200_000)

    threading.Thread(target=serve_once, daemon=True).start()
    monkeypatch.setattr(recon_engine, "_WHOIS_PORT", port)
    out = recon_engine._whois_query("127.0.0.1", "bücher.test", timeout=5)
    assert received == [b"xn--bcher-kva.test\r\n"]     # IDNA-encoded, CRLF-terminated
    assert out.startswith("Domain Name: XN--BCHER-KVA.TEST") and len(out) > 200_000  # read to close


_WHOIS_REPLIES = {
    ("whois.iana.org", "test"):
        "domain:  TEST\ne-mail:  ops@registry-operator.test\nwhois:   whois.registry.test\n",
    ("whois.registry.test", "example.test"):
        "Domain Name: EXAMPLE.TEST\nRegistrar: Test Registrar\nCreation Date: 2001-02-03\n"
        "Registrar WHOIS Server: whois.registrar.test\n",
    ("whois.registrar.test", "example.test"):
        "Registrant Email: owner@example.test\nRegistrar WHOIS Server: whois.registrar.test\n",
}


def test_whois_works_without_the_binary_and_follows_referrals(monkeypatch):
    asked = []

    def fake_query(server, query, timeout=8.0):
        asked.append((server, query))
        return _WHOIS_REPLIES[(server, query)]

    monkeypatch.setattr(recon_engine, "_whois_query", fake_query)
    monkeypatch.setattr(recon_engine.shutil, "which", lambda name: None)    # no whois binary
    res = recon_engine.run_component("whois", "example.test")
    assert res["error"] is None
    # IANA is asked only for the TLD, then registry -> registrar; the registrar's
    # self-referral ends the chain.
    assert asked == list(_WHOIS_REPLIES)
    contacts = [e["key"] for e in res["entities"] if e["kind"] == "contact"]
    assert contacts == ["owner@example.test"]    # not the registry operator from IANA's reply
    domain = next(e for e in res["entities"] if e["kind"] == "domain")
    assert (domain["registrar"], domain["registered"]) == ("Test Registrar", "2001-02-03")


def test_whois_falls_back_to_whois_nic_when_iana_lists_no_server(monkeypatch):
    asked = []

    def fake_query(server, query, timeout=8.0):
        asked.append((server, query))
        # IANA's real .uk record has an empty whois: field.
        return "domain:  UK\nwhois:   \nstatus:  ACTIVE\n" if server == "whois.iana.org" else ""

    monkeypatch.setattr(recon_engine, "_whois_query", fake_query)
    recon_engine._whois_lookup("bbc.co.uk")
    assert asked == [("whois.iana.org", "uk"), ("whois.nic.uk", "bbc.co.uk")]


def test_whois_prefers_the_installed_binary(monkeypatch):
    monkeypatch.setattr(recon_engine.shutil, "which", lambda name: "/usr/bin/whois")
    monkeypatch.setattr(recon_engine.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(stdout="Registrar: Binary Registrar\n"))
    monkeypatch.setattr(recon_engine, "_whois_lookup",
                        lambda *a, **k: pytest.fail("pure-Python fallback used despite the binary"))
    res = recon_engine.run_component("whois", "example.test")
    assert next(e for e in res["entities"] if e["kind"] == "domain")["registrar"] == "Binary Registrar"


# ── Suite: sweep checkpointing + scanning glow ────────────────────────────────

@pytest.fixture
def suite(tmp_path):
    # Not started: these tests drive the server object directly, no HTTP needed.
    srv = SuiteServer(host="127.0.0.1", port=0, state_dir=tmp_path / "suite",
                      sessions_registry=tmp_path / "sessions.json")
    try:
        yield srv
    finally:
        srv.stop()


def test_sweep_stop_keeps_partial_results_and_resume_redoes_the_operation(suite, monkeypatch):
    monkeypatch.setattr(suite_mod, "_RECON_SWEEP_STAGES",
                        [{"component": "reverse_sweep", "scope": "cidr"}])
    pid = suite.projects.state()["active"]
    block = "10.20.0.0/20"                                       # 4,094 hosts
    suite.recon.merge(pid, [{"kind": "netblock", "key": block, "source": "test"}])
    calls = _fake_ptr(monkeypatch, delay=0.05, names={"10.20.0.1": "gw.example.test"})
    done = lambda: suite.recon_brokers[str(pid)].since(10 ** 9)["done"]  # noqa: E731

    assert suite.start_recon_sweep(pid, {"target": "example.test"})["ok"]
    _until(lambda: len(calls) > 60)
    suite.stop_recon(pid)
    assert _until(done) < 1.5          # used to wait out the whole netblock (~4 s here)

    cp = suite.recon_sweeps.get(pid)
    op = "reverse_sweep\x00" + block
    assert cp["status"] == "interrupted" and op not in cp["completed"]
    assert "10.20.0.1" in suite.recon.values_of(pid, "ip")       # partial results kept
    events = [e["text"] for e in suite.recon_brokers[str(pid)].since(0)["events"]]
    assert any("stopped partway through" in t for t in events)

    calls = _fake_ptr(monkeypatch)                                # instant lookups now
    assert suite.start_recon_sweep(pid, {}, resume=True)["ok"]
    _until(done)
    cp = suite.recon_sweeps.get(pid)
    assert cp["status"] == "done" and op in cp["completed"]
    assert len(calls) == 4094                                     # re-swept in full


def test_activity_lights_up_spa_recon_runs(suite):
    pid = str(suite.projects.state()["active"])
    run = _Broker(meta={})
    suite.spa_brokers[pid] = run
    assert "sparecon" in suite.activity()["projects"][pid]
    run.finish()
    assert pid not in suite.activity()["projects"]


# ── Scope: lookalike domains are not subdomains ───────────────────────────────

@pytest.mark.parametrize("host,expected", [
    ("example.com", True), ("a.example.com", True), ("A.B.Example.COM.", True),
    ("m.testexample.com", False), ("evilexample.com", False),     # lookalikes passed .endswith()
    ("example.com.evil.net", False), ("", False),
])
def test_in_domain(host, expected):
    from beatrix.utils.helpers import in_domain
    assert in_domain(host, "example.com") is expected


# Each passive source as it really answers: a genuine subdomain, a lookalike domain
# (accepted by the old host.endswith(domain) filter), and their IPs.
_SOURCE_REPLIES = {
    "crtsh": {"json": [{"name_value": "a.example.com\nm.testexample.com\n*.evilexample.com"}]},
    "certspotter": {"json": [{"dns_names": ["a.example.com", "m.testexample.com"]}]},
    "otx": {"json": {"passive_dns": [{"hostname": "a.example.com", "address": "192.0.2.1"},
                                     {"hostname": "m.testexample.com", "address": "198.51.100.66"}]}},
    "hackertarget": {"text": "a.example.com,192.0.2.1\nm.testexample.com,198.51.100.66\n"},
    "wayback": {"json": [["original"], ["http://a.example.com/x"], ["https://m.testexample.com/y"]]},
}


@pytest.mark.parametrize("component", sorted(_SOURCE_REPLIES))
def test_passive_sources_drop_lookalike_domains_and_their_ips(monkeypatch, component):
    reply = _SOURCE_REPLIES[component]
    monkeypatch.setattr(recon_engine.requests, "get", lambda *a, **k: types.SimpleNamespace(
        status_code=200, json=lambda: reply.get("json"), text=reply.get("text", "")))
    res = recon_engine.run_component(component, "example.com")
    assert res["error"] is None
    subs = {e["key"] for e in res["entities"] if e["kind"] == "subdomain"}
    ips = {e["key"] for e in res["entities"] if e["kind"] == "ip"}
    assert subs == {"a.example.com"}
    assert "198.51.100.66" not in ips        # the lookalike's IP stays out of scope too


# ── Scope: the sweep only connects to hosts inside its domains ────────────────

_HOSTS = [
    {"kind": "domain", "key": "example.net", "source": "test"},       # a 2nd in-scope domain
    {"kind": "subdomain", "key": "a.example.com", "source": "crt.sh"},
    {"kind": "subdomain", "key": "hera.ns.cloudflare.com", "source": "NS"},
    {"kind": "subdomain", "key": "aspmx.l.google.com", "source": "MX"},
    {"kind": "subdomain", "key": "m.testexample.com", "source": "older data"},  # lookalike
    {"kind": "subdomain", "key": "shop.example.net", "source": "TLS SAN"},
]


def _one_stage_sweep(suite, monkeypatch, component, scope, seed, target="example.com"):
    """Run a one-stage sweep of ``target`` over a project seeded with ``seed``, with the
    component faked out; returns (project id, targets it ran on, log lines)."""
    monkeypatch.setattr(suite_mod, "_RECON_SWEEP_STAGES", [{"component": component, "scope": scope}])
    ran_on = []
    monkeypatch.setitem(recon_engine.COMPONENTS[component], "fn",
                        lambda t, opts, log, **kw: (ran_on.append(t), {"entities": [], "log": []})[1])
    pid = suite.projects.state()["active"]
    suite.recon.merge(pid, [dict(e) for e in seed])
    assert suite.start_recon_sweep(pid, {"target": target})["ok"]
    _until(lambda: suite.recon_brokers[str(pid)].since(10 ** 9)["done"])
    return pid, ran_on, [e["text"] for e in suite.recon_brokers[str(pid)].since(0)["events"]]


def test_sweep_never_contacts_hosts_outside_its_domains(suite, monkeypatch):
    pid, contacted, events = _one_stage_sweep(suite, monkeypatch, "tls_san", "host", _HOSTS)
    # The target, plus hosts under an in-scope domain (example.net is a domain entity) ...
    assert contacted == ["example.com", "a.example.com", "shop.example.net"]
    # ... while other organisations' NS / MX names and the lookalike are skipped with a
    # note — but stay recorded.
    note = next(t for t in events if "not contacting" in t)
    for host in ("hera.ns.cloudflare.com", "aspmx.l.google.com", "m.testexample.com"):
        assert host in note
    assert {"hera.ns.cloudflare.com", "aspmx.l.google.com"} <= set(suite.recon.values_of(pid, "subdomain"))


def test_sweep_still_resolves_out_of_domain_names(suite, monkeypatch):
    # Resolve only asks DNS resolvers — it never touches the host — so NS / MX names
    # are still resolved for context.
    _, looked_up, events = _one_stage_sweep(suite, monkeypatch, "resolve", "host", _HOSTS)
    assert {"hera.ns.cloudflare.com", "aspmx.l.google.com"} <= set(looked_up)
    assert not any("not contacting" in t for t in events)


# ── Scope: no reverse-DNS sweeps of CDN / cloud-provider address space ────────

@pytest.mark.parametrize("org,provider", [
    ("Cloudflare, Inc.", "cloudflare"), ("CLOUDFLARENET, US", "cloudflare"),
    ("Amazon Technologies Inc.", "amazon"), ("AMAZON-02", "amazon"), ("Google LLC", "google"),
    ("MICROSOFT-CORP-MSN-AS-BLOCK", "microsoft"), ("Akamai Technologies, Inc.", "akamai"),
    ("DigitalOcean, LLC", "digitalocean"), ("Hetzner Online GmbH", "hetzner"), ("OVH SAS", "ovh"),
    # whole words only — these must NOT read as providers:
    ("Lawson Software", None), ("Amazonas Energia S.A.", None), ("Example Corp", None),
    ("(from SPF)", None), ("", None),
])
def test_shared_provider(org, provider):
    assert recon_engine.shared_provider(org) == provider


_NETBLOCKS = [
    {"kind": "netblock", "key": "104.16.0.0/12", "org": "Cloudflare, Inc.", "source": "RDAP"},
    {"kind": "netblock", "key": "203.0.113.0/24", "org": "Example Corp", "source": "RDAP"},
    {"kind": "netblock", "key": "52.94.0.0/22", "org": "AMAZON-02", "source": "ASN"},
    {"kind": "netblock", "key": "198.51.100.0/24", "org": "(from SPF)", "source": "SPF"},
    {"kind": "netblock", "key": "192.0.2.0/24", "org": "Lawson Software", "source": "RDAP"},
]


def test_sweep_skips_cdn_and_cloud_provider_netblocks(suite, monkeypatch):
    _, swept, events = _one_stage_sweep(suite, monkeypatch, "reverse_sweep", "cidr", _NETBLOCKS)
    assert swept == ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"]
    note = next(t for t in events if "cloud-provider netblock" in t)
    assert "104.16.0.0/12 (Cloudflare, Inc.)" in note and "52.94.0.0/22 (AMAZON-02)" in note


def test_sweep_keeps_a_providers_netblocks_when_the_provider_is_the_target(suite, monkeypatch):
    _, swept, _ = _one_stage_sweep(suite, monkeypatch, "reverse_sweep", "cidr", _NETBLOCKS,
                                   target="cloudflare.com")
    assert "104.16.0.0/12" in swept and "52.94.0.0/22" not in swept


def test_asn_owner_comes_from_the_as_record_not_the_allocation_date(monkeypatch):
    import dns.resolver
    answers = {   # Team Cymru's two TXT formats
        "1.2.0.192.origin.asn.cymru.com": ['"64500 | 192.0.2.0/24 | US | arin | 2015-02-25"'],
        "AS64500.asn.cymru.com": ['"64500 | US | arin | 2010-07-14 | EXAMPLENET - Example Corp, US"'],
    }
    monkeypatch.setattr(dns.resolver, "resolve", lambda q, rdtype: answers[q])
    data = asyncio.run(recon_helpers.whois_asn_lookup("", "192.0.2.1"))
    assert (data["asn"], data["asn_org"]) == ("64500", "EXAMPLENET - Example Corp, US")
    assert data["ip_ranges"] == ["192.0.2.0/24"]
