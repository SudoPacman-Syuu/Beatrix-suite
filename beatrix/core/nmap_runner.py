"""
BEATRIX — nmap runner for the Suite's Network (Zenmap-style) module.

Unlike :mod:`beatrix.core.nmap_scanner` (python-nmap, used by the kill chain),
this runner shells out to ``nmap -oX`` directly so we keep the canonical XML.
That XML is what a Zenmap-style UI needs: it drives the Ports/Hosts tables, the
Topology graph (traceroute hops), the raw-output tab, and scan-to-scan diffing.

Everything here is plain subprocess + ``xml.etree`` — no extra dependency. The
Suite drives it on a thread and streams ``nmap``'s stdout to the project broker;
the structured result is parsed from the XML file on completion.

Nothing runs a shell: argv is always a list. Privileged profiles (SYN/UDP/OS/
traceroute/-A) are prefixed with ``sudo -n`` when raw sockets are needed and
passwordless sudo is available, matching how an operator would run Zenmap.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Tuple

# The à-la-carte preset catalog, grouped by nmap capability so any single useful
# function is one click. NMAP_PROFILES (flat name→args) is derived from the groups
# for the server-side fallback; the Suite's JS mirrors NET_PROFILE_GROUPS to build
# the dropdown's <optgroup>s. Keep the two in sync. The free-form args box still
# lets the operator type anything. Presets whose value needs a target-specific
# token carry an ALL-CAPS PLACEHOLDER the UI makes the operator fill in.
NMAP_PROFILE_GROUPS: List[Tuple[str, Dict[str, str]]] = [
    ("Zenmap classic", {
        "Intense scan": "-T4 -A -v",
        "Intense scan plus UDP": "-sS -sU -T4 -A -v",
        "Intense scan, all TCP ports": "-p 1-65535 -T4 -A -v",
        "Intense scan, no ping": "-T4 -A -v -Pn",
        "Ping scan": "-sn",
        "Quick scan": "-T4 -F",
        "Quick scan plus": "-sV -T4 -O -F --version-light",
        "Quick traceroute": "-sn --traceroute",
        "Regular scan": "",
        "Slow comprehensive scan":
            "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 "
            '--script "default or (discovery and safe)"',
    }),
    ("Host discovery", {
        "List scan (no probes)": "-sL",
        "Ping sweep (no port scan)": "-sn",
        "ARP ping sweep (LAN)": "-sn -PR",
        "ICMP echo ping": "-sn -PE",
        "ICMP timestamp + netmask ping": "-sn -PP -PM",
        "TCP SYN ping (common ports)":
            "-sn -PS21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5900,8080",
        "TCP ACK ping": "-sn -PA80,443,3389",
        "UDP ping": "-sn -PU53,123,137,161",
        "SCTP INIT ping": "-sn -PY",
        "IP protocol ping": "-sn -PO",
        "No-ping (assume host up)": "-Pn -T4 -F",
        "Traceroute": "-sn --traceroute",
    }),
    ("TCP scans", {
        "Quick scan (top 100)": "-T4 -F",
        "Top 1000 ports (SYN)": "-sS -T4 --open",
        "All TCP ports (SYN)": "-sS -p- -T4 --open",
        "TCP connect (unprivileged)": "-sT -T4",
        "TCP NULL scan": "-sN",
        "TCP FIN scan": "-sF",
        "TCP Xmas scan": "-sX",
        "TCP ACK scan (firewall map)": "-sA",
        "TCP Window scan": "-sW",
        "TCP Maimon scan": "-sM",
        "Idle / zombie scan": "-sI ZOMBIE_HOST:PORT",
        "Custom TCP flags": "--scanflags SYNACK",
    }),
    ("UDP / other protocols", {
        "UDP top 200 ports": "-sU --top-ports 200 -T4 --open",
        "UDP all ports (slow)": "-sU -p- -T4",
        "SCTP INIT scan": "-sY -T4",
        "SCTP COOKIE-ECHO scan": "-sZ",
        "IP protocol scan": "-sO",
        "FTP bounce scan": "-b FTP_RELAY_HOST",
    }),
    ("Service / OS", {
        "Service / version detection": "-sV -T4",
        "Version (light / fast)": "-sV --version-light -T4",
        "Version (intensive)": "-sV --version-all -T4",
        "OS detection": "-O --osscan-guess",
        "OS + version fingerprint": "-sS -sV -O -T4",
        "Aggressive (OS+ver+scripts+trace)": "-A -T4",
    }),
    ("NSE script categories", {
        "Default scripts (-sC)": "-sC",
        "Discovery scripts": "--script discovery",
        "Safe scripts": "--script safe",
        "Auth scripts": "-sV --script auth",
        "Vulnerability detection (vuln)": "-sV --script vuln",
        "Vulners / CVE lookup": "-sV --script vulners",
        "Exploit scripts": "-sV --script exploit",
        "Malware / backdoor check": "--script malware",
        "Broadcast discovery (LAN)": "--script broadcast",
        "Brute force (slow)": "-sV --script brute",
        "Denial-of-service (dangerous)": "--script dos",
        "Intrusive scripts": "-sV --script intrusive",
        "External (3rd-party data)": "--script external",
        "Fuzzer (slow)": "--script fuzzer",
    }),
    ("Targeted service enumeration", {
        "HTTP enumeration":
            '-sV --script "http-enum,http-headers,http-methods,http-title,http-robots.txt"',
        "SMB enumeration":
            '--script "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-protocols,smb-security-mode"',
        "SMB vulnerabilities": '--script "smb-vuln*"',
        "SSL / TLS (cert, ciphers, vulns)":
            '--script "ssl-cert,ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,sslv2"',
        "SSH enumeration": '--script "ssh-hostkey,ssh-auth-methods,ssh2-enum-algos"',
        "FTP enumeration": '--script "ftp-anon,ftp-syst"',
        "DNS enumeration": '--script "dns-nsid,dns-recursion,dns-zone-transfer"',
        "SNMP enumeration": '-sU --script "snmp-info,snmp-sysdescr,snmp-interfaces"',
        "Databases (SQL/Mongo)":
            '--script "ms-sql-info,mysql-info,oracle-tns-version,pgsql-brute,mongodb-info"',
        "RDP enumeration": '--script "rdp-ntlm-info,rdp-enum-encryption"',
        "SMTP enumeration": '--script "smtp-commands,smtp-open-relay,smtp-enum-users"',
        "VNC enumeration": '--script "vnc-info,vnc-title"',
        "NFS enumeration": '--script "nfs-showmount,nfs-ls,nfs-statfs"',
    }),
    ("Firewall / IDS evasion", {
        "Fragment packets": "-f -sS",
        "Fragment (custom MTU)": "--mtu 16 -sS",
        "Decoy scan": "-sS -D RND:10",
        "Source port 53": "-sS -g 53",
        "Slow stealth (-T1)": "-sS -T1 -f",
        "Spoof MAC (random)": "-sS --spoof-mac 0",
        "Bad-checksum probe": "--badsum",
    }),
    ("IPv6", {
        "IPv6 SYN scan": "-6 -sS -T4",
        "IPv6 aggressive": "-6 -A -T4",
    }),
]

# Flat name → args, derived from the groups (server-side fallback + completeness).
NMAP_PROFILES: Dict[str, str] = {
    name: args for _cat, items in NMAP_PROFILE_GROUPS for name, args in items.items()
}

# ── Full-sweep sequences ───────────────────────────────────────────────────────
# Ordered step lists for the one-button resumable sweeps. Each step is a normal
# nmap scan run through run_scan() and folded into the deduped host inventory, so
# the sweep accumulates coverage while staying resumable step-by-step. SWEEP_ACTIVE
# extends SWEEP_PASSIVE with intrusive NSE categories (auth/brute/exploit/dos).
# `-Pn` on the scan steps means a host that blocks ping is still fully scanned
# (maximum coverage, the whole point of the sweep).
SWEEP_PASSIVE: List[Dict[str, str]] = [
    {"key": "discovery", "label": "Host discovery",
     "args": "-sn -PE -PP -PS21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5900,8080 "
             "-PA80,443,3389 -PU53,123,137,161 -PY", "ports": ""},
    {"key": "tcp_top", "label": "Top-1000 TCP ports (SYN)",
     "args": "-sS -T4 --top-ports 1000 --open -Pn", "ports": ""},
    {"key": "tcp_all", "label": "All TCP ports (SYN)",
     "args": "-sS -p- -T4 --open -Pn", "ports": ""},
    {"key": "udp_top", "label": "Top-200 UDP ports",
     "args": "-sU --top-ports 200 -T4 --open -Pn", "ports": ""},
    {"key": "version_os", "label": "Service/version, OS, default+discovery+safe scripts",
     "args": '-sS -sV -O -sC --script "default or discovery or safe" -T4 -Pn', "ports": ""},
    {"key": "vuln", "label": "Vulnerability detection (vuln, vulners)",
     "args": '-sV --script "vuln or vulners" -T4 -Pn', "ports": ""},
    {"key": "traceroute", "label": "Traceroute / topology",
     "args": "-sn --traceroute", "ports": ""},
    {"key": "enum_web", "label": "Web enumeration (HTTP)",
     "args": '-sV -Pn --script "http-enum,http-headers,http-methods,http-title,http-robots.txt"',
     "ports": "80,443,8080,8443"},
    {"key": "enum_smb", "label": "SMB enumeration",
     "args": '-Pn --script "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-protocols,smb-security-mode"',
     "ports": "139,445"},
    {"key": "enum_tls_ssh", "label": "TLS + SSH enumeration",
     "args": '-sV -Pn --script "ssl-cert,ssl-enum-ciphers,ssl-dh-params,ssh-hostkey,ssh-auth-methods,ssh2-enum-algos"',
     "ports": "22,443,8443"},
    {"key": "enum_services", "label": "FTP/DNS/SNMP/SMTP/DB/RDP enumeration",
     "args": '-sS -sU -Pn --script "ftp-anon,dns-nsid,dns-recursion,snmp-info,smtp-commands,ms-sql-info,mysql-info,rdp-ntlm-info"',
     "ports": "T:21,25,53,1433,3306,3389,U:53,161"},
]
SWEEP_ACTIVE: List[Dict[str, str]] = SWEEP_PASSIVE + [
    {"key": "auth", "label": "Auth scripts", "args": "-sV -Pn --script auth -T4", "ports": ""},
    {"key": "brute", "label": "Brute force (slow)", "args": "-sV -Pn --script brute -T4", "ports": ""},
    {"key": "exploit", "label": "Exploit scripts", "args": "-sV -Pn --script exploit -T4", "ports": ""},
    {"key": "dos", "label": "Denial-of-service (dangerous)", "args": "-Pn --script dos -T4", "ports": ""},
]

def sweep_steps(mode: str) -> List[Dict[str, str]]:
    """The ordered step list for a sweep mode ('passive' | 'active')."""
    return [dict(s) for s in (SWEEP_ACTIVE if mode == "active" else SWEEP_PASSIVE)]

# Scan flags that need raw sockets (→ root). Connect (-sT), version (-sV), and
# TCP ping sweeps work unprivileged; these do not.
_RAW_FLAGS = {
    "-sS", "-sU", "-sO", "-sF", "-sN", "-sX", "-sA", "-sW", "-sM", "-sY", "-sZ",
    "-O", "-A", "-PE", "-PP", "-PM", "-PO", "-PR",
}
_RAW_SUBSTR = ("--traceroute",)


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def sudo_available() -> bool:
    """True if we can gain root non-interactively (passwordless sudo)."""
    if shutil.which("sudo") is None:
        return False
    try:
        return subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


def needs_root(args: str) -> bool:
    """Does this argument string need raw sockets (and therefore root)?"""
    toks = args.split()
    if any(t in _RAW_FLAGS for t in toks):
        return True
    return any(s in args for s in _RAW_SUBSTR)


def build_command(target: str, args: str, ports: str = "") -> List[str]:
    """Build the *display* nmap argv (no -oX) from target + args + ports.

    Returns the argv list a human would recognize (``nmap <args> -p <ports>
    <target>``). The actual run adds ``-oX`` and maybe ``sudo``; see
    :func:`run_scan`.
    """
    argv: List[str] = ["nmap"]
    if args.strip():
        argv += shlex.split(args)
    if ports.strip():
        argv += ["-p", ports.strip()]
    argv += shlex.split(target.strip()) if target.strip() else []
    return argv


def display_command(target: str, args: str, ports: str = "") -> str:
    """The clean, shell-quoted command string the operator would recognize."""
    return " ".join(shlex.quote(a) for a in build_command(target, args, ports))


class LiveHostStream:
    """Read an nmap ``-oX`` file while nmap is still writing it.

    nmap appends each ``<host>`` element as that host finishes. An
    ``XMLPullParser`` is fed only the new bytes on each poll, and it reports an
    element only once its closing tag has arrived. So a half-written host is
    never emitted, nothing is emitted twice, and no retry or repair is needed.
    Each completed host goes through :func:`_parse_host`, the same code the final
    parse uses, so a streamed host matches the final result exactly.

    If the stream turns out to be malformed, streaming stops for good. The final
    whole-file parse after the scan still gives the complete, authoritative result.
    """

    def __init__(self, path: str):
        self.path = path
        self._offset = 0
        self._parser = ET.XMLPullParser(events=("end",))
        self.broken: Optional[str] = None

    def poll(self) -> List[Dict[str, Any]]:
        """Return hosts completed since the last poll (possibly empty)."""
        if self.broken is not None:
            return []
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
        except FileNotFoundError:
            return []
        if not chunk:
            return []
        self._offset += len(chunk)
        new: List[Dict[str, Any]] = []
        try:
            self._parser.feed(chunk)
            for _event, el in self._parser.read_events():
                if el.tag == "host":
                    new.append(_parse_host(el))
        except ET.ParseError as e:
            self.broken = str(e)
        return new


def run_scan(
    target: str,
    args: str,
    ports: str,
    xml_path: str,
    on_line: Optional[Callable[[str], None]] = None,
    stop_event: Optional[threading.Event] = None,
    timeout: int = 1800,
    allow_privileged: bool = True,
    on_hosts: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    poll_interval: float = 0.5,
    oa_base: Optional[str] = None,
    resume_base: Optional[str] = None,
) -> Dict[str, Any]:
    """Run one nmap scan, streaming stdout via ``on_line``; parse the XML.

    ``on_hosts`` (optional) receives each batch of hosts the moment nmap finishes
    them, while the scan is still running. Hosts are delivered once each. The
    final result (``hosts`` in the return value) is the complete whole-file parse.

    Returns a result dict with ``command`` (as run), ``privileged``, ``error``,
    and (on success) the parsed scan under ``parse_nmap_xml``'s shape merged in.
    """
    priv = needs_root(args)
    if resume_base:
        # Continue an aborted scan from its -oA log. --resume reads the original
        # targets, options, and output files from the normal/greppable log, so argv
        # is just `--resume <base>.gnmap`; nmap keeps writing <base>.xml, which we
        # parse at the end (streaming is skipped on resume — the final parse is
        # authoritative and the inventory merge dedupes).
        xml_path = resume_base + ".xml"
        display = ["nmap", "--resume", resume_base + ".gnmap"]
        run_argv = list(display)
    else:
        display = build_command(target, args, ports)
        run_argv = list(display)
        # Insert output (and machine-readable progress) right after 'nmap'. -oA keeps
        # the .nmap/.gnmap logs that make a later --resume possible; plain -oX otherwise.
        if oa_base:
            xml_path = oa_base + ".xml"
            extra = ["-oA", oa_base]
        else:
            extra = ["-oX", xml_path]
        if "--stats-every" not in args:
            extra += ["--stats-every", "2s"]
        run_argv[1:1] = extra
    used_sudo = False
    if priv and allow_privileged:
        if sudo_available():
            run_argv = ["sudo", "-n"] + run_argv
            used_sudo = True
        # If sudo isn't available the scan will likely fail for raw-socket
        # types; we still run it and surface nmap's own error to the UI.

    result: Dict[str, Any] = {
        "command": " ".join(shlex.quote(a) for a in display),
        "privileged": priv,
        "used_sudo": used_sudo,
        "error": None,
        "hosts": [],
        "elapsed": 0.0,
        "summary": "",
        "raw_xml": "",
    }
    if not resume_base:
        try:
            os.remove(xml_path)          # never stream a previous scan's hosts
        except FileNotFoundError:
            pass
    try:
        proc = subprocess.Popen(
            run_argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except FileNotFoundError:
        result["error"] = "nmap is not installed."
        return result
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    stream = LiveHostStream(xml_path) if (on_hosts and not resume_base) else None
    poll_stop = threading.Event()

    def _deliver(hosts: List[Dict[str, Any]]) -> None:
        if hosts and on_hosts:
            try:
                on_hosts(hosts)
            except Exception:  # noqa: BLE001 — a UI callback must never break the scan
                pass

    def _poll_loop() -> None:
        while not poll_stop.is_set():
            if stream is not None:
                _deliver(stream.poll())
            poll_stop.wait(poll_interval)

    poller = None
    if stream is not None:
        poller = threading.Thread(target=_poll_loop, daemon=True)
        poller.start()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if on_line:
                on_line(line.rstrip("\n"))
            if stop_event is not None and stop_event.is_set():
                proc.terminate()
                break
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        result["error"] = f"scan exceeded {timeout}s and was killed"
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        # Stop the poller, then drain whatever nmap wrote last. Joining first
        # guarantees a single reader, so no host is delivered twice.
        poll_stop.set()
        if poller is not None:
            poller.join()
        if stream is not None:
            _deliver(stream.poll())

    # Parse whatever XML landed (nmap writes it even for partial scans).
    try:
        with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        result["raw_xml"] = raw
        parsed = parse_nmap_xml(raw)
        result.update(parsed)
    except FileNotFoundError:
        if not result["error"]:
            result["error"] = "nmap produced no output (did it fail to start?)"
    except ET.ParseError as e:
        if not result["error"]:
            result["error"] = f"could not parse nmap XML: {e}"
    return result


def _parse_host(host: ET.Element) -> Dict[str, Any]:
    """Parse one <host> element into the shared host dict.

    Used by both the final whole-file parse and the live stream, so a host
    looks identical whether it was read mid-scan or at the end.
    """
    status = host.find("status")
    addr = host.find("address")
    hr: Dict[str, Any] = {
        "ip": addr.get("addr", "") if addr is not None else "",
        "hostname": "",
        "state": status.get("state", "unknown") if status is not None else "unknown",
        "os": [],
        "ports": [],
        "scripts": {},
        "trace": [],
    }
    hn = host.find("hostnames/hostname")
    if hn is not None:
        hr["hostname"] = hn.get("name", "")
    for om in host.findall("os/osmatch"):
        hr["os"].append({"name": om.get("name", ""),
                         "accuracy": _int(om.get("accuracy"))})
    for port in host.findall("ports/port"):
        st = port.find("state")
        svc = port.find("service")
        pr: Dict[str, Any] = {
            "port": _int(port.get("portid")),
            "protocol": port.get("protocol", ""),
            "state": st.get("state", "") if st is not None else "",
            "reason": st.get("reason", "") if st is not None else "",
            "service": svc.get("name", "") if svc is not None else "",
            # nmap reports HTTPS as service name="http" + tunnel="ssl" (HTTP over a
            # TLS tunnel), so keep `tunnel` to render it as nmap does ("ssl/http").
            "tunnel": svc.get("tunnel", "") if svc is not None else "",
            "product": svc.get("product", "") if svc is not None else "",
            "version": svc.get("version", "") if svc is not None else "",
            "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
            "cpe": (svc.findtext("cpe", "") if svc is not None else ""),
            "scripts": {},
        }
        for scr in port.findall("script"):
            pr["scripts"][scr.get("id", "")] = scr.get("output", "")
        hr["ports"].append(pr)
    for scr in host.findall("hostscript/script"):
        hr["scripts"][scr.get("id", "")] = scr.get("output", "")
    for hop in host.findall("trace/hop"):
        hr["trace"].append({
            "ttl": _int(hop.get("ttl")),
            "ip": hop.get("ipaddr", ""),
            "rtt": hop.get("rtt", ""),
            "host": hop.get("host", ""),
        })
    return hr


def parse_nmap_xml(xml: str) -> Dict[str, Any]:
    """Parse nmap -oX output into a JSON-serializable dict.

    Shape:
        { command, start, elapsed, summary,
          hosts: [ { ip, hostname, state, os:[{name,accuracy}],
                     ports:[{port,protocol,state,reason,service,tunnel,product,
                             version,extrainfo,cpe,scripts:{id:output}}],
                     scripts:{id:output},               # host scripts
                     trace:[{ttl,ip,rtt,host}] } ] }
    """
    root = ET.fromstring(xml)
    out: Dict[str, Any] = {
        "argline": root.get("args", ""),   # the exact nmap invocation (incl. -oX)
        "start": root.get("start", ""),
        "elapsed": 0.0,
        "summary": "",
        "hosts": [],
    }
    for host in root.findall("host"):
        out["hosts"].append(_parse_host(host))

    finished = root.find("runstats/finished")
    if finished is not None:
        out["elapsed"] = _float(finished.get("elapsed"))
        out["summary"] = finished.get("summary", "")
    if not out["summary"]:
        hs = root.find("runstats/hosts")
        up = hs.get("up", "0") if hs is not None else "0"
        total_open = sum(
            1 for h in out["hosts"] for p in h["ports"] if p["state"] == "open"
        )
        out["summary"] = f"{up} host(s) up, {total_open} open port(s), {out['elapsed']:.1f}s"
    return out


def diff_scans(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Structural diff of two parsed scans (Zenmap's "compare" feature).

    Per host (keyed by ip) reports: port added/removed/changed (a port is
    "changed" on state, service, version, product OR tunnel), a change in the
    best OS guess, host-script added/removed/changed, and whether the host is
    present in one scan only. A host with no differences is omitted.
    """
    # ports keyed by (proto, port) so the same port number on tcp vs udp is
    # treated as two distinct ports (as nmap does).
    def port_map(h: Optional[Dict[str, Any]]) -> Dict[Any, Dict[str, Any]]:
        return {(p.get("protocol"), p.get("port")): p for p in (h or {}).get("ports", [])}

    def top_os(h: Optional[Dict[str, Any]]) -> str:
        os = (h or {}).get("os", [])
        return os[0].get("name", "") if os else ""

    by_ip_a = {h["ip"]: h for h in a.get("hosts", [])}
    by_ip_b = {h["ip"]: h for h in b.get("hosts", [])}
    _PORT_FIELDS = ("state", "service", "version", "product", "tunnel")

    diff: Dict[str, Any] = {"hosts": []}
    for ip in sorted(set(by_ip_a) | set(by_ip_b)):
        ha, hb = by_ip_a.get(ip), by_ip_b.get(ip)
        pa, pb = port_map(ha), port_map(hb)
        added, removed, changed = [], [], []
        for k in sorted(set(pa) | set(pb),
                        key=lambda k: (str(k[0]), k[1] if isinstance(k[1], int) else 0)):
            x, y = pa.get(k), pb.get(k)
            if x and not y:
                removed.append(x)
            elif y and not x:
                added.append(y)
            elif x and y and any(x.get(f) != y.get(f) for f in _PORT_FIELDS):
                changed.append({"before": x, "after": y})

        osa, osb = top_os(ha), top_os(hb)
        os_change = {"before": osa, "after": osb} if osa != osb else None

        sa = (ha or {}).get("scripts", {}) or {}
        sb = (hb or {}).get("scripts", {}) or {}
        s_added = {k: v for k, v in sb.items() if k not in sa}
        s_removed = {k: v for k, v in sa.items() if k not in sb}
        s_changed = {k: {"before": sa[k], "after": sb[k]}
                     for k in sa if k in sb and sa[k] != sb[k]}

        present_in = "both" if (ha and hb) else ("a" if ha else "b")
        if (added or removed or changed or os_change
                or s_added or s_removed or s_changed or present_in != "both"):
            diff["hosts"].append({
                "ip": ip, "present_in": present_in,
                "added": added, "removed": removed, "changed": changed,
                "os": os_change,
                "scripts": {"added": s_added, "removed": s_removed, "changed": s_changed},
            })
    return diff


def to_csv(scan: Dict[str, Any]) -> str:
    """Flatten a parsed scan to CSV — one row per (host, port), hosts with no
    ports still get a row. Columns are stable for spreadsheet import."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "hostname", "host_state", "protocol", "port", "port_state",
                "service", "product", "version", "tunnel", "cpe"])
    for h in scan.get("hosts", []):
        base = [h.get("ip", ""), h.get("hostname", ""), h.get("state", "")]
        ports = h.get("ports", [])
        if not ports:
            w.writerow(base + ["", "", "", "", "", "", "", ""])
        for p in ports:
            w.writerow(base + [p.get("protocol", ""), p.get("port", ""), p.get("state", ""),
                               p.get("service", ""), p.get("product", ""), p.get("version", ""),
                               p.get("tunnel", ""), p.get("cpe", "")])
    return buf.getvalue()


def to_gnmap(scan: Dict[str, Any]) -> str:
    """Approximate nmap's greppable output (-oG): one Status + one Ports line per
    host. Not byte-identical to nmap, but grep/awk-friendly in the same shape."""
    lines: List[str] = []
    for h in scan.get("hosts", []):
        host = h.get("ip", "")
        if h.get("hostname"):
            host += f" ({h['hostname']})"
        lines.append(f"Host: {host}\tStatus: {(h.get('state', '') or '').capitalize()}")
        ports = h.get("ports", [])
        if ports:
            cells = ", ".join(
                f"{p.get('port', '')}/{p.get('state', '')}/{p.get('protocol', '')}"
                f"//{p.get('service', '')}//{p.get('version', '')}/"
                for p in ports)
            lines.append(f"Host: {host}\tPorts: {cells}")
    return "\n".join(lines) + ("\n" if lines else "")


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0
