"""
BEATRIX — packet engine for the Suite's Packets (Wireshark-style) module.

Unprivileged work only: read a .pcap/.pcapng and dissect it for the viewer
(packet list → layer tree → hex), plus the shared structured-packet builder used
by the crafter and the privileged scapy worker. Live capture and packet *send*
need root and live in :mod:`beatrix.core.scapy_worker`.

Engine: scapy (already in the venv) does the reading and dissection, so no new
dependency and no tshark required. If ``tshark`` is present it can later be used
as a richer dissection tier; this module is the always-works baseline.
"""

from __future__ import annotations

import re
import shutil
from typing import Any, Dict, List, Optional

_SCAPY = None


def _scapy():
    """Import scapy lazily (it's slow and chatty) and cache it."""
    global _SCAPY
    if _SCAPY is None:
        import logging
        logging.getLogger("scapy").setLevel(logging.ERROR)
        from scapy import all as scapy  # type: ignore
        _SCAPY = scapy
    return _SCAPY


def available() -> Dict[str, Any]:
    ok = True
    try:
        _scapy()
    except Exception:  # noqa: BLE001
        ok = False
    return {"scapy": ok, "tshark": shutil.which("tshark") is not None}


# ── proto / field formatting ──────────────────────────────────────────────────
# Highest "interesting" layer → the protocol label a tester expects in the list.
_PROTO_ORDER = ("TLS", "DNS", "HTTPRequest", "HTTP", "ICMP", "ICMPv6ND_NS",
                "ARP", "DHCP", "BOOTP", "NTP", "SNMP", "TCP", "UDP", "IPv6", "IP")


def _proto_name(p) -> str:
    for name in _PROTO_ORDER:
        try:
            if p.haslayer(name):
                return name
        except Exception:  # noqa: BLE001
            continue
    try:
        return p.lastlayer().name
    except Exception:  # noqa: BLE001
        return p.name


def _endpoints(p) -> (str, str):
    s = _scapy()
    try:
        if p.haslayer(s.IP):
            return p[s.IP].src, p[s.IP].dst
        if p.haslayer("IPv6"):
            return p["IPv6"].src, p["IPv6"].dst
        if p.haslayer(s.ARP):
            return p[s.ARP].psrc, p[s.ARP].pdst
        if p.haslayer(s.Ether):
            return p[s.Ether].src, p[s.Ether].dst
    except Exception:  # noqa: BLE001
        pass
    return "", ""


def _fmt(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray)):
        try:
            txt = bytes(v).decode("utf-8")
            if txt.isprintable():
                return txt
        except Exception:  # noqa: BLE001
            pass
        return bytes(v).hex()
    if isinstance(v, (int, float, str)) or v is None:
        return v
    return str(v)


def _row(i: int, p, base_time: float) -> Dict[str, Any]:
    src, dst = _endpoints(p)
    try:
        t = float(p.time) - base_time
    except Exception:  # noqa: BLE001
        t = 0.0
    try:
        info = p.summary()
    except Exception:  # noqa: BLE001
        info = ""
    return {"no": i, "time": round(t, 6), "src": src, "dst": dst,
            "proto": _proto_name(p), "length": len(p), "info": info}


def _layers(p) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for cls in p.layers():
        layer = p.getlayer(cls)
        if layer is None:
            continue
        fields: Dict[str, Any] = {}
        for f in getattr(layer, "fields_desc", []):
            try:
                fields[f.name] = _fmt(layer.getfieldval(f.name))
            except Exception:  # noqa: BLE001
                fields[f.name] = None
        out.append({"name": layer.name, "fields": fields})
    return out


# ── reading ─────────────────────────────────────────────────────────────────
_READ_CAP = 50000   # never load more than this many packets into memory


def read_capture(path: str, flt: str = "", offset: int = 0,
                 limit: int = 200) -> Dict[str, Any]:
    """Return a page of packet-list rows (filtered), plus total matched count."""
    s = _scapy()
    rows: List[Dict[str, Any]] = []
    total = 0
    base_time: Optional[float] = None
    truncated = False
    pred = _compile_filter(flt)
    try:
        reader = s.PcapReader(path)
    except FileNotFoundError:
        return {"error": "capture not found", "packets": [], "total": 0}
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not open capture: {e}", "packets": [], "total": 0}
    try:
        i = 0
        for p in reader:
            if i >= _READ_CAP:
                truncated = True
                break
            if base_time is None:
                try:
                    base_time = float(p.time)
                except Exception:  # noqa: BLE001
                    base_time = 0.0
            if pred is not None and not pred(p):
                i += 1
                continue
            if offset <= total < offset + limit:
                rows.append(_row(i, p, base_time or 0.0))
            total += 1
            i += 1
    finally:
        try:
            reader.close()
        except Exception:  # noqa: BLE001
            pass
    return {"error": None, "packets": rows, "total": total, "truncated": truncated}


def packet_detail(path: str, n: int) -> Optional[Dict[str, Any]]:
    """Full dissection (layer tree + hex + summary) of the nth packet."""
    s = _scapy()
    try:
        reader = s.PcapReader(path)
    except Exception:  # noqa: BLE001
        return None
    try:
        for i, p in enumerate(reader):
            if i == n:
                try:
                    hexd = s.hexdump(p, dump=True)
                except Exception:  # noqa: BLE001
                    hexd = bytes(p).hex()
                return {"no": n, "summary": p.summary(), "layers": _layers(p), "hex": hexd}
    finally:
        try:
            reader.close()
        except Exception:  # noqa: BLE001
            pass
    return None


# ── display filter (v2 — a small boolean grammar) ─────────────────────────────
# Wireshark-ish, enough for real triage:
#   fields     ip.addr/src/dst, ipv6.addr/src/dst, eth.addr/src/dst,
#              tcp|udp.port/srcport/dstport, tcp.flags/seq/ack/window,
#              udp.length, dns.qname, frame.len
#   operators  ==  !=  >  <  >=  <=
#   boolean    &&/and   ||/or   !/not   ( )
#   existence  a bare protocol keyword (tcp, udp, icmp, arp, dns, http, tls …)
# Anything that doesn't parse falls back to a case-insensitive substring match on
# the packet summary, so the old one-word filters keep working. The filter is
# compiled once per read (``_compile_filter``) and the predicate is applied per
# packet, so a long capture doesn't re-parse the grammar 50 000 times.
_PROTO_KEYWORDS = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "arp": "ARP",
                   "dns": "DNS", "ip": "IP", "ipv6": "IPv6", "tls": "TLS",
                   "http": "TCP", "dhcp": "DHCP", "ntp": "NTP", "icmpv6": "ICMPv6",
                   "ether": "Ether", "eth": "Ether"}

_TOK_RE = re.compile(r"""\s*(?:
      (?P<lp>\()
    | (?P<rp>\))
    | (?P<op>==|!=|>=|<=|>|<)
    | (?P<and>&&|and\b)
    | (?P<or>\|\||or\b)
    | (?P<not>!|not\b)
    | (?P<str>"[^"]*"|'[^']*')
    | (?P<word>[A-Za-z0-9_.:+/\-]+)
    )""", re.X | re.I)


class _FilterError(Exception):
    """Raised when a filter string isn't valid grammar (→ substring fallback)."""


def _tokenize(flt: str):
    toks, pos, n = [], 0, len(flt)
    while pos < n:
        if flt[pos].isspace():
            pos += 1
            continue
        m = _TOK_RE.match(flt, pos)
        if not m or m.end() == pos:
            raise _FilterError(f"bad token at {pos}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "str":
            val = val[1:-1]
        toks.append((kind, val))
    return toks


# recursive descent: or → and → not → atom ; atom = (expr) | field op value |
# bare-proto existence | unknown-word substring.
def _parse_filter(flt: str):
    toks = _tokenize(flt)
    if not toks:
        raise _FilterError("empty")
    node, i = _parse_or(toks, 0)
    if i != len(toks):
        raise _FilterError("trailing tokens")
    return node


def _parse_or(toks, i):
    node, i = _parse_and(toks, i)
    while i < len(toks) and toks[i][0] == "or":
        rhs, i = _parse_and(toks, i + 1)
        node = ("or", node, rhs)
    return node, i


def _parse_and(toks, i):
    node, i = _parse_not(toks, i)
    while i < len(toks) and toks[i][0] == "and":
        rhs, i = _parse_not(toks, i + 1)
        node = ("and", node, rhs)
    return node, i


def _parse_not(toks, i):
    if i < len(toks) and toks[i][0] == "not":
        node, i = _parse_not(toks, i + 1)
        return ("not", node), i
    return _parse_atom(toks, i)


def _parse_atom(toks, i):
    if i >= len(toks):
        raise _FilterError("expected atom")
    kind, val = toks[i]
    if kind == "lp":
        node, i = _parse_or(toks, i + 1)
        if i >= len(toks) or toks[i][0] != "rp":
            raise _FilterError("expected )")
        return node, i + 1
    if kind != "word":
        raise _FilterError(f"unexpected {kind}")
    if i + 1 < len(toks) and toks[i + 1][0] == "op":
        if i + 2 >= len(toks) or toks[i + 2][0] not in ("word", "str"):
            raise _FilterError("expected value")
        return ("cmp", val.lower(), toks[i + 1][1], toks[i + 2][1]), i + 3
    if val.lower() in _PROTO_KEYWORDS:
        return ("exists", val.lower()), i + 1
    return ("sub", val), i + 1          # unknown bare word → summary substring


def _has(p, name) -> bool:
    try:
        return bool(p.haslayer(name))
    except Exception:  # noqa: BLE001
        return False


def _num(v):
    try:
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)):
            return v
        s = str(v).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        if re.fullmatch(r"-?\d+\.\d+", s):
            return float(s)
    except Exception:  # noqa: BLE001
        pass
    return None


def _eth_endpoints(p):
    try:
        if _has(p, "Ether"):
            e = p["Ether"]
            return str(e.src), str(e.dst)
    except Exception:  # noqa: BLE001
        pass
    return "", ""


def _resolve(p, field: str):
    """Candidate values for a display-filter field (empty list → field absent)."""
    f = field
    src, dst = _endpoints(p)
    if f in ("ip.addr", "ipv6.addr", "addr"):
        return [src, dst]
    if f in ("ip.src", "ipv6.src"):
        return [src]
    if f in ("ip.dst", "ipv6.dst"):
        return [dst]
    if f == "eth.addr":
        return list(_eth_endpoints(p))
    if f == "eth.src":
        return [_eth_endpoints(p)[0]]
    if f == "eth.dst":
        return [_eth_endpoints(p)[1]]
    if f == "frame.len":
        return [len(p)]
    if f.endswith((".port", ".srcport", ".dstport")):
        proto = f.split(".", 1)[0]
        names = ["TCP"] if proto == "tcp" else (["UDP"] if proto == "udp"
                                                else ["TCP", "UDP"])
        out = []
        for ln in names:
            if _has(p, ln):
                lp = p[ln]
                try:
                    if f.endswith(".srcport"):
                        out.append(int(lp.sport))
                    elif f.endswith(".dstport"):
                        out.append(int(lp.dport))
                    else:
                        out += [int(lp.sport), int(lp.dport)]
                except Exception:  # noqa: BLE001
                    pass
        return out
    if f.startswith("tcp.") and _has(p, "TCP"):
        lp, attr = p["TCP"], f.split(".", 1)[1]
        if attr == "flags":
            return [str(lp.flags)]
        if attr in ("seq", "ack", "window"):
            try:
                return [int(getattr(lp, attr))]
            except Exception:  # noqa: BLE001
                return []
    if f == "udp.length" and _has(p, "UDP"):
        try:
            return [int(p["UDP"].len)]
        except Exception:  # noqa: BLE001
            return []
    if f == "dns.qname" and _has(p, "DNS"):
        try:
            qd = p["DNS"].qd
            if qd is None:
                return []
            name = _fmt(qd.qname)
            if isinstance(name, str) and name.endswith("."):
                name = name[:-1]      # scapy stores the FQDN root dot; drop it
            return [name]
        except Exception:  # noqa: BLE001
            return []
    return []


def _apply_op(v, op: str, want) -> bool:
    nv, nw = _num(v), _num(want)
    if nv is not None and nw is not None:
        return {"==": nv == nw, "!=": nv != nw, ">": nv > nw,
                "<": nv < nw, ">=": nv >= nw, "<=": nv <= nw}.get(op, False)
    sv, sw = str(v).lower(), str(want).lower()
    if op == "==":
        return sv == sw
    if op == "!=":
        return sv != sw
    return False                 # ordering comparisons need numbers on both sides


def _eval(node, p) -> bool:
    t = node[0]
    if t == "or":
        return _eval(node[1], p) or _eval(node[2], p)
    if t == "and":
        return _eval(node[1], p) and _eval(node[2], p)
    if t == "not":
        return not _eval(node[1], p)
    if t == "exists":
        return _has(p, _PROTO_KEYWORDS[node[1]])
    if t == "sub":
        try:
            return node[1].lower() in p.summary().lower()
        except Exception:  # noqa: BLE001
            return False
    if t == "cmp":
        vals = _resolve(p, node[1])
        return any(_apply_op(v, node[2], node[3]) for v in vals) if vals else False
    return False


def _compile_filter(flt: str):
    """Parse a display filter once → a predicate ``f(packet) -> bool`` (or None
    for an empty filter). Malformed grammar degrades to a summary substring."""
    flt = (flt or "").strip()
    if not flt:
        return None
    try:
        ast = _parse_filter(flt)
    except _FilterError:
        low = flt.lower()

        def _sub(p):
            try:
                return low in p.summary().lower()
            except Exception:  # noqa: BLE001
                return False
        return _sub

    def _pred(p):
        try:
            return _eval(ast, p)
        except Exception:  # noqa: BLE001
            return False
    return _pred


def _match(p, flt: str) -> bool:
    """Convenience: compile ``flt`` and test one packet (empty filter → True)."""
    pred = _compile_filter(flt)
    return True if pred is None else pred(p)


# ── analysis: follow stream, statistics, export ───────────────────────────────
def _conv_key(p):
    """A hashable key for the conversation a packet belongs to — ``(proto,
    frozenset{(ip,port),(ip,port)})`` — or None if it has no TCP/UDP ports.
    Direction-independent: both halves of a flow share one key."""
    src, dst = _endpoints(p)
    for ln, proto in (("TCP", "tcp"), ("UDP", "udp")):
        if _has(p, ln):
            lp = p[ln]
            try:
                return (proto, frozenset(((src, int(lp.sport)),
                                          (dst, int(lp.dport)))))
            except Exception:  # noqa: BLE001
                return None
    return None


def _as_text(payload: bytes) -> str:
    """Printable rendering of a payload for the stream view (non-text → dots)."""
    try:
        txt = payload.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        txt = payload.decode("latin-1", "replace")
    return "".join(c if (c.isprintable() or c in "\r\n\t") else "." for c in txt)


def _read_all(path: str):
    """Read up to ``_READ_CAP`` packets into a list (shared by the analysis fns)."""
    s = _scapy()
    reader = s.PcapReader(path)        # may raise; callers handle
    pkts = []
    try:
        for i, p in enumerate(reader):
            if i >= _READ_CAP:
                break
            pkts.append(p)
    finally:
        try:
            reader.close()
        except Exception:  # noqa: BLE001
            pass
    return pkts


def follow_stream(path: str, n: int) -> Dict[str, Any]:
    """Reassemble the TCP/UDP conversation that packet ``n`` belongs to.

    Returns the ordered payload segments tagged by direction (client = the side
    that sent the first packet of the flow), plus client/server labels — the data
    behind Wireshark's "Follow TCP/UDP Stream".
    """
    try:
        pkts = _read_all(path)
    except FileNotFoundError:
        return {"error": "capture not found"}
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not open capture: {e}"}
    if n < 0 or n >= len(pkts):
        return {"error": "packet index out of range"}
    key = _conv_key(pkts[n])
    if key is None:
        return {"error": "selected packet has no TCP/UDP stream"}
    proto = key[0]
    ln = "TCP" if proto == "tcp" else "UDP"
    client = server = None
    segments: List[Dict[str, Any]] = []
    count = 0
    for p in pkts:
        if _conv_key(p) != key:
            continue
        count += 1
        lp = p[ln]
        src, dst = _endpoints(p)
        here = (src, int(lp.sport))
        if client is None:                 # first packet seen → client side
            client, server = here, (dst, int(lp.dport))
        payload = bytes(lp.payload)
        if not payload:
            continue                       # pure ACK / empty datagram
        segments.append({"dir": "client" if here == client else "server",
                         "len": len(payload), "text": _as_text(payload),
                         "hex": payload.hex()})
    return {"error": None, "proto": proto, "packets": count,
            "client": f"{client[0]}:{client[1]}" if client else "",
            "server": f"{server[0]}:{server[1]}" if server else "",
            "segments": segments}


def statistics(path: str) -> Dict[str, Any]:
    """Capture statistics: protocol breakdown, conversations, endpoints.

    The data behind Wireshark's Statistics menu (a flat protocol tally by the
    'most interesting' layer, plus per-conversation and per-endpoint totals).
    """
    try:
        pkts = _read_all(path)
    except FileNotFoundError:
        return {"error": "capture not found"}
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not open capture: {e}"}
    protos: Dict[str, List[int]] = {}
    convs: Dict[Any, Dict[str, Any]] = {}
    ends: Dict[str, List[int]] = {}
    total_bytes = 0
    for p in pkts:
        ln = len(p)
        total_bytes += ln
        pr = _proto_name(p)
        protos.setdefault(pr, [0, 0])
        protos[pr][0] += 1
        protos[pr][1] += ln
        src, dst = _endpoints(p)
        for ip in (src, dst):
            if ip:
                ends.setdefault(ip, [0, 0])
                ends[ip][0] += 1
                ends[ip][1] += ln
        key = _conv_key(p)
        if key is not None:
            (a, b) = sorted(key[1])
            c = convs.setdefault(key, {"proto": key[0],
                                       "a": f"{a[0]}:{a[1]}", "b": f"{b[0]}:{b[1]}",
                                       "packets": 0, "bytes": 0})
            c["packets"] += 1
            c["bytes"] += ln
    return {
        "error": None,
        "total_packets": len(pkts),
        "total_bytes": total_bytes,
        "protocols": [{"name": k, "packets": v[0], "bytes": v[1]}
                      for k, v in sorted(protos.items(), key=lambda kv: -kv[1][0])],
        "conversations": sorted(convs.values(), key=lambda c: -c["packets"]),
        "endpoints": [{"ip": k, "packets": v[0], "bytes": v[1]}
                      for k, v in sorted(ends.items(), key=lambda kv: -kv[1][0])],
    }


def export_subset(path: str, flt: str, out_path: str) -> Dict[str, Any]:
    """Write the packets matching display filter ``flt`` to a new pcap at
    ``out_path`` (empty filter → every packet). Returns counts."""
    s = _scapy()
    pred = _compile_filter(flt)
    try:
        pkts = _read_all(path)
    except FileNotFoundError:
        return {"error": "capture not found"}
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not open capture: {e}"}
    keep = [p for p in pkts if pred is None or pred(p)]
    try:
        s.wrpcap(out_path, keep)
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not write export: {e}"}
    return {"error": None, "written": len(keep), "total": len(pkts), "path": out_path}


def tls_probe(target: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Open a TLS connection and report the negotiated version/cipher and the
    peer certificate (subject, issuer, validity, SANs). Unprivileged — a plain
    socket + :mod:`ssl`, no raw packets — so it runs without the root worker.
    Mirrors ``packet_crafter._tls_probe_sync`` for the manual Crafter."""
    import socket as _socket
    import ssl
    result: Dict[str, Any] = {"target": target, "port": int(port)}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with _socket.create_connection((target, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as tls:
                result["version"] = tls.version()
                result["cipher"] = tls.cipher()
                cert = tls.getpeercert(binary_form=False)
                if cert:
                    result["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                    result["notBefore"] = cert.get("notBefore")
                    result["notAfter"] = cert.get("notAfter")
                    result["san"] = [v for _t, v in cert.get("subjectAltName", ())]
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
    return result


# ── structured packet builder (shared with the crafter + worker) ──────────────
# A spec is {"layers": [{"name": "IP", "fields": {"dst": "1.2.3.4"}},
#                        {"name": "TCP", "fields": {"dport": 80, "flags": "S"}}]}.
# Only a safe allowlist of layer classes can be built this way — the whole point
# is that the GUI's guided builder can construct real packets WITHOUT eval'ing
# operator strings. A field value may itself be a nested allowlisted layer (or a
# list of them) via {"_layer": "DNSQR", "fields": {...}}, so a DNS query's
# ``qd=DNSQR(qname=...)`` is still buildable on this safe path.
_BUILDABLE = {
    "Ether": "Ether", "Dot1Q": "Dot1Q", "ARP": "ARP",
    "IP": "IP", "IPv6": "IPv6", "TCP": "TCP", "UDP": "UDP",
    "ICMP": "ICMP", "DNS": "DNS", "DNSQR": "DNSQR", "DNSRR": "DNSRR",
    "Raw": "Raw",
}


def _coerce_field(v: Any) -> Any:
    """Field values pass through unchanged, except a nested-layer object
    ({"_layer"/"name", "fields"}) or a list of them, which is built recursively
    through the same allowlist (e.g. a DNS ``qd`` DNSQR)."""
    if isinstance(v, dict) and ("_layer" in v or ("name" in v and "fields" in v)):
        return _build_layer(v)
    if isinstance(v, list):
        return [_coerce_field(x) for x in v]
    return v


def _build_layer(ldef: Dict[str, Any]):
    s = _scapy()
    name = ldef.get("_layer") or ldef.get("name")
    if name not in _BUILDABLE:
        raise ValueError(f"layer not allowed: {name}")
    cls = getattr(s, _BUILDABLE[name])
    fields = {str(k): _coerce_field(v) for k, v in (ldef.get("fields") or {}).items()}
    return cls(**fields)


def build_packet(spec: Dict[str, Any]):
    """Build a scapy packet from a structured, allowlisted layer spec."""
    layers = spec.get("layers") or []
    if not layers:
        raise ValueError("no layers")
    pkt = None
    for ldef in layers:
        layer = _build_layer(ldef)
        pkt = layer if pkt is None else pkt / layer
    return pkt


def packet_to_dict(p, index: int = 0) -> Dict[str, Any]:
    """Row + layer tree + hex for a freshly built/received scapy packet."""
    s = _scapy()
    try:
        base = float(p.time)
    except Exception:  # noqa: BLE001
        base = 0.0
    try:
        hexd = s.hexdump(p, dump=True)
    except Exception:  # noqa: BLE001
        hexd = bytes(p).hex()
    return {"row": _row(index, p, base), "layers": _layers(p),
            "hex": hexd, "summary": p.summary()}
