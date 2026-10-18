"""
BEATRIX — privileged scapy worker for the Suite's Packets module.

Launched by the Suite as ``sudo -n <venv-python> -m beatrix.core.scapy_worker``
(one per project) because live capture and packet *send* need raw sockets
(root). It speaks a JSON-line protocol: one command object per line on stdin,
one event object per line on stdout. The Suite proxies the Packets pane to it
and streams its events to the project broker.

Commands (``cmd``):
  sniff_start {iface, filter?, out, count?, duration?}
  sniff_stop  {}
  send        {spec|expr, iface?, mode: send|sendp|sr1, out?}
  replay      {path, iface?}
  eval        {code}            # the scapy console — runs scapy Python as root
  ping        {}

Events (``ev``): ready, packet, sniff_done, sent, replay_done, result, error.

SECURITY: this process runs as root. Structured commands (sniff/send/replay)
are validated. ``eval`` deliberately runs operator-supplied scapy Python as
root — it is the console, and the Suite is responsible for gating who can reach
it (local, session-authenticated). See the module plan's security note.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import threading
import time
from typing import Any, Dict, Optional


def _emit(obj: Dict[str, Any]) -> None:
    try:
        sys.stdout.write(json.dumps(obj, default=str) + "\n")
        sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass


class _Worker:
    def __init__(self):
        from beatrix.core import packet_engine as PE
        from scapy import all as scapy  # type: ignore
        import logging
        logging.getLogger("scapy").setLevel(logging.ERROR)
        self.PE = PE
        self.scapy = scapy
        # Namespace for the console: all of scapy plus a couple of helpers.
        self.ns: Dict[str, Any] = {"__name__": "scapy_console"}
        self.ns.update({k: getattr(scapy, k) for k in dir(scapy) if not k.startswith("_")})
        self._sniffer = None
        self._writer = None
        self._sniff_base: Optional[float] = None
        self._sniff_idx = 0
        self._sniff_emitted = 0
        self._lock = threading.Lock()

    # ── sniff ────────────────────────────────────────────────────────────
    def _sniff_cb(self, pkt) -> None:
        with self._lock:
            if self._writer is not None:
                try:
                    self._writer.write(pkt)
                    self._writer.flush()
                except Exception:  # noqa: BLE001
                    pass
            if self._sniff_base is None:
                try:
                    self._sniff_base = float(pkt.time)
                except Exception:  # noqa: BLE001
                    self._sniff_base = 0.0
            idx = self._sniff_idx
            self._sniff_idx += 1
            # Cap how many rows we stream (the pcap still gets everything).
            if self._sniff_emitted < 5000:
                self._sniff_emitted += 1
                _emit({"ev": "packet", "row": self.PE._row(idx, pkt, self._sniff_base or 0.0)})

    def sniff_start(self, cmd: Dict[str, Any]) -> None:
        if self._sniffer is not None:
            _emit({"ev": "error", "error": "a capture is already running"})
            return
        iface = cmd.get("iface") or None
        flt = cmd.get("filter") or None
        out = cmd.get("out")
        count = int(cmd.get("count") or 0)
        timeout = int(cmd.get("duration") or 0) or None
        self._sniff_base = None
        self._sniff_idx = 0
        self._sniff_emitted = 0
        self._writer = self.scapy.PcapWriter(out, append=False, sync=True) if out else None
        kwargs: Dict[str, Any] = {"prn": self._sniff_cb, "store": False}
        if iface:
            kwargs["iface"] = iface
        if flt:
            kwargs["filter"] = flt       # libpcap BPF
        if count:
            kwargs["count"] = count
        if timeout:
            kwargs["timeout"] = timeout
        self._sniffer = self.scapy.AsyncSniffer(**kwargs)
        self._sniffer.start()
        _emit({"ev": "sniff_started", "iface": iface or "(default)", "filter": flt or ""})
        if count or timeout:
            threading.Thread(target=self._auto_stop, daemon=True).start()

    def _auto_stop(self) -> None:
        s = self._sniffer
        if s is None:
            return
        try:
            s.join()
        except Exception:  # noqa: BLE001
            pass
        self.sniff_stop({})

    def sniff_stop(self, cmd: Dict[str, Any]) -> None:
        s = self._sniffer
        self._sniffer = None
        n = self._sniff_idx
        if s is not None:
            try:
                s.stop()
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:  # noqa: BLE001
                    pass
                self._writer = None
        _emit({"ev": "sniff_done", "packets": n})

    # ── send ─────────────────────────────────────────────────────────────
    def _do_send(self, pkt, mode: str, iface, timeout, count, out):
        """Send one crafted packet (shared by `send` and `resend`). L2 vs L3 and
        reply-waiting follow scapy's own split: sr1/srp1 wait for a reply,
        send/sendp don't; a packet carrying an Ether header goes out at L2."""
        has_l2 = self.scapy.Ether in pkt
        reply = None
        reply_pkt = None
        sent_dict = self.PE.packet_to_dict(pkt, 0)
        use_l2 = has_l2 or mode == "sendp"
        if mode == "sr1":
            fn = self.scapy.srp1 if has_l2 else self.scapy.sr1
            kw = {"timeout": int(timeout or 3), "verbose": 0}
            if iface and has_l2:          # iface is an L2 concern; L3 routes by dst
                kw["iface"] = iface
            reply_pkt = fn(pkt, **kw)
            if reply_pkt is not None:
                reply = self.PE.packet_to_dict(reply_pkt, 1)
        else:
            fn = self.scapy.sendp if use_l2 else self.scapy.send
            kw = {"count": int(count or 1), "verbose": 0}
            if iface and use_l2:
                kw["iface"] = iface
            fn(pkt, **kw)
        # Append the sent packet (and any reply) to the capture if one was named.
        if out:
            try:
                batch = [pkt] + ([reply_pkt] if reply_pkt is not None else [])
                self.scapy.wrpcap(out, batch, append=True)
            except Exception:  # noqa: BLE001
                pass
        return sent_dict, reply

    def send(self, cmd: Dict[str, Any]) -> None:
        mode = cmd.get("mode") or "send"
        if cmd.get("spec"):
            pkt = self.PE.build_packet(cmd["spec"])
        elif cmd.get("expr"):
            pkt = eval(cmd["expr"], self.ns)      # scapy expression (operator-supplied)
        else:
            _emit({"ev": "error", "error": "send needs a spec or expr"})
            return
        if cmd.get("fragsize"):                   # IP fragmentation (firewall/IDS reassembly test)
            sent_dict, reply, nfrags = self._do_send_fragmented(
                pkt, int(cmd["fragsize"]), cmd.get("timeout"), cmd.get("out"))
            _emit({"ev": "sent", "mode": "fragment", "fragments": nfrags,
                   "sent": sent_dict, "reply": reply})
            return
        sent_dict, reply = self._do_send(pkt, mode, cmd.get("iface") or None,
                                         cmd.get("timeout"), cmd.get("count"), cmd.get("out"))
        _emit({"ev": "sent", "mode": mode, "sent": sent_dict, "reply": reply})

    def _do_send_fragmented(self, pkt, fragsize: int, timeout, out):
        """Fragment an IP packet into ``fragsize``-byte pieces and send them, then
        wait (sr1 on the last fragment) for the reply the target sends once it
        reassembles. If a filtered port answers, the firewall isn't reassembling."""
        if self.scapy.IP not in pkt:
            raise ValueError("fragmentation needs an IP packet")
        frags = self.scapy.fragment(pkt, fragsize=max(8, int(fragsize)))
        sent_dict = self.PE.packet_to_dict(pkt, 0)
        if len(frags) > 1:
            self.scapy.send(frags[:-1], verbose=0)      # L3 route by dst; no reply yet
        reply_pkt = self.scapy.sr1(frags[-1], timeout=int(timeout or 3), verbose=0)
        reply = self.PE.packet_to_dict(reply_pkt, 1) if reply_pkt is not None else None
        if out:
            try:
                batch = list(frags) + ([reply_pkt] if reply_pkt is not None else [])
                self.scapy.wrpcap(out, batch, append=True)
            except Exception:  # noqa: BLE001
                pass
        return sent_dict, reply, len(frags)

    def resend(self, cmd: Dict[str, Any]) -> None:
        """Replay editor: read packet #index from a pcap, apply per-layer field
        overrides, recompute lengths/checksums, and (re)send it — optionally
        waiting for a reply. Overrides are restricted to allowlisted layers."""
        path = cmd.get("path")
        index = int(cmd.get("index") or 0)
        overrides = cmd.get("overrides") or {}
        mode = cmd.get("mode") or "send"
        try:
            pkts = self.scapy.rdpcap(path)
        except Exception as e:  # noqa: BLE001
            _emit({"ev": "error", "error": f"cannot read capture: {e}"})
            return
        if index < 0 or index >= len(pkts):
            _emit({"ev": "error", "error": "packet index out of range"})
            return
        pkt = pkts[index]
        for lname, fields in overrides.items():
            if not isinstance(fields, dict) or lname not in self.PE._BUILDABLE:
                continue
            if not pkt.haslayer(lname):
                continue
            layer = pkt[lname]
            for k, v in fields.items():
                try:
                    setattr(layer, str(k), v)
                except Exception:  # noqa: BLE001
                    pass
        # Null the computed fields so scapy recalculates them, then re-dissect.
        for lname in ("IP", "IPv6", "TCP", "UDP"):
            if pkt.haslayer(lname):
                layer = pkt[lname]
                for fld in ("chksum", "len", "plen"):
                    if hasattr(layer, fld):
                        try:
                            setattr(layer, fld, None)
                        except Exception:  # noqa: BLE001
                            pass
        try:
            pkt = pkt.__class__(bytes(pkt))
        except Exception:  # noqa: BLE001
            pass
        sent_dict, reply = self._do_send(pkt, mode, cmd.get("iface") or None,
                                         cmd.get("timeout"), cmd.get("count"), cmd.get("out"))
        _emit({"ev": "sent", "mode": mode, "sent": sent_dict, "reply": reply})

    def traceroute(self, cmd: Dict[str, Any]) -> None:
        """TTL-increment traceroute (learning recipe). Sends one probe per TTL
        and records the hop that answered, stopping when the target is reached.
        Synchronous: it returns the whole hop list in one event."""
        import socket
        host = cmd.get("host")
        if not host:
            _emit({"ev": "error", "error": "traceroute needs a host"})
            return
        proto = (cmd.get("proto") or "tcp").lower()
        dport = int(cmd.get("dport") or 80)
        maxttl = max(1, min(int(cmd.get("maxttl") or 20), 30))
        per = float(cmd.get("timeout") or 1.0)
        s = self.scapy
        try:
            target_ip = socket.gethostbyname(host)
        except Exception:  # noqa: BLE001
            target_ip = host
        hops = []
        for ttl in range(1, maxttl + 1):
            if proto == "icmp":
                probe = s.IP(dst=host, ttl=ttl) / s.ICMP()
            elif proto == "udp":
                probe = s.IP(dst=host, ttl=ttl) / s.UDP(dport=dport)
            else:
                probe = s.IP(dst=host, ttl=ttl) / s.TCP(dport=dport, flags="S")
            t0 = time.time()
            rep = s.sr1(probe, timeout=per, verbose=0)
            rtt = round((time.time() - t0) * 1000, 1)
            if rep is None:
                hops.append({"ttl": ttl, "ip": None, "rtt": None, "last": False})
                continue
            ip = rep[s.IP].src if rep.haslayer(s.IP) else ""
            reached = (ip == target_ip)
            hops.append({"ttl": ttl, "ip": ip, "rtt": rtt, "last": reached})
            if reached:
                break
        _emit({"ev": "traceroute_done", "target": host, "target_ip": target_ip, "hops": hops})

    def replay(self, cmd: Dict[str, Any]) -> None:
        path = cmd.get("path")
        iface = cmd.get("iface") or None
        pkts = self.scapy.rdpcap(path)
        kw: Dict[str, Any] = {"verbose": 0}
        if iface:
            kw["iface"] = iface
        self.scapy.sendp(pkts, **kw)
        _emit({"ev": "replay_done", "packets": len(pkts)})

    # ── console ────────────────────────────────────────────────────────────
    def run_eval(self, cmd: Dict[str, Any]) -> None:
        code = cmd.get("code") or ""
        buf = io.StringIO()
        out_val = ""
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                try:
                    val = eval(code, self.ns)          # expression
                    if val is not None:
                        out_val = repr(val)
                except SyntaxError:
                    exec(code, self.ns)                 # statements
            except Exception as e:  # noqa: BLE001
                out_val = f"{type(e).__name__}: {e}"
        captured = buf.getvalue()
        _emit({"ev": "result", "out": (captured + out_val).rstrip("\n")})

    # ── dispatch ───────────────────────────────────────────────────────────
    def handle(self, cmd: Dict[str, Any]) -> None:
        name = cmd.get("cmd")
        if name == "ping":
            _emit({"ev": "pong"})
        elif name == "sniff_start":
            self.sniff_start(cmd)
        elif name == "sniff_stop":
            self.sniff_stop(cmd)
        elif name == "send":
            self.send(cmd)
        elif name == "resend":
            self.resend(cmd)
        elif name == "traceroute":
            self.traceroute(cmd)
        elif name == "replay":
            self.replay(cmd)
        elif name == "eval":
            self.run_eval(cmd)
        else:
            _emit({"ev": "error", "error": f"unknown command: {name}"})


def main() -> None:
    try:
        worker = _Worker()
    except Exception as e:  # noqa: BLE001
        _emit({"ev": "fatal", "error": f"worker init failed: {type(e).__name__}: {e}"})
        return
    _emit({"ev": "ready", "pid": os.getpid(), "root": os.geteuid() == 0})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            cmd = json.loads(line)
        except Exception:  # noqa: BLE001
            _emit({"ev": "error", "error": "malformed command json"})
            continue
        try:
            worker.handle(cmd)
        except Exception as e:  # noqa: BLE001
            _emit({"ev": "error", "error": f"{type(e).__name__}: {e}", "cmd": cmd.get("cmd")})


if __name__ == "__main__":
    main()
