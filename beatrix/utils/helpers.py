"""Utility functions for the framework"""

import asyncio
import ipaddress
import subprocess
import threading
import time
from typing import Callable, List, Optional

# Handle optional imports gracefully
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


async def resolve_dns(domain: str, record_type: str = 'A') -> List[str]:
    """Resolve DNS records"""
    if not HAS_DNS:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


async def check_http(url: str, timeout: int = 5) -> Optional[dict]:
    """Check HTTP/HTTPS endpoint"""
    if not HAS_AIOHTTP:
        return None
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout, ssl=False) as response:
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "url": str(response.url)
                }
    except Exception:
        return None


def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    return all(part.replace('-', '').isalnum() for part in parts)


async def tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """Test TCP connection"""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def extract_domain(target: str) -> str:
    """Extract base domain from URL or hostname"""
    target = target.lower()
    # Remove protocol
    for prefix in ['https://', 'http://', '//']:
        if target.startswith(prefix):
            target = target[len(prefix):]
    # Remove path
    target = target.split('/')[0]
    # Remove port
    target = target.split(':')[0]
    return target


def in_domain(host: str, domain: str) -> bool:
    """True if ``host`` is ``domain`` itself or a subdomain of it.

    Use this, not ``host.endswith(domain)``: the bare suffix test also accepts unrelated
    lookalike domains ("m.testexample.com", "evilexample.com" for "example.com"), which
    recon then treated as in scope and actively probed. Case- and trailing-dot-insensitive.
    """
    h = (host or "").strip().lower().rstrip(".")
    d = (domain or "").strip().lower().rstrip(".")
    return bool(h and d) and (h == d or h.endswith("." + d))


def is_ip_address(target: str) -> bool:
    """
    Check if a target string is an IP address (v4 or v6).

    Handles raw IPs, URLs (http://1.2.3.4/path), and [IPv6] bracket notation.
    """
    host = extract_domain(target)
    # Strip IPv6 brackets if present
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def kill_on_stop(proc: "subprocess.Popen", stop_event: Optional[threading.Event] = None,
                 deadline: Optional[float] = None, on_deadline: Optional[Callable[[], None]] = None,
                 poll: float = 0.25) -> threading.Thread:
    """Terminate ``proc`` as soon as ``stop_event`` is set or ``deadline`` (a ``time.time()``
    value) passes, independently of its output.

    Runners used to check Stop (and their timeout) only between output lines, so a quiet
    process (no findings, no -v) ignored both until it exited on its own; for a slow nmap
    that can be hours. SIGTERM first, then SIGKILL if it hasn't exited within 5 s.
    """
    def watch() -> None:
        while proc.poll() is None:
            if stop_event is not None:
                fired = stop_event.wait(poll)
            else:
                time.sleep(poll)
                fired = False
            late = deadline is not None and time.time() > deadline
            if not (fired or late) or proc.poll() is not None:
                continue
            if late and not fired and on_deadline is not None:
                try:
                    on_deadline()
                except Exception:  # noqa: BLE001 — a callback must never keep the process alive
                    pass
            try:
                proc.terminate()
                proc.wait(5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
            except OSError:
                pass
            return

    t = threading.Thread(target=watch, daemon=True, name="kill-on-stop")
    t.start()
    return t
