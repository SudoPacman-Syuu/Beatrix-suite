"""
External-tool plumbing fixed alongside the installer: finding Go binaries that same-named
Python shims shadow on PATH, the nomore403 CLI as it exists today, the sudo probe that
recognises a scoped sudoers rule, python-nmap's password prompt, and the GHOST sandbox image.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from beatrix.core import external_tools as et
from beatrix.core import nmap_runner


def _exe(path: Path, text: str) -> Path:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_go_bin_dirs_follow_gobin_and_gopath(monkeypatch, tmp_path):
    monkeypatch.setenv("GOBIN", str(tmp_path / "gobin"))
    monkeypatch.setenv("GOPATH", os.pathsep.join([str(tmp_path / "a"), str(tmp_path / "b")]))
    dirs = et.go_bin_dirs()
    assert dirs[:3] == [str(tmp_path / "gobin"), str(tmp_path / "a" / "bin"), str(tmp_path / "b" / "bin")]
    assert "/go/bin" in dirs and str(Path.home() / "go" / "bin") in dirs
    assert len(dirs) == len(set(dirs))


def test_python_script_detection(tmp_path):
    assert et.is_python_script(str(_exe(tmp_path / "s", "#!/usr/bin/env python3\nprint(1)\n")))
    assert not et.is_python_script(str(_exe(tmp_path / "b", "#!/bin/sh\necho hi\n")))
    (tmp_path / "elf").write_bytes(b"\x7fELF" + b"\x00" * 32)
    assert not et.is_python_script(str(tmp_path / "elf"))
    assert not et.is_python_script(str(tmp_path / "missing"))


def test_s3scanner_prefers_the_go_cli_over_the_pypi_shim(monkeypatch, tmp_path):
    shim_dir, go_dir = tmp_path / "local", tmp_path / "go"
    shim_dir.mkdir(), go_dir.mkdir()
    _exe(shim_dir / "s3scanner", "#!/usr/bin/python3\nfrom S3Scanner.__main__ import main\n")
    monkeypatch.setenv("PATH", str(shim_dir))
    monkeypatch.setattr(et, "go_bin_dirs", lambda: [str(go_dir)])
    assert et.S3ScannerRunner().path is None                 # only the PyPI tool: not usable
    _exe(go_dir / "s3scanner", "#!/bin/sh\necho v3\n")
    assert et.S3ScannerRunner().path == str(go_dir / "s3scanner")


def test_base_lookup_falls_back_to_go_bin_dirs(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(et, "go_bin_dirs", lambda: [str(tmp_path)])
    _exe(tmp_path / "crlfuzz", "#!/bin/sh\n")
    assert et.CrlfuzzRunner().path == str(tmp_path / "crlfuzz")


# ── nomore403 ────────────────────────────────────────────────────────────────

_FAKE_NOMORE403 = r"""#!/bin/sh
# Records its argv, then behaves like nomore403 v1.4: banner sections on stdout, JSON in -o.
printf '%s\n' "$@" > "$(dirname "$0")/argv"
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
echo "━━━━━━━━ DEFAULT REQUEST ━━━━━━━━"
echo "403 	             9 bytes http://t/admin"
echo "━━━━━━━━ CUSTOM PATHS ━━━━━━━━"
echo "200 	           380 bytes http://t/admin/."
[ -n "$out" ] && [ "$MODE" = json ] && cat > "$out" <<'EOF'
[{"status_code": 403, "content_length": 9, "technique": "default", "payload": "http://t/admin"},
 {"status_code": 403, "content_length": 9, "technique": "headers", "payload": "X-Original-URL: /admin"},
 {"status_code": 200, "content_length": 380, "technique": "endpaths", "payload": "http://t/admin/."}]
EOF
exit 0
"""


@pytest.fixture
def nomore403(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _exe(bindir / "nomore403", _FAKE_NOMORE403)
    payloads = tmp_path / "share" / "payloads"
    payloads.mkdir(parents=True)
    (payloads / "httpmethods").write_text("GET\n")
    monkeypatch.setattr(et.Nomore403Runner, "_PAYLOAD_DIRS", [str(payloads)])
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    r = et.Nomore403Runner()
    assert r.path == str(bindir / "nomore403")
    return r, bindir, payloads


def test_nomore403_uses_current_flags_and_reads_json(nomore403, monkeypatch):
    runner, bindir, payloads = nomore403
    monkeypatch.setenv("MODE", "json")
    res = asyncio.run(runner.bypass("http://t/admin", threads=7))
    argv = (bindir / "argv").read_text().split("\n")
    assert argv[:4] == ["-u", "http://t/admin", "-m", "7"]          # not --url/--threads (unknown flags)
    assert "--json" in argv and argv[argv.index("-f") + 1] == str(payloads)
    assert res["bypassed"] and res["bypass_url"] == "http://t/admin/." and res["status"] == 200
    assert res["technique"] == "endpaths"
    assert {"url": "http://t/admin", "technique": "headers: X-Original-URL: /admin", "status": 403} in res["all_attempts"]
    assert all(a["technique"] != "default" for a in res["all_attempts"])


def test_nomore403_falls_back_to_streamed_lines(nomore403, monkeypatch):
    runner, _, _ = nomore403
    monkeypatch.setenv("MODE", "stdout")                          # no JSON file (e.g. killed by the timeout)
    res = asyncio.run(runner.bypass("http://t/admin"))
    assert res["bypassed"] and res["bypass_url"] == "http://t/admin/." and res["technique"] == "custom paths"
    assert len(res["all_attempts"]) == 1                          # the default 403 isn't an attempt


# ── sudo probe / python-nmap ─────────────────────────────────────────────────

def test_sudo_probe_asks_about_the_exact_command(monkeypatch):
    calls = []
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(nmap_runner.subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0))
    assert nmap_runner.sudo_available()
    assert nmap_runner.sudo_available("/venv/bin/python", "-m", "beatrix.core.scapy_worker")
    assert calls == [["sudo", "-n", "-l", "/usr/bin/nmap"],
                     ["sudo", "-n", "-l", "/venv/bin/python", "-m", "beatrix.core.scapy_worker"]]


def test_python_nmap_never_prompts_for_a_sudo_password(monkeypatch):
    from beatrix.core import nmap_scanner
    seen = {}

    class _PS:
        def scan(self, hosts, **kw):
            seen.update(kw)

        def command_line(self):
            return "nmap"

        def all_hosts(self):
            return []

        def scanstats(self):
            return {"elapsed": "0"}

    s = nmap_scanner.NetworkScanner.__new__(nmap_scanner.NetworkScanner)
    s._scanner, s.timeout = _PS(), 5
    monkeypatch.setattr(nmap_scanner.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(nmap_runner, "sudo_available", lambda *a: False)
    s._scan_sync("127.0.0.1", None, "-sS", "syn", sudo=True)
    assert "sudo" not in seen                                     # bare `sudo nmap` would wait for a password
    monkeypatch.setattr(nmap_runner, "sudo_available", lambda *a: True)
    s._scan_sync("127.0.0.1", None, "-sS", "syn", sudo=True)
    assert seen.get("sudo") is True


# ── GHOST: sandbox image + install hint ──────────────────────────────────────

def test_sandbox_prefers_the_locally_built_image():
    from beatrix.ai.ghost2.runtime import sandbox

    class _Images:
        def __init__(self, have):
            self.have = have

        def get(self, name):
            if name not in self.have:
                raise LookupError(name)

    rt = sandbox.DockerRuntime.__new__(sandbox.DockerRuntime)
    rt._client = SimpleNamespace(images=_Images({sandbox.BUILT_IMAGE}))
    assert rt._default_image() == sandbox.BUILT_IMAGE
    rt._client = SimpleNamespace(images=_Images(set()))
    assert rt._default_image() == sandbox.DEFAULT_IMAGE


def test_agent_extra_hint_points_at_this_checkout():
    import sys
    from beatrix.ai.ghost2 import agent_extra_hint
    hint = agent_extra_hint()
    repo = Path(__file__).resolve().parents[1]
    assert hint.startswith(sys.executable) and f"{repo}[agent]" in hint and "beatrix-cli[agent]" not in hint


# ── kiterunner ───────────────────────────────────────────────────────────────

_FAKE_KR = r"""#!/bin/sh
printf '%s\n' "$@" > "$(dirname "$0")/argv"
echo '{"level":"info","target":"http://t","message":"scan options"}' >&2
echo '{"method":"GET","target":"http://t","path":"/api/v1/users","responses":[{"uri":"http://t/api/v1/users","sc":200,"len":8}],"message":""}'
echo '{"level":"info","results":1,"message":"scan complete"}'
"""


def test_kiterunner_uses_real_flags_and_reads_stdout_hits(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _exe(bindir / "kr", _FAKE_KR)
    kite = tmp_path / "routes-small.kite"
    kite.write_text("x")
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setattr(et.KiterRunnerRunner, "_WORDLIST_PATHS", [str(kite)])
    res = asyncio.run(et.KiterRunnerRunner().scan("http://t", timeout=3))
    argv = (bindir / "argv").read_text().split("\n")
    assert argv[argv.index("--timeout") + 1] == "3s"            # a Go duration; "3" is rejected
    assert "--output-file" not in argv and argv[argv.index("-o") + 1] == "json"
    assert res == {"endpoints": [{"url": "http://t/api/v1/users", "method": "GET", "status": 200, "length": 8}],
                   "total": 1}
