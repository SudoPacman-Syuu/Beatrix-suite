"""
install.sh / uninstall.sh: the parts that can destroy data or silently mis-install, exercised
through bash against a throwaway HOME. Nothing here installs packages or touches the network.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "install.sh"
UNINSTALL = REPO / "uninstall.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _bash(script: str, home: Path, **env) -> subprocess.CompletedProcess:
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "TERM": "dumb", **env}
    return subprocess.run(["bash", "-c", script], cwd=REPO, env=e, capture_output=True, text=True, timeout=60)


DATA = {
    "findings.db": "db", "findings.db-wal": "wal", "sessions.json": "{}", "sessions/s1/state.json": "x",
    "suite/projects/1/issues.json": '{"issues": []}', ".env": "OPENAI_API_KEY=k", "auth.yaml": "a: 1",
    "config.yaml": "c: 1", "nuclei-templates/custom.yaml": "t", "suite.token": "tok",
}


def _old_layout(home: Path) -> Path:
    """~/.beatrix as older installers left it: the venv's files mixed in with the user's data."""
    b = home / ".beatrix"
    (b / "bin").mkdir(parents=True)
    (b / "bin" / "activate").write_text("# venv")
    (b / "bin" / "python").write_text("")
    (b / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (b / "include" / "python3.12").mkdir(parents=True)
    (b / "share" / "man" / "man1").mkdir(parents=True)
    os.symlink("lib", b / "lib64")
    (b / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (b / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55")
    (b / ".lock").write_text("")
    (b / ".gitignore").write_text("*")
    for rel, content in DATA.items():
        (b / rel).parent.mkdir(parents=True, exist_ok=True)
        (b / rel).write_text(content)
    return b


def _digest(b: Path) -> dict:
    return {rel: hashlib.sha256((b / rel).read_bytes()).hexdigest() for rel in DATA}


def test_sourcing_does_not_run_the_installer(tmp_path):
    # `beatrix setup` / `make setup` source install.sh only to call install_external_tools.
    r = _bash("source ./install.sh && type install_external_tools >/dev/null && echo SOURCED-ONLY", tmp_path)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().endswith("SOURCED-ONLY") and "Checking requirements" not in r.stdout


def test_help_runs_main_when_piped(tmp_path):
    r = subprocess.run(["bash", "-s", "--", "--help"], input=INSTALL.read_text(), cwd=tmp_path,
                       capture_output=True, text=True, timeout=60, env={**os.environ, "HOME": str(tmp_path)})
    assert r.returncode == 0 and "--with-sudo-rules" in r.stdout


def test_migration_removes_only_the_old_venv(tmp_path):
    b = _old_layout(tmp_path)
    before = _digest(b)
    r = _bash("source ./install.sh && migrate_old_layout", tmp_path)
    assert r.returncode == 0, r.stderr
    assert _digest(b) == before                                       # every data file intact
    left = sorted(p.name for p in b.iterdir())
    assert left == sorted({Path(rel).parts[0] for rel in DATA})       # and nothing of the venv
    assert _bash("source ./install.sh && migrate_old_layout", tmp_path).returncode == 0   # idempotent


def test_migration_keeps_unknown_files_in_venv_like_folders(tmp_path):
    b = _old_layout(tmp_path)
    (b / "share" / "notes.txt").write_text("mine")
    (b / ".gitignore").write_text("my rules\n")
    assert _bash("source ./install.sh && migrate_old_layout", tmp_path).returncode == 0
    assert (b / "share" / "notes.txt").read_text() == "mine"
    assert (b / ".gitignore").read_text() == "my rules\n"


def test_venv_can_never_be_the_data_folder(tmp_path):
    (tmp_path / ".beatrix").mkdir()
    (tmp_path / ".beatrix" / "findings.db").write_text("db")
    r = _bash("source ./install.sh && USE_UV=0 && create_venv", tmp_path, BEATRIX_VENV=str(tmp_path / ".beatrix"))
    assert r.returncode != 0 and "holds your data" in (r.stdout + r.stderr)
    assert (tmp_path / ".beatrix" / "findings.db").read_text() == "db"


def test_create_venv_refuses_to_replace_a_non_venv_folder(tmp_path):
    target = tmp_path / "stuff"
    target.mkdir()
    (target / "keep.txt").write_text("k")
    r = _bash("source ./install.sh && USE_UV=0 && create_venv", tmp_path, BEATRIX_VENV=str(target))
    assert r.returncode != 0 and (target / "keep.txt").exists()


def test_add_to_path_writes_the_exact_line_once(tmp_path):
    rc = tmp_path / ".bashrc"
    rc.write_text("export PATH=\"/usr/local/go/bin:$PATH\"\n")          # a substring of /go/bin's line
    script = "source ./install.sh && _add_to_path /go/bin && _add_to_path /go/bin"
    assert _bash(script, tmp_path, PATH="/usr/bin:/bin").returncode == 0
    assert rc.read_text().count('export PATH="/go/bin:$PATH"') == 1   # the old substring grep skipped it


def test_python_shims_are_not_mistaken_for_go_binaries(tmp_path):
    shim = tmp_path / "httpx"
    shim.write_text("#!/usr/bin/python3\nimport sys\n")
    elf = tmp_path / "nuclei"
    elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 64)
    r = _bash(f"source ./install.sh && _is_python_script {shim} && ! _is_python_script {elf} && echo OK", tmp_path)
    assert r.stdout.strip().endswith("OK"), r.stderr


def _passwordless_sudo() -> bool:
    return shutil.which("sudo") is not None and \
        subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


@pytest.mark.skipif(not _passwordless_sudo(), reason="needs passwordless sudo")
def test_install_refuses_to_run_under_sudo():
    # Under sudo everything would land in root's home; sourcing has no side effects.
    r = subprocess.run(["sudo", "-n", "bash", "-c", "source ./install.sh && check_invocation && echo RAN"],
                       cwd=REPO, capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "RAN" not in r.stdout and "without sudo" in r.stderr


def test_uninstall_keeps_data_unless_asked(tmp_path):
    b = _old_layout(tmp_path)
    venv = b / "venv"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    before = _digest(b)
    r = subprocess.run(["bash", str(UNINSTALL)], cwd=tmp_path, capture_output=True, text=True, timeout=60,
                       stdin=subprocess.DEVNULL,
                       env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "BEATRIX_INSTALL_DIR": str(tmp_path / "bin")})
    assert r.returncode == 0, r.stderr
    assert not venv.exists() and not (b / "pyvenv.cfg").exists()
    assert _digest(b) == before and "Kept" in r.stdout
