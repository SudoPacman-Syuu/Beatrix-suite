"""
Regression tests for the stress-test fixes in the Suite's run lifecycle and HTTP layer.

Covers: findings leaking into another session when the session is switched mid-run, runs
stranded as "running" (lazy-import deadlock, exceptions escaping a worker), deleted projects
resurrected by late writes and SPA Recon surviving a project delete, Stop → Start refused while
the old run unwinds, Stop ignored by quiet subprocesses, the tiny listen backlog, malformed input
dropping the connection, unselected injection sweeps in Active Scan, and the test suite writing
into the real ~/.beatrix/findings.db.
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from beatrix.cli.ghost_web import _Broker
import beatrix.cli.suite as suite_mod
from beatrix.cli.suite import SuiteServer
from beatrix.core import recon_engine


@pytest.fixture
def suite(tmp_path):
    srv = SuiteServer(host="127.0.0.1", port=0, state_dir=tmp_path / "A",
                      sessions_registry=tmp_path / "sessions.json")
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture
def server(suite):
    suite.start(open_browser=False)
    return suite


def _request(srv, method, path, body=None, headers=None, token=True):
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    try:
        h = {"X-Beatrix-Token": srv.token} if token else {}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, json.loads(r.read() or b"null")
    finally:
        c.close()


def _until(pred, timeout=10.0):
    t0 = time.monotonic()
    while not pred():
        if time.monotonic() - t0 > timeout:
            pytest.fail("condition not reached in %.0fs" % timeout)
        time.sleep(0.02)


def _done(broker):
    return broker.since(10 ** 9)["done"]


def _blocking_resolve(monkeypatch, release, hold=5.0):
    """Make the 'resolve' recon component block until `release` is set (or `hold` passes),
    then report one entity: a stand-in for a slow network operation."""
    def fn(target, opts, log, **kw):
        release.wait(hold)
        return {"entities": [{"kind": "subdomain", "key": "late.example.test", "source": "test"}], "log": []}
    monkeypatch.setitem(recon_engine.COMPONENTS["resolve"], "fn", fn)


def _recon_keys(session_dir, pid=1):
    f = os.path.join(session_dir, "projects", str(pid), "recon.json")
    if not os.path.exists(f):
        return set()
    return set(json.load(open(f))["entities"].get("subdomain", {}))


# ── Session switch: findings stay in the session that ran the scan ────────────

def test_switching_session_waits_for_runs_and_keeps_their_results(suite, monkeypatch, tmp_path):
    release = threading.Event()
    _blocking_resolve(monkeypatch, release, hold=1.0)        # returns by itself after 1 s
    assert suite.start_recon_component(1, {"component": "resolve", "target": "x.example.test"})["ok"]
    t0 = time.monotonic()
    suite.mount_session(tmp_path / "B", register=False)       # drains A's run before swapping
    assert time.monotonic() - t0 >= 0.5                       # it really waited for the run
    assert _recon_keys(tmp_path / "A") == {"late.example.test"}
    assert _recon_keys(tmp_path / "B") == set()


def test_a_run_outliving_the_switch_still_writes_into_its_own_session(suite, monkeypatch, tmp_path):
    release = threading.Event()
    _blocking_resolve(monkeypatch, release)
    monkeypatch.setattr(suite, "_stop_and_drain", lambda keys, timeout=15.0: [])   # simulate a run the drain can't stop
    assert suite.start_recon_component(1, {"component": "resolve", "target": "x.example.test"})["ok"]
    broker = suite.recon_brokers["1"]
    suite.mount_session(tmp_path / "B", register=False)       # swap while the run is still blocked
    release.set()
    _until(lambda: _done(broker))
    assert _recon_keys(tmp_path / "A") == {"late.example.test"}   # bound to the session it started in
    assert _recon_keys(tmp_path / "B") == set()                   # used to land here, and vanish from A


# ── Runs are never stranded as "running" ──────────────────────────────────────

def test_a_worker_exception_still_finishes_the_run(suite, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("engine exploded")
    monkeypatch.setattr(suite_mod.nuclei_runner, "run", boom)
    monkeypatch.setattr(suite_mod.nuclei_runner, "available", lambda: {"nuclei": True})
    assert suite.start_nuclei_run(1, {"target": "http://127.0.0.1:1"})["ok"]
    broker = suite.nuclei_brokers["1"]
    _until(lambda: _done(broker))
    texts = [e["text"] for e in broker.since(0)["events"]]
    assert any("nuclei run failed: RuntimeError: engine exploded" in t for t in texts)
    assert "nuclei" not in suite.activity()["projects"].get("1", [])  # no stuck glow, can start again


def test_engines_are_imported_before_the_server_serves(tmp_path):
    # Fresh interpreter: lazily importing beatrix.scanners from two threads at once deadlocked
    # Python's import locks (SPA Recon + Nuclei started together, 8 of 8 trials).
    code = ("import sys; from beatrix.cli.suite import SuiteServer, _PRELOAD;"
            "s = SuiteServer(host='127.0.0.1', port=0, state_dir=sys.argv[1], sessions_registry=sys.argv[2], token='t' * 43);"
            "s.start(open_browser=False); print(json.dumps([m for m in _PRELOAD if m not in sys.modules])); s.stop()")
    out = subprocess.run([sys.executable, "-c", "import json; " + code, str(tmp_path / "s"), str(tmp_path / "r.json")],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert json.loads(out.stdout.strip().splitlines()[-1]) == []


# ── Project delete ────────────────────────────────────────────────────────────

def test_deleting_a_project_stops_spa_recon_and_never_resurrects_its_folder(suite):
    pid = suite.projects.new()["active"]
    key = str(pid)
    broker, stop = _Broker(meta={}), threading.Event()
    suite.spa_brokers[key], suite.spa_stops[key] = broker, stop

    def fake_spa_run():                                       # finishes only when told to stop
        stop.wait(10)
        broker.finish()
    threading.Thread(target=fake_spa_run, daemon=True).start()
    suite._close_project(pid)
    assert stop.is_set() and _done(broker)                    # SPA Recon used to be missed
    assert suite.projects.delete(pid)["ok"]
    folder = suite.projects.workspace_dir(pid)                # what a late write would ask for
    assert not folder.exists()


# ── Stop → Start ──────────────────────────────────────────────────────────────

def test_start_waits_for_a_stopping_run_instead_of_refusing(suite, monkeypatch):
    monkeypatch.setitem(recon_engine.COMPONENTS["resolve"], "fn",
                        lambda t, o, log, **kw: {"entities": [], "log": []})
    old, stop = _Broker(meta={}), threading.Event()
    suite.recon_brokers["1"], suite.recon_stops["1"] = old, stop
    assert not suite.start_recon_component(1, {"component": "resolve", "target": "a.test"})["ok"]  # still running

    stop.set()                                                # Stop pressed; the run unwinds in 0.4 s
    threading.Timer(0.4, old.finish).start()
    assert suite.start_recon_component(1, {"component": "resolve", "target": "a.test"})["ok"]


# ── Quiet subprocesses still honour Stop and their timeout ───────────────────

QUIET = [sys.executable, "-c", "import time; time.sleep(60)"]      # prints nothing, like a slow nmap


def test_kill_on_stop_terminates_a_silent_process_promptly():
    from beatrix.utils.helpers import kill_on_stop
    proc, stop = subprocess.Popen(QUIET), threading.Event()
    kill_on_stop(proc, stop)
    threading.Timer(0.3, stop.set).start()
    t0 = time.monotonic()
    proc.wait(10)
    assert time.monotonic() - t0 < 3


def test_kill_on_stop_enforces_the_deadline():
    from beatrix.utils.helpers import kill_on_stop
    proc, fired = subprocess.Popen(QUIET), []
    kill_on_stop(proc, None, deadline=time.time() + 0.5, on_deadline=lambda: fired.append(True))
    proc.wait(10)
    assert fired == [True]


# ── HTTP layer ────────────────────────────────────────────────────────────────

def test_listen_backlog_is_raised(server):
    assert server._httpd.request_queue_size == 128   # stdlib default 5 → multi-second stalls under load


@pytest.mark.parametrize("raw", [b"[]", b"null", b'"x"', b"7"])
def test_non_object_json_body_is_a_400_not_a_dropped_connection(server, raw):
    status, body = _request(server, "POST", "/projects/select", raw, {"Content-Type": "application/json"})
    assert status == 400 and body["ok"] is False


def test_invalid_content_length_is_a_400(server):
    c = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    c.putrequest("POST", "/projects/select"); c.putheader("Content-Length", "abc")
    c.putheader("X-Beatrix-Token", server.token); c.endheaders()
    r = c.getresponse()
    assert r.status == 400; c.close()


def test_unexpected_handler_error_returns_json_500(server):
    status, body = _request(server, "GET", "/recon/events?since=abc&project=1")   # int('abc')
    assert status == 500 and body["ok"] is False and "ValueError" in body["error"]
    assert _request(server, "GET", "/projects")[0] == 200                          # server unharmed


# ── Active Scan only runs the injection sweeps you selected ───────────────────

@pytest.mark.parametrize("modules,expected", [
    ([], (True, True)),                                                   # full scan
    (["crawl", "endpoint_prober", "js_analysis", "headers", "cors", "redirect"], (False, False)),  # Quick Scan
    (["crawl", "injection", "ssti"], (True, True)),
    (["crawl", "dom_xss"], (True, False)),
])
def test_proactive_injection_sweeps_follow_the_module_selection(modules, expected):
    from beatrix.core.kill_chain import proactive_sweeps_allowed
    assert proactive_sweeps_allowed(modules) == expected


@pytest.mark.parametrize("preset,runs", [
    ("quick", set()), ("stealth", set()), ("recon", set()),
    ("standard", {"nuclei", "dom_xss", "injection", "graphql"}),
    ("full", {"nuclei", "dom_xss", "injection", "graphql"}),        # no explicit modules = everything
])
def test_direct_stages_follow_the_preset_modules(preset, runs):
    # nuclei (recon/network/exploit), DOM XSS, SmartFuzzer (injection) and clairvoyance (graphql)
    # fetched their engines directly and ran in every scan, Quick and Stealth included.
    from beatrix.core.engine import BeatrixEngine
    from beatrix.core.kill_chain import module_requested
    modules = BeatrixEngine.PRESETS[preset].get("modules")
    stages = {"nuclei", "dom_xss", "injection", "graphql"}
    assert {s for s in stages if module_requested(modules, s)} == runs


# ── The test suite itself stays out of the real ~/.beatrix ────────────────────

def test_findings_db_default_is_isolated_per_test(tmp_path):
    from beatrix.core.findings_db import FindingsDB
    db = FindingsDB()
    try:
        assert str(db.db_path).startswith(str(tmp_path))
    finally:
        db.conn.close()


# ── Every Active Scan tool follows the module selection ──────────────────────

# tool → the module that must be selected for it to run ("deep" = full scans only: no module covers it)
_TOOL_GATES = {
    "dnsx": "crawl", "httpx": "crawl", "gau": "crawl", "waymore": "crawl", "gospider": "crawl",
    "hakrawler": "crawl", "webanalyze": "crawl", "kiterunner": "endpoint_prober", "arjun": "param_miner",
    "s3scanner": "takeover", "nomore403": "bac", "naabu": "deep", "rea": "deep",
}
_SINKS = {"notify", "metasploit"}   # post-scan sinks: summarise confirmed findings, no traffic to the target


def test_every_kill_chain_tool_launch_is_gated_by_the_module_selection():
    import re
    from beatrix.core import kill_chain
    src = open(kill_chain.__file__).read().split("\n")
    seen = set()
    for n, line in enumerate(src):
        m = re.search(r"\b\w+\.(\w+)\.available\b", line)
        if not m or not line.lstrip().startswith(("if ", "elif ")):
            continue
        tool = m.group(1); seen.add(tool)
        if tool in _SINKS:
            continue
        # gated by: an explicit module, full-scan-only, the proactive-sweep flags, or findings a
        # selected scanner already confirmed (xss_targets / cmdi_targets …)
        window = " ".join(src[max(0, n - 8):n + 1])
        assert re.search(r'module_requested\(|\bdeep\b|run_deep_recon|_selected\b|context\.get\("modules"\)|\w+_targets\b', window), \
            f"kill_chain.py:{n + 1}: {tool} runs whatever modules are selected"
        if tool in _TOOL_GATES:
            want = _TOOL_GATES[tool]
            assert (("deep" in line or 'not context.get("modules")' in line) if want == "deep"
                    else f'module_requested(context.get("modules"), "{want}")' in line), \
                f"kill_chain.py:{n + 1}: {tool} should be gated on {want!r}"
    assert set(_TOOL_GATES) <= seen          # the mapping still points at real call sites


def test_external_tool_run_honours_a_per_call_timeout():
    # 15 runners passed timeout= to a _run() that didn't accept it → TypeError → tool never ran.
    import asyncio
    from beatrix.core.external_tools import ExternalTool

    class _Py(ExternalTool):
        BINARY_NAME = os.path.basename(sys.executable)
    tool = _Py(timeout=60)
    tool.path = sys.executable
    assert asyncio.run(tool._run([sys.executable, "-c", "print('ok')"], timeout=10)) == "ok"
    t0 = time.monotonic()
    assert asyncio.run(tool._run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)) is None
    assert time.monotonic() - t0 < 5          # the per-call timeout, not the 60 s default
