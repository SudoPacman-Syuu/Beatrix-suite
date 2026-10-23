"""
Tests for the Beatrix Suite central dashboard (`beatrix-suite`).

The suite unifies the existing GUIs behind ONE stdlib http.server: the shell at
/, the auth GUI mounted verbatim at /auth (+ its /api/* backend), a Ghost tool
that streams a run's events at /ghost/events, and a Hunt tool (the Dashboard's
module/preset control panel + terminal) that streams at /hunt/events. These
tests exercise the route wiring and event plumbing over real HTTP without a
browser, LLM, API key, or a real scan.
"""

from __future__ import annotations

import json
import time
import urllib.request

import pytest

from beatrix.cli.ghost_web import _Broker
from beatrix.cli.suite import (
    _AUTH_GET, _AUTH_POST, _IssueStore, _ProjectStore, _RepeaterStore,
    _ar_count, _ar_expand_set, _ar_generate, _ar_parse_positions, _ar_process,
    _finding_to_issue, _ghost_validation_objective, _ghost_validation_target,
    _gql_find_hints, _gql_normalize, _gql_stencil, _gql_type_str,
    _graphql_discover, _html_forms, _normalize_severity, _param_active_verify,
    _param_discover, _param_shape, _parse_raw_request, SuiteServer,
)


@pytest.fixture
def server(tmp_path):
    # Isolate both the project store and the session registry from the real
    # ~/.beatrix, and mount a session up front (the back-compatible path).
    srv = SuiteServer(host="127.0.0.1", port=0, state_dir=tmp_path / "suite",
                      sessions_registry=tmp_path / "sessions.json")
    srv.start(open_browser=False)
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture
def sessionless(tmp_path):
    # A server with NO session mounted (what `beatrix-suite` shows at launch).
    srv = SuiteServer(host="127.0.0.1", port=0,
                      sessions_registry=tmp_path / "sessions.json")
    srv.start(open_browser=False)
    try:
        yield srv
    finally:
        srv.stop()


def _get(srv, path):
    with urllib.request.urlopen(srv.url.rstrip("/") + path, timeout=5) as r:
        return r.getcode(), r.read()


def _post(srv, path, obj):
    req = urllib.request.Request(
        srv.url.rstrip("/") + path, data=json.dumps(obj).encode(), method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.getcode(), json.loads(r.read())


# ── One server, all tools: route wiring ─────────────────────────────────
def test_shell_served_at_root(server):
    code, body = _get(server, "/")
    assert code == 200
    text = body.decode()
    # Kill-chain-staged nav: stage wrappers in the bar, their module tabs inside.
    for stage in ('data-stage="setup"', 'data-stage="recon"', 'data-stage="exploitation"'):
        assert stage in text
    for tab in ('data-tab="auth"', 'data-tab="ghost"', 'data-tab="repeater"'):
        assert tab in text


def test_ghost_pane_has_original_dashboard_controls(server):
    # Regression: the Ghost pane must carry the same controls the standalone
    # GHOST v2 dashboard has — autoscroll toggle, Save HTML, and the
    # events/tools/elapsed stat readout — not just the bare log.
    text = _get(server, "/")[1].decode()
    for needle in ('id="g-autoscroll"', 'id="g-save"', 'id="g-count"',
                   'id="g-tools"', 'id="g-elapsed"', "saveGhostHtml"):
        assert needle in text, f"missing {needle!r} from Ghost pane"


def test_auth_gui_mounted_same_origin(server):
    # The Auth tab iframes /auth on the SAME origin — full reuse of the existing page.
    code, body = _get(server, "/auth")
    assert code == 200
    assert b"Beatrix" in body and b"Auth" in body


def test_auth_api_dispatches_to_backend(server):
    # A GET auth route returns the same JSON shape the standalone auth GUI serves.
    code, body = _get(server, "/api/list")
    assert code == 200
    assert isinstance(json.loads(body), dict)


def test_auth_routes_match_standalone_gui():
    # Suite mounts exactly the auth GUI's route set (no drift).
    assert set(_AUTH_GET) == {"/api/list", "/api/keys", "/api/model", "/api/models"}
    assert set(_AUTH_POST) == {"/api/save", "/api/clear", "/api/keys", "/api/model"}


# ── Ghost tool: run validation + event streaming (per-project) ──────────
def test_ghost_events_empty_before_any_run(server):
    # No broker yet for this project => reported "done" so a client never
    # sits in an infinite poll loop for a project that never ran anything.
    code, body = _get(server, "/ghost/events?since=0&project=1")
    assert code == 200
    assert json.loads(body) == {"events": [], "done": True}


def test_ghost_run_rejects_empty_target(server):
    code, result = _post(server, "/ghost/run", {"target": "  ", "project": 1})
    assert code == 200
    assert result["ok"] is False and "target" in result["error"].lower()


def test_ghost_events_stream_from_broker(server):
    # Simulate a run's broker (what run_investigation's on_event feeds) and
    # confirm the /ghost/events contract the page polls.
    b = _Broker(meta={"target": "https://x"})
    server.ghost_brokers["1"] = b
    b.emit({"type": "agent_start", "text": "GHOST engaged"})
    b.emit({"type": "finding", "text": "SQLi", "detail": "id param"})

    code, body = _get(server, "/ghost/events?since=0&project=1")
    data = json.loads(body)
    assert [e["type"] for e in data["events"]] == ["agent_start", "finding"]
    assert data["done"] is False

    # `since` cursor only returns newer events.
    last = data["events"][-1]["seq"]
    _, body2 = _get(server, "/ghost/events?since=%d&project=1" % last)
    assert json.loads(body2)["events"] == []

    b.finish()
    _, body3 = _get(server, "/ghost/events?since=0&project=1")
    assert json.loads(body3)["done"] is True


def test_ghost_state_reflects_current_run(server):
    assert _get(server, "/ghost/state?project=1")[0] == 200
    assert json.loads(_get(server, "/ghost/state?project=1")[1]) == {}  # no run yet
    server.ghost_brokers["1"] = _Broker(meta={"target": "https://x", "model": "m"})
    state = json.loads(_get(server, "/ghost/state?project=1")[1])
    assert state["target"] == "https://x" and state["model"] == "m"
    assert state["running"] is True  # broker not finished yet


def test_ghost_events_isolated_between_projects(server):
    # This is the exact bug: project 1 has a run streaming; switching to /
    # creating project 2 must NOT clobber or hide project 1's events.
    b1 = _Broker(meta={"target": "https://one.com"})
    server.ghost_brokers["1"] = b1
    b1.emit({"type": "agent_start", "text": "GHOST engaged"})
    b1.emit({"type": "finding", "text": "SQLi on one.com"})

    # A second project is created and has never run anything.
    code, d2 = _post(server, "/projects/new", {})
    new_id = d2["projects"][-1]["id"]
    assert json.loads(_get(server, "/ghost/state?project=%d" % new_id)[1]) == {}

    # Project 1's stream is completely unaffected by project 2 existing/being active.
    data = json.loads(_get(server, "/ghost/events?since=0&project=1")[1])
    assert [e["type"] for e in data["events"]] == ["agent_start", "finding"]
    state1 = json.loads(_get(server, "/ghost/state?project=1")[1])
    assert state1["target"] == "https://one.com" and state1["running"] is True


def test_ghost_run_defaults_to_active_project_when_unspecified(server):
    # Client omits `project` -> server uses the currently active project.
    _post(server, "/projects/select", {"id": 1})
    code, result = _post(server, "/ghost/run", {"target": ""})  # empty target, no project
    assert result["ok"] is False  # still validates target; proves the route was reached

    assert json.loads(_get(server, "/ghost/events?since=0")[1]) == {"events": [], "done": True}


def test_ghost_run_rejects_concurrent_run_on_same_project(server):
    server.ghost_brokers["1"] = _Broker(meta={"target": "https://x"})  # still running
    code, result = _post(server, "/ghost/run", {"target": "https://y", "project": 1})
    assert result["ok"] is False
    assert "already running" in result["error"].lower()


def test_unknown_route_404s(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(server, "/nope")
    assert exc.value.code == 404


# ── Projects rail: create / switch / delete over HTTP ───────────────────
def test_projects_seeded_with_one_active(server):
    code, body = _get(server, "/projects")
    assert code == 200
    d = json.loads(body)
    assert len(d["projects"]) == 1
    assert d["projects"][0]["id"] == 1 and d["projects"][0]["name"] == "Project 1"
    assert d["active"] == 1


def test_projects_created_numerically_and_active(server):
    _, d2 = _post(server, "/projects/new", {})
    assert [p["id"] for p in d2["projects"]] == [1, 2]
    assert d2["active"] == 2  # newest becomes active
    _, d3 = _post(server, "/projects/new", {})
    assert [p["name"] for p in d3["projects"]] == ["Project 1", "Project 2", "Project 3"]


def test_project_select_switches_active(server):
    _post(server, "/projects/new", {})           # -> active 2
    _, r = _post(server, "/projects/select", {"id": 1})
    assert r == {"ok": True, "active": 1}
    assert json.loads(_get(server, "/projects")[1])["active"] == 1


def test_project_delete_removes_and_fixes_active(server):
    _post(server, "/projects/new", {})           # 2 (active)
    _post(server, "/projects/new", {})           # 3 (active)
    _, r = _post(server, "/projects/delete", {"id": 3})
    assert r["ok"] is True
    assert [p["id"] for p in r["projects"]] == [1, 2]
    assert r["active"] == 1  # active fell back off the deleted one


def test_ids_are_stable_after_delete(server):
    _post(server, "/projects/new", {})           # 2
    _post(server, "/projects/new", {})           # 3
    _post(server, "/projects/delete", {"id": 2})  # gap: [1, 3]
    ids = [p["id"] for p in json.loads(_get(server, "/projects")[1])["projects"]]
    assert ids == [1, 3]                          # not renumbered
    _, d = _post(server, "/projects/new", {})     # next monotonic id
    assert d["projects"][-1]["id"] == 4


def test_deleting_last_project_reseeds(server):
    _, r = _post(server, "/projects/delete", {"id": 1})
    assert r["ok"] is True
    assert len(r["projects"]) == 1                # never empty
    assert r["active"] == r["projects"][0]["id"]


# ── Tab labels: the number on the tab, which is NOT the id ──────────────
# `id` identifies a project forever (and keys its data on disk); `label` is
# only what the rail shows and is recycled, so N tabs read 1..N instead of
# climbing every time you create and delete one.
def test_new_project_reuses_the_lowest_free_label(server):
    _post(server, "/projects/new", {})            # label 2
    _post(server, "/projects/new", {})            # label 3
    _post(server, "/projects/delete", {"id": 2})  # frees label 2
    _, d = _post(server, "/projects/new", {})
    new = d["projects"][-1]
    assert new["label"] == 2 and new["name"] == "Project 2"
    assert new["id"] == 4                         # ...on a brand-new id


def test_delete_never_renumbers_the_surviving_tabs(server):
    _post(server, "/projects/new", {})            # 2
    _post(server, "/projects/new", {})            # 3
    _post(server, "/projects/delete", {"id": 2})
    d = json.loads(_get(server, "/projects")[1])
    # 3 keeps reading "3" — a tab's number must never move under the user.
    assert [(p["id"], p["label"]) for p in d["projects"]] == [(1, 1), (3, 3)]


def test_labels_stay_bounded_by_the_tab_count_across_churn(server):
    # The property the whole change exists for: however much you create and
    # delete, the labels on screen are always exactly 1..N for N tabs.
    for _ in range(4):
        _post(server, "/projects/new", {})
    for pid in (2, 3, 5):
        _post(server, "/projects/delete", {"id": pid})
    for _ in range(3):
        _post(server, "/projects/new", {})
    labels = sorted(p["label"] for p in
                    json.loads(_get(server, "/projects")[1])["projects"])
    assert labels == list(range(1, len(labels) + 1))


def test_reseeded_last_project_is_labeled_one(server):
    _post(server, "/projects/delete", {"id": 1})  # empties, then re-seeds
    d = json.loads(_get(server, "/projects")[1])
    assert d["projects"][0]["label"] == 1         # not "Project 2"
    assert d["projects"][0]["name"] == "Project 1"


def test_recycled_label_does_not_recycle_the_workspace(tmp_path):
    # Label 2 comes back around; its data must not land in the dead project's
    # directory, because that is keyed by the (never-reused) id.
    store = _ProjectStore(tmp_path / "suite")
    store.new()                                   # id 2, label 2
    dead = store.workspace_dir(2)
    (dead / "loot.txt").write_text("old project's findings")
    store.delete(2)
    store.new()                                   # id 3, relabeled 2
    fresh = store.state()["projects"][-1]
    assert fresh["label"] == 2 and fresh["id"] == 3
    assert store.workspace_dir(fresh["id"]) != dead
    assert not (store.workspace_dir(fresh["id"]) / "loot.txt").exists()


def test_legacy_projects_json_keeps_the_numbers_already_on_screen(tmp_path):
    # Written before labels existed: ids drifted to {1, 7} with next_id 14.
    root = tmp_path / "suite"
    root.mkdir(parents=True)
    (root / "projects.json").write_text(json.dumps({
        "projects": [{"id": 1, "name": "Project 1", "created_at": 1.0},
                     {"id": 7, "name": "Project 7", "created_at": 2.0}],
        "active": 1, "next_id": 14,
    }))
    store = _ProjectStore(root)
    # Existing tabs keep reading 1 and 7 rather than being renumbered...
    assert [p["label"] for p in store.state()["projects"]] == [1, 7]
    # ...and the next project fills the lowest free slot instead of "14".
    fresh = store.new()["projects"][-1]
    assert fresh["label"] == 2 and fresh["name"] == "Project 2"
    assert fresh["id"] == 14                      # id still monotonic


def test_delete_unknown_project_is_noop(server):
    _, r = _post(server, "/projects/delete", {"id": 999})
    assert r["ok"] is False


def test_projects_persist_across_restart(tmp_path):
    sd = tmp_path / "suite"
    s1 = SuiteServer(host="127.0.0.1", port=0, state_dir=sd)
    s1.start(open_browser=False)
    try:
        _post(s1, "/projects/new", {})            # now [1, 2]
    finally:
        s1.stop()
    # New server instance, same state dir -> projects survive.
    store = _ProjectStore(sd)
    st = store.state()
    assert [p["id"] for p in st["projects"]] == [1, 2]


def test_project_workspace_dir_created_and_removed(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    store.new()  # id 2
    assert (tmp_path / "suite" / "projects" / "2").is_dir()
    store.delete(2)
    assert not (tmp_path / "suite" / "projects" / "2").exists()


# ── Hunt tool: catalog, validation, per-project run isolation ────────────
def test_hunt_catalog_shape(server):
    code, body = _get(server, "/hunt/catalog")
    assert code == 200
    cat = json.loads(body)
    assert len(cat["modules"]) >= 30  # BeatrixEngine's real module count
    assert {"key", "name", "category", "description"} <= set(cat["modules"][0])
    preset_keys = {p["key"] for p in cat["presets"]}
    assert {"quick", "standard", "full", "stealth"} <= preset_keys


def test_hunt_catalog_full_preset_is_every_module(server):
    cat = json.loads(_get(server, "/hunt/catalog")[1])
    full = next(p for p in cat["presets"] if p["key"] == "full")
    assert set(full["modules"]) == {m["key"] for m in cat["modules"]}


def test_hunt_catalog_modules_grouped_by_category(server):
    # Regression: modules used to be sorted by key, not category, so same-
    # category modules weren't adjacent and the panel printed a near-duplicate
    # header per module instead of grouping them.
    cat = json.loads(_get(server, "/hunt/catalog")[1])
    cats_in_order = [m["category"] for m in cat["modules"]]
    # Every occurrence of a category must be contiguous (no A, B, A pattern).
    seen = set()
    prev = None
    for c in cats_in_order:
        if c != prev:
            assert c not in seen, f"category {c!r} appeared in two separate groups"
            seen.add(c)
        prev = c


def test_hunt_run_rejects_empty_target(server):
    code, result = _post(server, "/hunt/run", {"target": "  ", "modules": ["headers"], "project": 1})
    assert code == 200
    assert result["ok"] is False and "target" in result["error"].lower()


def test_hunt_run_rejects_empty_module_selection(server):
    # Empty modules must NOT silently mean "run everything" (that's what an
    # empty list means to BeatrixEngine.hunt/kill_chain) — it must be rejected.
    code, result = _post(server, "/hunt/run", {"target": "example.com", "modules": [], "project": 1})
    assert result["ok"] is False
    assert "module" in result["error"].lower()


def test_hunt_events_empty_before_any_run(server):
    code, body = _get(server, "/hunt/events?since=0&project=1")
    assert code == 200
    assert json.loads(body) == {"events": [], "done": True}


def test_hunt_events_stream_from_broker(server):
    b = _Broker(meta={"target": "https://x", "modules": ["headers"]})
    server.hunt_brokers["1"] = b
    b.emit({"type": "scanner_start", "text": "▸ headers → https://x"})
    b.emit({"type": "finding", "text": "[LOW] Missing CSP", "detail": "URL: https://x"})

    data = json.loads(_get(server, "/hunt/events?since=0&project=1")[1])
    assert [e["type"] for e in data["events"]] == ["scanner_start", "finding"]
    assert data["done"] is False

    b.finish()
    assert json.loads(_get(server, "/hunt/events?since=0&project=1")[1])["done"] is True


def test_hunt_state_reflects_current_run(server):
    assert json.loads(_get(server, "/hunt/state?project=1")[1]) == {}
    server.hunt_brokers["1"] = _Broker(meta={"target": "https://x", "modules": ["headers"]})
    state = json.loads(_get(server, "/hunt/state?project=1")[1])
    assert state["target"] == "https://x" and state["running"] is True


def test_hunt_run_isolated_between_projects(server):
    b1 = _Broker(meta={"target": "https://one.com"})
    server.hunt_brokers["1"] = b1
    b1.emit({"type": "scanner_start", "text": "▸ headers"})

    _post(server, "/projects/new", {})  # project 2, never ran anything
    assert json.loads(_get(server, "/hunt/state?project=2")[1]) == {}

    state1 = json.loads(_get(server, "/hunt/state?project=1")[1])
    assert state1["target"] == "https://one.com" and state1["running"] is True


def test_hunt_run_rejects_concurrent_run_on_same_project(server):
    server.hunt_brokers["1"] = _Broker(meta={"target": "https://x"})  # still running
    code, result = _post(server, "/hunt/run",
                          {"target": "https://y", "modules": ["headers"], "project": 1})
    assert result["ok"] is False
    assert "already running" in result["error"].lower()


def test_hunt_event_translator_covers_kill_chain_event_types():
    # The translator must produce a sensible line for every event type
    # kill_chain.py actually emits (scanner_start/done/error, phase_*, crawl_*,
    # finding, info) so nothing silently vanishes from the terminal.
    from types import SimpleNamespace

    from beatrix.cli.suite import _hunt_event_to_line

    assert _hunt_event_to_line("phase_start", {"phase": "Recon", "description": "d"})["type"] == "phase"
    assert _hunt_event_to_line("phase_done", {"phase": "Recon", "findings": 2, "duration": 1.0})["type"] == "phase_done"
    assert _hunt_event_to_line("crawl_start", {})["type"] == "info"
    assert _hunt_event_to_line("crawl_done", {"pages": 1})["type"] == "info"
    assert _hunt_event_to_line("crawl_error", {"error": "x"})["type"] == "scanner_error"
    assert _hunt_event_to_line("scanner_start", {"scanner": "cors"})["type"] == "scanner_start"
    assert _hunt_event_to_line("scanner_done", {"scanner": "cors", "findings": 0}) is None  # quiet on zero
    assert _hunt_event_to_line("scanner_done", {"scanner": "cors", "findings": 1})["type"] == "scanner_done"
    assert _hunt_event_to_line("scanner_error", {"scanner": "cors", "error": "boom"})["type"] == "scanner_error"
    finding = SimpleNamespace(title="XSS", url="https://x", parameter="q", severity=None, evidence="ev")
    line = _hunt_event_to_line("finding", {"finding": finding})
    assert line["type"] == "finding" and "XSS" in line["text"]
    assert _hunt_event_to_line("info", {"message": "hi"})["type"] == "info"
    assert _hunt_event_to_line("unknown_event_type", {}) is None
    # http events are hidden unless debug is on; zero-finding scanner_done too.
    assert _hunt_event_to_line("http", {"method": "GET", "url": "https://x", "status": 200}) is None
    assert _hunt_event_to_line("scanner_done", {"scanner": "cors", "findings": 0}, debug=True)["type"] == "scanner_done"
    dbg = _hunt_event_to_line("http", {"method": "GET", "url": "https://x", "status": 200, "elapsed_ms": 12}, debug=True)
    assert dbg["type"] == "debug" and "GET" in dbg["text"] and "200" in dbg["text"]


# ── Scope: parsing/matching helpers ──────────────────────────────────────
def test_parse_scope_entry_normalizes_urls_and_bare_hosts():
    from beatrix.cli.suite import _parse_scope_entry

    assert _parse_scope_entry("https://Example.com/path?x=1") == "example.com"
    assert _parse_scope_entry("example.com:8443") == "example.com"
    assert _parse_scope_entry("  EXAMPLE.com  ") == "example.com"
    assert _parse_scope_entry("*.example.com") == "*.example.com"
    assert _parse_scope_entry("10.0.0.1") == "10.0.0.1"
    assert _parse_scope_entry("   ") is None
    assert _parse_scope_entry("") is None


def test_is_ip_literal():
    from beatrix.cli.suite import _is_ip_literal

    assert _is_ip_literal("10.0.0.1") is True
    assert _is_ip_literal("::1") is True
    assert _is_ip_literal("example.com") is False


def test_expand_for_crawler_adds_wildcards_except_ips_and_existing_wildcards():
    from beatrix.cli.suite import _expand_for_crawler

    assert _expand_for_crawler(["example.com"]) == ["example.com", "*.example.com"]
    assert _expand_for_crawler(["*.example.com"]) == ["*.example.com"]
    assert _expand_for_crawler(["10.0.0.1"]) == ["10.0.0.1"]


def test_host_in_scope_matches_subdomains():
    from beatrix.cli.suite import _host_in_scope

    assert _host_in_scope("https://api.example.com/x", ["example.com"]) is True
    assert _host_in_scope("https://example.com", ["example.com"]) is True
    assert _host_in_scope("https://evil.com", ["example.com"]) is False


def test_parse_scope_text_splits_dedups_and_drops_junk():
    from beatrix.cli.suite import _parse_scope_text

    raw = "https://example.com/x, api.example.com\n  ,, example.com   10.0.0.1"
    assert _parse_scope_text(raw) == ["example.com", "api.example.com", "10.0.0.1"]


# ── Scope: per-project storage (_ProjectStore) ───────────────────────────
def test_project_store_scope_starts_empty(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    assert store.get_scope(1) == []


def test_project_store_add_scope_merges_sorted_and_dedups(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    r = store.add_scope(1, ["b.com", "a.com"])
    assert r == {"ok": True, "scope": ["a.com", "b.com"]}
    r2 = store.add_scope(1, ["a.com", "c.com"])
    assert r2["scope"] == ["a.com", "b.com", "c.com"]


def test_project_store_remove_scope(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    store.add_scope(1, ["a.com", "b.com"])
    r = store.remove_scope(1, "a.com")
    assert r == {"ok": True, "scope": ["b.com"]}


def test_project_store_clear_scope(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    store.add_scope(1, ["a.com", "b.com"])
    r = store.clear_scope(1)
    assert r == {"ok": True, "scope": []}


def test_project_store_scope_isolated_per_project(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    store.new()  # project 2
    store.add_scope(1, ["a.com"])
    store.add_scope(2, ["b.com"])
    assert store.get_scope(1) == ["a.com"]
    assert store.get_scope(2) == ["b.com"]


def test_project_store_scope_persists_across_restart(tmp_path):
    sd = tmp_path / "suite"
    store = _ProjectStore(sd)
    store.add_scope(1, ["a.com"])
    store2 = _ProjectStore(sd)
    assert store2.get_scope(1) == ["a.com"]


# ── Scope: HTTP routes ────────────────────────────────────────────────────
def test_scope_get_empty_by_default(server):
    code, body = _get(server, "/scope?project=1")
    assert code == 200
    assert json.loads(body) == {"scope": [], "exclude": []}


def test_scope_get_defaults_to_active_project(server):
    _post(server, "/scope/add", {"project": 1, "text": "example.com"})
    assert json.loads(_get(server, "/scope")[1]) == {"scope": ["example.com"], "exclude": []}


def test_scope_add_route_parses_pasted_text(server):
    code, r = _post(server, "/scope/add",
                     {"project": 1, "text": "https://example.com/x, evil.com"})
    assert code == 200
    assert r == {"ok": True, "scope": ["evil.com", "example.com"]}


def test_scope_add_route_rejects_unparseable_text(server):
    code, r = _post(server, "/scope/add", {"project": 1, "text": "   "})
    assert code == 200
    assert r["ok"] is False
    assert "no valid" in r["error"]


def test_scope_remove_route(server):
    _post(server, "/scope/add", {"project": 1, "text": "a.com b.com"})
    code, r = _post(server, "/scope/remove", {"project": 1, "entry": "a.com"})
    assert code == 200
    assert r == {"ok": True, "scope": ["b.com"]}


def test_scope_clear_route(server):
    _post(server, "/scope/add", {"project": 1, "text": "a.com b.com"})
    code, r = _post(server, "/scope/clear", {"project": 1})
    assert code == 200
    assert r == {"ok": True, "scope": []}


def test_scope_isolated_between_projects_over_http(server):
    _post(server, "/projects/new", {})  # project 2
    _post(server, "/scope/add", {"project": 1, "text": "a.com"})
    _post(server, "/scope/add", {"project": 2, "text": "b.com"})
    assert json.loads(_get(server, "/scope?project=1")[1]) == {"scope": ["a.com"], "exclude": []}
    assert json.loads(_get(server, "/scope?project=2")[1]) == {"scope": ["b.com"], "exclude": []}


# ── Scope: enforcement wired into start_hunt_run / start_ghost_run ───────
def test_start_ghost_run_passes_project_scope_as_allowed_hosts(server, monkeypatch):
    # start_ghost_run does `from ...runner import run_investigation` and
    # `from ...config import GhostV2Config` locally on every call, so patch
    # the attributes on those modules directly (the local import resolves to
    # whatever's on the module at call time).
    import beatrix.ai.ghost2.config as config_mod
    import beatrix.ai.ghost2.core.runner as runner_mod

    captured = {}

    async def fake_run_investigation(target, **kwargs):
        captured["allowed_hosts"] = kwargs.get("allowed_hosts")
        return {"verdict": "SECURE", "final_output": ""}

    monkeypatch.setattr(runner_mod, "run_investigation", fake_run_investigation)
    monkeypatch.setattr(config_mod.GhostV2Config, "missing_key_message", lambda self: None)
    monkeypatch.setattr(config_mod.GhostV2Config, "load",
                         staticmethod(lambda: config_mod.GhostV2Config(model="openrouter/x/y", api_key="k")))

    server.projects.add_scope(1, ["example.com", "api.example.com"])
    result = server.start_ghost_run("https://example.com", "find bugs", 1)
    assert result["ok"] is True

    import time
    for _ in range(50):
        if "allowed_hosts" in captured:
            break
        time.sleep(0.05)
    assert captured["allowed_hosts"] == ["api.example.com", "example.com"]


def test_start_hunt_run_filters_out_of_scope_findings(server, monkeypatch):
    from datetime import datetime
    from types import SimpleNamespace

    from beatrix.core.types import Finding, Severity

    async def fake_hunt(self, target, preset, ai, modules, scope=None, **kwargs):
        in_scope_finding = Finding(
            title="SQLi", url="https://example.com/x", severity=Severity.HIGH,
            scanner_module="injection",
        )
        out_of_scope_finding = Finding(
            title="XSS", url="https://evil.com/x", severity=Severity.HIGH,
            scanner_module="injection",
        )
        self.findings = [in_scope_finding, out_of_scope_finding]
        if self._on_event:
            self._on_event("finding", {"finding": in_scope_finding})
            self._on_event("finding", {"finding": out_of_scope_finding})
        return SimpleNamespace(started_at=datetime.now(), phase_results={})

    import beatrix.core.engine as engine_mod
    monkeypatch.setattr(engine_mod.BeatrixEngine, "hunt", fake_hunt)

    server.projects.add_scope(1, ["example.com"])
    result = server.start_hunt_run("https://example.com", ["injection"], "custom", False, 1)
    assert result["ok"] is True

    import time
    broker = server.hunt_brokers.get("1")
    for _ in range(50):
        if broker is not None and broker.since(10**9)["done"]:
            break
        time.sleep(0.05)

    events = broker.since(0)["events"]
    texts = " ".join(e.get("text", "") for e in events)
    assert "Skipped out-of-scope finding" in texts
    assert "excluded from the final report" in texts
    finding_events = [e for e in events if e["type"] == "finding"]
    assert len(finding_events) == 1  # the evil.com finding never became a terminal line


# ── Stop button: cancel an in-flight Ghost/Hunt run on demand ────────────
def test_stop_ghost_run_when_nothing_running(server):
    code, r = _post(server, "/ghost/stop", {"project": 1})
    assert code == 200
    assert r["ok"] is False
    assert "no scan running" in r["error"].lower()


def test_stop_hunt_run_when_nothing_running(server):
    code, r = _post(server, "/hunt/stop", {"project": 1})
    assert code == 200
    assert r["ok"] is False
    assert "no scan running" in r["error"].lower()


def test_ghost_stop_cancels_in_flight_run(server, monkeypatch):
    import asyncio
    import time

    import beatrix.ai.ghost2.config as config_mod
    import beatrix.ai.ghost2.core.runner as runner_mod

    async def fake_run_investigation(target, **kwargs):
        await asyncio.Event().wait()  # blocks forever unless the task is cancelled

    monkeypatch.setattr(runner_mod, "run_investigation", fake_run_investigation)
    monkeypatch.setattr(config_mod.GhostV2Config, "missing_key_message", lambda self: None)
    monkeypatch.setattr(config_mod.GhostV2Config, "load",
                         staticmethod(lambda: config_mod.GhostV2Config(model="openrouter/x/y", api_key="k")))

    assert server.start_ghost_run("https://example.com", "find bugs", 1)["ok"] is True

    for _ in range(50):
        if "1" in server.ghost_tasks:
            break
        time.sleep(0.05)
    assert "1" in server.ghost_tasks

    assert server.stop_ghost_run(1) == {"ok": True}

    broker = server.ghost_brokers["1"]
    for _ in range(50):
        if broker.since(10**9)["done"]:
            break
        time.sleep(0.05)
    events = broker.since(0)["events"]
    assert events[-1]["type"] == "verdict" and events[-1]["text"] == "stopped"
    assert "1" not in server.ghost_tasks  # cleaned up after teardown


def test_hunt_stop_cancels_in_flight_run(server, monkeypatch):
    import asyncio
    import time

    from beatrix.core.types import Finding, Severity

    async def fake_hunt(self, target, preset, ai, modules, scope=None, **kwargs):
        self.findings = [Finding(title="partial", url=target, severity=Severity.LOW)]
        await asyncio.Event().wait()  # blocks forever unless the task is cancelled

    import beatrix.core.engine as engine_mod
    monkeypatch.setattr(engine_mod.BeatrixEngine, "hunt", fake_hunt)

    assert server.start_hunt_run("https://example.com", ["injection"], "custom", False, 1)["ok"] is True

    for _ in range(50):
        if "1" in server.hunt_tasks:
            break
        time.sleep(0.05)
    assert "1" in server.hunt_tasks

    assert server.stop_hunt_run(1) == {"ok": True}

    broker = server.hunt_brokers["1"]
    for _ in range(50):
        if broker.since(10**9)["done"]:
            break
        time.sleep(0.05)
    events = broker.since(0)["events"]
    assert events[-1]["type"] == "verdict" and events[-1]["text"] == "stopped"
    assert "1 finding" in events[-1]["detail"]
    assert "1" not in server.hunt_tasks


def test_stop_route_defaults_to_active_project(server, monkeypatch):
    import asyncio
    import time

    import beatrix.ai.ghost2.config as config_mod
    import beatrix.ai.ghost2.core.runner as runner_mod

    async def fake_run_investigation(target, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(runner_mod, "run_investigation", fake_run_investigation)
    monkeypatch.setattr(config_mod.GhostV2Config, "missing_key_message", lambda self: None)
    monkeypatch.setattr(config_mod.GhostV2Config, "load",
                         staticmethod(lambda: config_mod.GhostV2Config(model="openrouter/x/y", api_key="k")))

    _post(server, "/ghost/run", {"target": "https://example.com", "project": 1})
    for _ in range(50):
        if "1" in server.ghost_tasks:
            break
        time.sleep(0.05)

    code, r = _post(server, "/ghost/stop", {})  # no project -> active project (1)
    assert code == 200 and r["ok"] is True


# ── Issues: per-project store (serialization, dedup, edit, delete) ───────
def _finding(**kw):
    from beatrix.core.types import Confidence, Finding, Severity
    defaults = dict(title="SQLi in id", severity=Severity.HIGH, confidence=Confidence.FIRM,
                    url="https://example.com/search?id=1", parameter="id", payload="1'",
                    description="classic sqli", impact="db read", remediation="parameterize",
                    evidence={"error": "SQL syntax"}, cwe_id="CWE-89",
                    references=["https://owasp.org/sqli"], scanner_module="injection",
                    request="GET /search?id=1", response="SQL error", poc_curl="curl ...",
                    reproduction_steps=["step1", "step2"], validated=True)
    defaults.update(kw)
    return Finding(**defaults)


def test_issue_serialization_full_detail(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    summary = store.add_finding(1, _finding(), "injection", "hunt")
    assert summary["id"] == 1 and summary["severity"] == "high" and summary["host"] == "example.com"
    d = store.get(1, 1)
    assert d["path"] == "/search" and d["parameter"] == "id" and d["module"] == "injection"
    assert d["cwe"] == "CWE-89" and d["origin"] == "hunt" and d["validated"] is True
    # references include the finding's own + a derived CWE docs link
    assert "https://owasp.org/sqli" in d["references"]
    assert "https://cwe.mitre.org/data/definitions/89.html" in d["references"]
    # dict evidence is stringified
    assert "SQL syntax" in d["evidence"]
    assert d["reproduction_steps"] == ["step1", "step2"]


def test_severity_normalizer_downgrades_only_informational_lows():
    # The exact reported case and its disclosure siblings → info.
    for t in ["Internal Hostnames Disclosed in JS Bundles (2 hosts)",
              "WebSocket Endpoints Disclosed (3 URLs)",
              "Auth-Related Storage Keys in JS (4 keys)",
              "API Routes Disclosed in JS Bundles (12 endpoints)",
              "Server Version Disclosure", "Source Map Disclosure"]:
        assert _normalize_severity(t, "low") == "info", t
    # Real secrets are NEVER hidden — they stay low.
    for t in ["Hardcoded Secret Disclosed in JS", "AWS Access Token Disclosed",
              "API Key Disclosed in Source"]:
        assert _normalize_severity(t, "low") == "low", t
    # Real low-severity vulns are untouched.
    for t in ["Open Redirect in return_url", "Reflected XSS in q parameter",
              "Missing X-Frame-Options header", "CORS misconfiguration"]:
        assert _normalize_severity(t, "low") == "low", t
    # Never touches anything above low, even a matching title.
    assert _normalize_severity("Internal Hostnames Disclosed", "medium") == "medium"
    assert _normalize_severity("Secret Disclosed", "high") == "high"


def test_info_high_signal_classification():
    clf = _normalize_severity
    # An exact software version → info-high (feed it to a CVE search).
    assert clf("Server Version Disclosure", "low", "Server: nginx/1.18.0") == "info-high"
    assert clf("X-Powered-By Header Present", "info", "X-Powered-By: PHP/7.2.24") == "info-high"
    assert clf("Software Version Detected", "low", "Apache/2.4.29 (Ubuntu)") == "info-high"
    assert clf("Outdated jQuery 1.4.2 in use", "info") == "info-high"
    assert clf("OpenSSH Banner", "info", "SSH-2.0-OpenSSH_7.4") == "info-high"
    # A routable backend/origin IP → info-high (direct-hit / WAF bypass).
    assert clf("Origin IP Address Disclosed", "low", "backend 34.201.5.10 behind CDN") == "info-high"
    # Inert info stays plain info.
    assert clf("Internal Hostnames Disclosed", "low", "127.0.0.2, 192.168.1.2") == "info"
    assert clf("API Routes Disclosed in JS Bundles", "low") == "info"
    assert clf("Server Version Disclosure", "low") == "info"      # no concrete version → not high-signal
    # Guards hold: secret stays, real vuln untouched, version-only-in-remediation not promoted.
    assert clf("Hardcoded Secret Disclosed in JS", "low", "AKIA... nginx/1.18") == "low"
    assert clf("SQL Injection in id", "high", "MySQL 5.7") == "high"
    assert clf("Missing X-Frame-Options header", "low", "recommend nginx 1.25") == "low"


def test_info_high_is_a_valid_retriage_severity(server):
    # The new tier is sortable and a legal manual re-triage target.
    from beatrix.cli.suite import _SEVERITY_ORDER
    assert _SEVERITY_ORDER["low"] < _SEVERITY_ORDER["info-high"] < _SEVERITY_ORDER["info"]
    server.issues.add_finding(1, _finding(), "injection", "hunt")
    assert _post(server, "/issues/update", {"project": 1, "id": 1, "severity": "info-high"})[1]["ok"] is True
    assert json.loads(_get(server, "/issues/detail?project=1&id=1")[1])["issue"]["severity"] == "info-high"


def test_issue_serialization_normalizes_informational_severity():
    from beatrix.core.types import Finding, Severity
    iss = _finding_to_issue(Finding(
        title="Internal Hostnames Disclosed in JS Bundles (2 hosts)",
        severity=Severity.LOW, url="https://x.com",
        scanner_module="js_bundle"), "hunt", "hunt")
    assert iss["severity"] == "info"          # the Issues tab shows it honestly
    assert iss["orig_severity"] == "low"      # scanner's raw call kept for audit


def test_issue_dedup_is_idempotent(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    assert store.add_finding(1, _finding(), "injection", "hunt") is not None
    assert store.add_finding(1, _finding(), "injection", "hunt") is None  # same key -> no dup
    assert store.count(1) == 1
    # a different URL is a distinct issue
    assert store.add_finding(1, _finding(url="https://example.com/x?id=2"), "injection", "hunt") is not None
    assert store.count(1) == 2


def test_issue_update_severity_and_highlight(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    store.add_finding(1, _finding(), "injection", "hunt")
    assert store.update(1, 1, severity="critical")["issue"]["severity"] == "critical"
    assert store.update(1, 1, highlight="red")["issue"]["highlight"] == "red"
    assert store.update(1, 1, highlight="none")["issue"]["highlight"] is None
    assert store.update(1, 1, severity="bogus")["ok"] is False
    assert store.update(1, 1, highlight="chartreuse")["ok"] is False
    assert store.update(1, 999, severity="low")["ok"] is False


def test_issue_false_positive_toggle_and_badge_count(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    store.add_finding(1, _finding(), "injection", "hunt")
    store.add_finding(1, _finding(url="https://example.com/x?id=2"), "injection", "hunt")

    # New issues start un-flagged and count toward the badge.
    assert store.list(1)[0]["false_positive"] is False
    assert store.count(1) == 2

    # Marking one as a false positive drops it from the badge count but keeps
    # the issue in the list.
    res = store.update(1, 1, false_positive=True)
    assert res["ok"] is True and res["issue"]["false_positive"] is True
    assert store.get(1, 1)["false_positive"] is True
    assert store.count(1) == 1
    assert len(store.list(1)) == 2

    # Un-marking restores it to the count.
    assert store.update(1, 1, false_positive=False)["issue"]["false_positive"] is False
    assert store.count(1) == 2

    # A user's false-positive decision survives a re-scan (completion sweep).
    store.update(1, 2, false_positive=True)
    assert store.add_finding(1, _finding(url="https://example.com/x?id=2"), "injection", "hunt") is None
    assert store.get(1, 2)["false_positive"] is True


# ── Resumable scans: checkpoint store ────────────────────────────────────
def test_scan_checkpoint_records_completed_and_resumes(tmp_path):
    from beatrix.cli.suite import _ScanCheckpoint
    cp = _ScanCheckpoint(_ProjectStore(tmp_path / "suite"))

    cp.start(1, "example.com", ["cors", "xss", "sqli"], "custom", ai=False, debug=True)
    got = cp.get(1)
    assert got["status"] == "running" and got["completed_modules"] == []
    assert got["debug"] is True and got["target"] == "example.com"
    assert got["modules"] == ["cors", "xss", "sqli"]

    cp.mark_module_done(1, "cors")
    cp.mark_module_done(1, "cors")          # idempotent — no duplicates
    cp.mark_module_done(1, "xss")
    assert cp.get(1)["completed_modules"] == ["cors", "xss"]

    # A stop/crash marks it interrupted; resume() flips it back to running and
    # returns the surviving completed set so the run can skip those scanners.
    cp.set_status(1, "interrupted")
    resumed = cp.resume(1)
    assert resumed["status"] == "running"
    assert resumed["completed_modules"] == ["cors", "xss"]
    assert cp.get(1)["status"] == "running"

    # A completed checkpoint is not resumable; clear removes it entirely.
    cp.set_status(1, "complete")
    assert cp.resume(1) == {}
    cp.clear(1)
    assert cp.get(1) == {}
    assert cp.resume(1) == {}


def test_scan_checkpoint_isolated_per_project(tmp_path):
    from beatrix.cli.suite import _ScanCheckpoint
    cp = _ScanCheckpoint(_ProjectStore(tmp_path / "suite"))
    cp.start(1, "a.com", ["cors"], "custom", ai=False, debug=False)
    cp.start(2, "b.com", ["xss"], "custom", ai=False, debug=False)
    cp.mark_module_done(1, "cors")
    assert cp.get(1)["completed_modules"] == ["cors"]
    assert cp.get(2)["completed_modules"] == []
    assert cp.get(2)["target"] == "b.com"


# ── Persistent event log: disk-backed _Broker ────────────────────────────
def test_broker_persists_and_reloads(tmp_path):
    from beatrix.cli.ghost_web import _Broker
    path = str(tmp_path / "hunt_events.jsonl")

    b = _Broker(meta={"target": "x"}, persist_path=path)
    b.emit({"type": "phase", "text": "one"})
    b.emit({"type": "info", "text": "two"})
    assert len(b.since(0)["events"]) == 2

    # A fresh process (no in-memory broker) rebuilds the transcript from disk,
    # finished, with contiguous seq numbering.
    b2 = _Broker.load(path, meta={"target": "x"})
    evs = b2.since(0)["events"]
    assert [e["text"] for e in evs] == ["one", "two"]
    assert [e["seq"] for e in evs] == [1, 2]
    assert b2.since(0)["done"] is True

    # A new run seeds history then continues the seq counter (no duplicate
    # rewrite of the seeded events to disk).
    b3 = _Broker(meta={"target": "x"}, persist_path=path)
    b3.seed(_Broker.read_events(path))
    b3.emit({"type": "phase", "text": "three"})
    texts = [e["text"] for e in b3.since(0)["events"]]
    assert texts == ["one", "two", "three"]
    # Disk now has exactly the three lines (seed didn't re-append the first two).
    assert len(_Broker.read_events(path)) == 3


def test_crawler_debug_hook_emits_one_http_line_per_request():
    # Debug mode routes every crawl request through the httpx response hook so
    # the terminal shows a line per fetch; silent when debug is off.
    import asyncio

    import httpx

    from beatrix.scanners.crawler import TargetCrawler
    got = []
    c = TargetCrawler(max_pages=1, timeout=5)
    c._debug_emit = lambda ev, data: got.append((ev, data))

    async def run():
        def handler(req):
            return httpx.Response(200)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                     event_hooks={"response": [c._debug_response_hook]}) as client:
            await client.get("https://example.com/a")
            await client.get("https://example.com/b?q=1")

    c._debug = True
    asyncio.run(run())
    assert len(got) == 2
    assert got[0][0] == "http" and got[0][1]["scanner"] == "crawl"
    assert got[1][1]["url"].endswith("/b?q=1") and got[1][1]["status"] == 200

    got.clear()
    c._debug = False
    asyncio.run(run())
    assert got == []


def test_broker_without_persist_is_memory_only(tmp_path):
    # Ghost's path: no persist_path → nothing written, original behavior intact.
    from beatrix.cli.ghost_web import _Broker
    b = _Broker(meta={"target": "x"})
    b.emit({"type": "info", "text": "hi"})
    assert not (tmp_path / "hunt_events.jsonl").exists()
    assert b.since(0)["events"][0]["text"] == "hi"


def test_hunt_checkpoint_and_clear_endpoints(server):
    # Seed a checkpoint + persisted log directly, then drive the HTTP surface the
    # Hunt view uses.
    server.scan_checkpoints.start(1, "example.com", ["cors", "xss"], "custom",
                                  ai=False, debug=False)
    server.scan_checkpoints.mark_module_done(1, "cors")
    server.scan_checkpoints.set_status(1, "interrupted")

    code, raw = _get(server, "/hunt/checkpoint?project=1")
    cp = json.loads(raw)
    assert code == 200
    assert cp["status"] == "interrupted" and cp["completed_count"] == 1 and cp["total"] == 2
    assert cp["running"] is False

    # Persisted event log survives with no live broker (post-restart behavior).
    path = server._hunt_persist_path(1)
    from beatrix.cli.ghost_web import _Broker
    _Broker(meta={}, persist_path=path).emit({"type": "info", "text": "persisted"})
    evs = json.loads(_get(server, "/hunt/events?since=0&project=1")[1])
    assert any(e["text"] == "persisted" for e in evs["events"])

    # Clear log wipes the transcript; clear checkpoint removes the resume offer.
    assert _post(server, "/hunt/clear", {"project": 1})[1]["ok"] is True
    assert json.loads(_get(server, "/hunt/events?since=0&project=1")[1])["events"] == []
    assert _post(server, "/hunt/checkpoint/clear", {"project": 1})[1]["ok"] is True
    assert json.loads(_get(server, "/hunt/checkpoint?project=1")[1]) == {}


def test_dedup_refreshes_stale_severity_but_not_user_retriage(tmp_path):
    import json

    from beatrix.core.types import Severity
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    f = lambda: _finding(title="Internal Hostnames Disclosed in JS Bundles (2 hosts)",
                         url="https://x.com/js", parameter="", scanner_module="js_bundle",
                         severity=Severity.LOW)
    store.add_finding(1, f(), "js_bundle", "hunt")
    # simulate an issue captured before the classifier fix: stored as a stale low
    data = json.loads(store._file(1).read_text())
    data["issues"][0]["severity"] = "low"
    store._file(1).write_text(json.dumps(data))

    # a re-scan re-finds it (now normalized to info) → the existing issue refreshes
    assert store.add_finding(1, f(), "js_bundle", "hunt") is not None
    assert store.get(1, 1)["severity"] == "info"
    assert store.count(1) == 1                       # refreshed in place, not duplicated
    # a second identical re-scan is a no-op (no severity change)
    assert store.add_finding(1, f(), "js_bundle", "hunt") is None

    # once a human re-triages it, a later re-scan must NOT overwrite that decision
    store.update(1, 1, severity="medium")
    store.add_finding(1, f(), "js_bundle", "hunt")
    assert store.get(1, 1)["severity"] == "medium"


def test_issue_edit_survives_completion_sweep(tmp_path):
    # A user re-triages an issue; a later re-add of the same finding (the Ghost
    # completion sweep, or a scanner re-emit) must NOT reset their severity.
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    store.add_finding(1, _finding(), "injection", "hunt")
    store.update(1, 1, severity="low")
    assert store.add_finding(1, _finding(), "injection", "hunt") is None
    assert store.get(1, 1)["severity"] == "low"


def test_issue_delete_and_clear(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    store.add_finding(1, _finding(), "injection", "hunt")
    store.add_finding(1, _finding(url="https://example.com/x?id=2"), "injection", "hunt")
    assert store.delete(1, 1)["ok"] is True
    assert store.delete(1, 1)["ok"] is False
    assert store.count(1) == 1
    store.clear(1)
    assert store.count(1) == 0


def test_issues_isolated_and_persisted_per_project(tmp_path):
    ps = _ProjectStore(tmp_path / "suite")
    ps.new()  # project 2
    store = _IssueStore(ps)
    store.add_finding(1, _finding(), "injection", "hunt")
    store.add_finding(2, _finding(url="https://example.com/x?id=2"), "injection", "hunt")
    assert store.count(1) == 1 and store.count(2) == 1
    # a fresh store over the same dir sees the persisted issues
    store2 = _IssueStore(ps)
    assert store2.count(1) == 1 and store2.get(1, 1)["title"] == "SQLi in id"


# ── Issues: HTTP routes ──────────────────────────────────────────────────
def test_issues_routes_empty_by_default(server):
    assert json.loads(_get(server, "/issues?project=1")[1]) == {"issues": []}
    assert json.loads(_get(server, "/issues/count?project=1")[1]) == {"count": 0}
    assert json.loads(_get(server, "/issues/detail?project=1&id=1")[1]) == {"issue": None}


def test_issues_routes_full_lifecycle(server):
    server.issues.add_finding(1, _finding(), "injection", "hunt")
    lst = json.loads(_get(server, "/issues?project=1")[1])["issues"]
    assert len(lst) == 1 and lst[0]["title"] == "SQLi in id"
    assert json.loads(_get(server, "/issues/count?project=1")[1])["count"] == 1
    detail = json.loads(_get(server, "/issues/detail?project=1&id=1")[1])["issue"]
    assert detail["remediation"] == "parameterize"

    up = _post(server, "/issues/update", {"project": 1, "id": 1, "severity": "critical", "highlight": "blue"})[1]
    assert up["ok"] is True and up["issue"]["severity"] == "critical" and up["issue"]["highlight"] == "blue"

    assert _post(server, "/issues/delete", {"project": 1, "id": 1})[1]["ok"] is True
    assert json.loads(_get(server, "/issues/count?project=1")[1])["count"] == 0


def test_issues_route_defaults_to_active_project(server):
    server.issues.add_finding(1, _finding(), "injection", "hunt")
    assert json.loads(_get(server, "/issues")[1])["issues"][0]["id"] == 1


def test_issues_clear_route(server):
    server.issues.add_finding(1, _finding(), "injection", "hunt")
    server.issues.add_finding(1, _finding(url="https://example.com/x?id=2"), "injection", "hunt")
    assert _post(server, "/issues/clear", {"project": 1})[1]["ok"] is True
    assert json.loads(_get(server, "/issues/count?project=1")[1])["count"] == 0


# ── Issues: live capture from Hunt + Ghost runs ──────────────────────────
def test_hunt_run_captures_findings_as_issues(server, monkeypatch):
    from datetime import datetime
    from types import SimpleNamespace

    from beatrix.core.types import Finding, Severity

    async def fake_hunt(self, target, preset, ai, modules, scope=None, **kwargs):
        f = Finding(title="Missing CSP", url="https://example.com/", severity=Severity.LOW,
                    scanner_module="headers")
        self.findings = [f]
        if self._on_event:
            self._on_event("finding", {"finding": f, "scanner": "headers"})
        return SimpleNamespace(started_at=datetime.now(), phase_results={})

    import beatrix.core.engine as engine_mod
    monkeypatch.setattr(engine_mod.BeatrixEngine, "hunt", fake_hunt)

    server.start_hunt_run("https://example.com", ["headers"], "custom", False, 1)
    import time
    for _ in range(60):
        if server.issues.count(1) >= 1:
            break
        time.sleep(0.05)
    issues = server.issues.list(1)
    assert len(issues) == 1
    assert issues[0]["title"] == "Missing CSP" and issues[0]["origin"] == "hunt"
    assert issues[0]["module"] == "headers"


def test_ghost_run_captures_findings_as_issues(server, monkeypatch):
    import beatrix.ai.ghost2.config as config_mod
    import beatrix.ai.ghost2.core.runner as runner_mod
    from beatrix.core.types import Finding, Severity

    captured_finding = Finding(title="SSRF in url param", url="https://example.com/fetch?url=x",
                               severity=Severity.HIGH, scanner_module="ghost2", parameter="url")

    async def fake_run_investigation(target, **kwargs):
        # exercise the live sink exactly like session.add_finding would
        cb = kwargs.get("on_finding")
        if cb:
            cb(captured_finding)
        return {"verdict": "VULNERABLE", "final_output": "", "findings": [captured_finding]}

    monkeypatch.setattr(runner_mod, "run_investigation", fake_run_investigation)
    monkeypatch.setattr(config_mod.GhostV2Config, "missing_key_message", lambda self: None)
    monkeypatch.setattr(config_mod.GhostV2Config, "load",
                        staticmethod(lambda: config_mod.GhostV2Config(model="openrouter/x/y", api_key="k")))

    assert server.start_ghost_run("https://example.com", "find bugs", 1)["ok"] is True
    import time
    for _ in range(60):
        if server.issues.count(1) >= 1:
            break
        time.sleep(0.05)
    # live sink + completion sweep must NOT double-count (dedup)
    issues = server.issues.list(1)
    assert len(issues) == 1
    assert issues[0]["title"] == "SSRF in url param" and issues[0]["origin"] == "ghost"


def test_ghost_session_on_finding_sink_fires():
    # The mechanism the Suite relies on: add_finding invokes session.on_finding
    # with the full Finding object (root + subagents share the session).
    import asyncio

    from beatrix.ai.ghost2.core.session import GhostSession, Scope
    from beatrix.core.types import Finding, Severity

    seen = []

    async def run():
        s = GhostSession(Scope(target="https://example.com"))
        s.on_finding = lambda f: seen.append(f)
        await s.add_finding(Finding(title="x", url="https://example.com", severity=Severity.LOW))
        # duplicate (same title+url) shouldn't fire the sink again
        await s.add_finding(Finding(title="x", url="https://example.com", severity=Severity.LOW))

    asyncio.run(run())
    assert len(seen) == 1 and seen[0].title == "x"


# ── Repeater: Burp-style compose / send / resend (per-project) ──────────
def test_repeater_parse_raw_request():
    m, target, ver, headers, body = _parse_raw_request(
        "POST /api/x?q=1 HTTP/1.1\r\nHost: ex.com\r\n"
        "Content-Type: application/json\r\n\r\n{\"a\": 1}")
    assert (m, target, ver) == ("POST", "/api/x?q=1", "HTTP/1.1")
    assert headers == [("Host", "ex.com"), ("Content-Type", "application/json")]
    assert body == '{"a": 1}'


def test_repeater_parse_preserves_duplicate_headers():
    # Two of the same header must survive — it matters when testing.
    _, _, _, headers, _ = _parse_raw_request(
        "GET / HTTP/1.1\nCookie: a=1\nCookie: b=2\n\n")
    assert headers == [("Cookie", "a=1"), ("Cookie", "b=2")]


def test_repeater_parse_lf_only_and_no_body():
    m, target, ver, headers, body = _parse_raw_request("GET /health HTTP/1.1\nHost: h\n")
    assert m == "GET" and target == "/health" and headers == [("Host", "h")] and body == ""


def test_repeater_parse_does_not_treat_body_colons_as_headers():
    # The XXE bug: a DOCTYPE/ENTITY line with a colon (http://) must stay in the
    # body, not be parsed as a header — even without a blank line before it.
    req = ("POST /u HTTP/1.1\nHost: t.com\nContent-Type: application/xml\n"
           '<?xml version="1.0"?>\n<!ENTITY x SYSTEM "http://evil/">\n')
    m, target, ver, headers, body = _parse_raw_request(req)
    names = [k for k, _ in headers]
    assert names == ["Host", "Content-Type"]          # the XML lines are NOT headers
    assert '<?xml version="1.0"?>' in body and "ENTITY" in body


def test_repeater_parse_stops_headers_at_first_non_header_line():
    # A well-formed request with a blank line still behaves; the body (JSON with
    # colons) is untouched.
    req = 'POST /api HTTP/1.1\nHost: h\nContent-Type: application/json\n\n{"url": "http://x"}'
    _, _, _, headers, body = _parse_raw_request(req)
    assert [k for k, _ in headers] == ["Host", "Content-Type"]
    assert body == '{"url": "http://x"}'


def test_repeater_seeds_one_tab_per_project(server):
    d = json.loads(_get(server, "/repeater")[1])
    assert len(d["tabs"]) == 1
    t = d["tabs"][0]
    assert t["label"] == 1 and t["response"] is None and d["active"] == t["id"]
    assert t["request"].startswith("GET / HTTP/1.1")


def test_repeater_tabs_use_lowest_free_label(server):
    _post(server, "/repeater/new", {})            # label 2
    _, d3 = _post(server, "/repeater/new", {})     # label 3
    assert [t["label"] for t in d3["tabs"]] == [1, 2, 3]
    mid = d3["tabs"][1]["id"]
    _post(server, "/repeater/close", {"id": mid})  # frees label 2
    _, d = _post(server, "/repeater/new", {})
    assert d["tabs"][-1]["label"] == 2             # reused, not climbed to 4


def test_repeater_close_last_reseeds(server):
    only = json.loads(_get(server, "/repeater")[1])["tabs"][0]["id"]
    _, d = _post(server, "/repeater/close", {"id": only})
    assert d["ok"] is True and len(d["tabs"]) == 1  # pane never empties


def test_repeater_send_round_trips_and_records_history(server):
    # Point the Repeater at the suite's own /projects endpoint — a real send.
    tid = json.loads(_get(server, "/repeater")[1])["tabs"][0]["id"]
    host = server.url.split("//", 1)[1].rstrip("/")
    req = "GET /projects HTTP/1.1\r\nHost: %s\r\n\r\n" % host
    _, d = _post(server, "/repeater/send",
                 {"id": tid, "request": req, "target": server.url})
    resp = d["response"]
    assert resp["status"] == 200 and resp["error"] is None
    assert '"projects"' in resp["body"] and resp["size"] > 0
    # raw preserves the server's actual status line (stdlib replies HTTP/1.0).
    assert resp["raw"].splitlines()[0].endswith("200 OK")
    assert len(d["tab"]["history"]) == 1           # send was recorded

    # A second send appends to history; the tab remembers its last response.
    _post(server, "/repeater/send", {"id": tid, "request": req, "target": server.url})
    reloaded = json.loads(_get(server, "/repeater")[1])["tabs"][0]
    assert len(reloaded["history"]) == 2 and reloaded["response"]["status"] == 200


def test_repeater_send_reports_transport_error_without_crashing(server):
    tid = json.loads(_get(server, "/repeater")[1])["tabs"][0]["id"]
    _, d = _post(server, "/repeater/send", {
        "id": tid, "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "target": "http://127.0.0.1:1"})            # nothing listening
    assert d["ok"] is True                          # the send call itself succeeds
    assert d["response"]["status"] is None and d["response"]["error"]


def test_repeater_is_isolated_between_projects(server):
    # Editing a tab in project 1 must not leak into a new project's tabs.
    tid = json.loads(_get(server, "/repeater?project=1")[1])["tabs"][0]["id"]
    _post(server, "/repeater/save",
          {"project": 1, "id": tid, "request": "GET /secret HTTP/1.1\n\n"})
    _, d2 = _post(server, "/projects/new", {})
    new_pid = d2["projects"][-1]["id"]
    other = json.loads(_get(server, "/repeater?project=%d" % new_pid)[1])["tabs"][0]
    assert "secret" not in other["request"]         # fresh template, not project 1's edit


def test_repeater_save_and_rename_persist(server):
    tid = json.loads(_get(server, "/repeater")[1])["tabs"][0]["id"]
    _post(server, "/repeater/save",
          {"id": tid, "request": "PUT /x HTTP/1.1\n\n", "target": "https://t.example"})
    _post(server, "/repeater/rename", {"id": tid, "name": "login flow"})
    t = json.loads(_get(server, "/repeater")[1])["tabs"][0]
    assert t["request"].startswith("PUT /x") and t["target"] == "https://t.example"
    assert t["name"] == "login flow"


# ── Issue detail: Request/Response tabs must always populate per issue ───
# A finding whose scanner/agent never captured the raw HTTP still has to show a
# real, per-issue request (and a response from its evidence), clearly flagged as
# reconstructed — never the blank "—" the tabs used to render.
def _bare_finding(**kw):
    # Deliberately minimal: no request/response/evidence unless a test sets them,
    # so the reconstruction path is what's under test.
    from beatrix.core.types import Finding, Severity
    kw.setdefault("severity", Severity.INFO)
    return Finding(**kw)


def test_issue_request_reconstructed_from_metadata_when_absent():
    iss = _finding_to_issue(
        _bare_finding(title="SQLi", url="https://x.com/api/item?ref=9",
                      parameter="id", payload="' OR 1=1--"), "hunt", "hunt")
    assert iss["request_synthesized"] is True
    assert iss["request"].startswith("GET /api/item?ref=9&id=' OR 1=1-- HTTP/1.1")
    assert "Host: x.com" in iss["request"]


def test_issue_request_replaces_existing_param_value_with_payload():
    # The vulnerable param already sits in the URL with a benign value — the
    # reconstruction must show the PAYLOAD there, not silently drop it.
    iss = _finding_to_issue(
        _bare_finding(title="XSS", url="https://x.com/search?q=1&page=2",
                      parameter="q", payload="<script>alert(1)</script>"), "hunt", "hunt")
    assert "q=<script>alert(1)</script>" in iss["request"]
    assert "page=2" in iss["request"]                 # other params untouched
    assert iss["request"].count("q=") == 1            # replaced, not duplicated


def test_issue_request_reconstructs_post_body_from_curl():
    iss = _finding_to_issue(
        _bare_finding(title="x", url="https://x.com/login", parameter="user",
                      payload="admin", poc_curl="curl -d 'user=admin' https://x.com/login"),
        "hunt", "hunt")
    assert iss["request"].startswith("POST /login HTTP/1.1")
    assert "user=admin" in iss["request"]
    assert "Content-Length: 10" in iss["request"]     # body length, recomputed


def test_issue_request_preserves_real_capture():
    raw = "GET /real HTTP/1.1\r\nHost: x.com\r\nX-Probe: 1\r\n\r\n"
    iss = _finding_to_issue(_bare_finding(title="x", url="https://x.com/", request=raw),
                            "hunt", "hunt")
    assert iss["request"] == raw and iss["request_synthesized"] is False


def test_issue_response_falls_back_to_evidence():
    iss = _finding_to_issue(
        _bare_finding(title="x", url="https://x.com/", evidence="HTTP/1.1 500\nSQL error"),
        "hunt", "hunt")
    assert iss["response"] == "HTTP/1.1 500\nSQL error"
    assert iss["response_synthesized"] is True


def test_issue_response_empty_stays_empty_without_false_flag():
    iss = _finding_to_issue(_bare_finding(title="x", url="https://x.com/p"), "hunt", "hunt")
    assert iss["response"] == "" and iss["response_synthesized"] is False
    # ...but the request is still never empty.
    assert iss["request"].startswith("GET /p HTTP/1.1")


# ── XXE regression: a payload-only finding.request must become a real, sendable
# HTTP request — not crash the Repeater with an illegal-header error. ──────────
_XXE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE foo [\n'
    '  <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">\n'
    ']>\n<root><data>&xxe;</data></root>'
)


def test_issue_wraps_payload_only_request_into_valid_http():
    # The XXE scanner stores raw XML in finding.request; it must be wrapped.
    iss = _finding_to_issue(
        _bare_finding(title="XXE", url="https://target.com/upload", request=_XXE_XML),
        "hunt", "xxe")
    assert iss["request_synthesized"] is True
    assert iss["request"].startswith("POST /upload HTTP/1.1")
    assert "Host: target.com" in iss["request"]
    assert "Content-Type: application/xml" in iss["request"]
    assert _XXE_XML.splitlines()[-1] in iss["request"]      # XML preserved in the body


def test_issue_leaves_a_real_captured_request_untouched():
    raw = "POST /x HTTP/1.1\nHost: t\nContent-Type: application/xml\n\n<a/>"
    iss = _finding_to_issue(_bare_finding(title="x", url="https://t/x", request=raw),
                            "hunt", "hunt")
    assert iss["request"] == raw and iss["request_synthesized"] is False


def test_repeater_send_of_wrapped_xxe_does_not_raise_illegal_header(server):
    # End-to-end: the wrapped XXE request sends against the suite itself and comes
    # back with a real status — never a LocalProtocolError.
    iss = _finding_to_issue(
        _bare_finding(title="XXE", url=server.url.rstrip("/") + "/upload", request=_XXE_XML),
        "hunt", "xxe")
    _, d = _post(server, "/repeater/new", {"request": iss["request"], "target": server.url})
    tid = d["tabs"][-1]["id"]
    _, sent = _post(server, "/repeater/send",
                    {"id": tid, "request": iss["request"], "target": server.url})
    resp = sent["response"]
    assert resp["error"] is None and resp["status"] is not None
    assert "LocalProtocolError" not in (resp.get("error") or "")


def test_repeater_send_of_bare_body_gives_actionable_error(server):
    # A hand-pasted body-only blob is rejected with guidance, not a cryptic error.
    tid = json.loads(_get(server, "/repeater")[1])["tabs"][0]["id"]
    _, sent = _post(server, "/repeater/send",
                    {"id": tid, "request": _XXE_XML, "target": server.url})
    err = sent["response"]["error"]
    assert err and "Not an HTTP request" in err
    assert "Illegal header" not in err


def test_repeater_build_wire_request_only_adds_whats_missing():
    from beatrix.cli.suite import _build_wire_request
    # Host + Content-Length absent -> both added; Connection: close added.
    w = _build_wire_request("POST", "HTTP/1.1", "/p",
                            [("X-A", "1")], "abcd", "h.com", 80, "http").decode()
    assert "Host: h.com" in w and "Content-Length: 4" in w and "Connection: close" in w
    # A typed Host / Content-Length / Connection are left exactly as-is.
    w2 = _build_wire_request("POST", "HTTP/1.1", "/p",
                             [("Host", "spoof"), ("Content-Length", "999"),
                              ("Connection", "keep-alive")], "abcd", "h.com", 80, "http").decode()
    assert "Host: spoof" in w2 and "Host: h.com" not in w2
    assert "Content-Length: 999" in w2 and "Content-Length: 4" not in w2
    assert w2.count("Connection:") == 1 and "keep-alive" in w2
    # Non-default port shows in an auto-added Host.
    w3 = _build_wire_request("GET", "HTTP/1.1", "/", [], "", "h.com", 8443, "https").decode()
    assert "Host: h.com:8443" in w3


def test_repeater_raw_send_is_byte_faithful_and_decodes_chunked_gzip():
    # The point of the v2 socket engine: bytes go out EXACTLY as typed (duplicate
    # headers, a spoofed Host, a deliberately-wrong Content-Length) and a chunked,
    # gzipped response comes back decoded. A throwaway TCP server captures the wire.
    import gzip
    import socket
    import threading

    from beatrix.cli.suite import _exec_repeater_request

    captured = {}
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        conn.settimeout(2)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            data += conn.recv(4096)                       # trailing body bytes
        except socket.timeout:
            pass
        captured["wire"] = data
        gz = gzip.compress(b"hello gzip world")
        resp = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
                b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                + b"%x\r\n" % len(gz) + gz + b"\r\n0\r\n\r\n")
        conn.sendall(resp)
        conn.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        req = ("POST /x HTTP/1.1\r\nHost: spoofed.example\r\n"
               "Cookie: a=1\r\nCookie: b=2\r\ncontent-length: 999\r\n\r\nBODY")
        r = _exec_repeater_request(req, "http://127.0.0.1:%d" % port)
    finally:
        th.join(timeout=3)
        srv.close()

    wire = captured["wire"].decode("latin-1")
    assert wire.count("Cookie:") == 2                     # duplicate headers on the wire
    assert "Host: spoofed.example" in wire                # spoofed host, not 127.0.0.1
    assert "content-length: 999" in wire                  # wrong CL sent verbatim (smuggling)
    assert r["status"] == 200 and r["error"] is None
    assert r["body"] == "hello gzip world"                # chunked + gzip decoded for display


def test_repeater_decodes_zstd_response_body():
    # Regression: Cloudflare & friends answer Accept-Encoding: zstd with a
    # Content-Encoding: zstd body. The Repeater must decode it for display
    # (both size-framed and streamed-without-size frames), not show raw bytes.
    import io
    zstandard = pytest.importorskip("zstandard")
    from beatrix.cli.suite import _decompress_body
    html = b"<!doctype html><title>ok</title>" + b"zstd body " * 40
    cctx = zstandard.ZstdCompressor()
    framed = cctx.compress(html)                                  # embeds content size
    streamed = cctx.stream_reader(io.BytesIO(html)).read()        # no embedded size (CDN style)
    for blob in (framed, streamed):
        assert _decompress_body([["Content-Encoding", "zstd"]], blob) == html
    # A corrupt zstd body must fall back to the raw bytes, never raise.
    assert _decompress_body([["Content-Encoding", "zstd"]], b"not-zstd") == b"not-zstd"


def test_real_scanner_request_flows_through_as_captured():
    # The whole point of wiring scanners to BaseScanner.format_http_request: a
    # real captured transaction must be recognized as REAL by the issue store
    # (request_synthesized False), not reconstructed — and it must be valid,
    # sendable raw HTTP that "Send to Repeater" can hand straight to the Repeater.
    import httpx

    from beatrix.core.types import Finding, Severity
    from beatrix.scanners.base import BaseScanner

    req = httpx.Request("POST", "https://x.com/api?id=1",
                        headers={"Content-Type": "application/json"}, content=b'{"a":1}')
    resp = httpx.Response(200, headers={"Content-Type": "application/json"},
                          content=b'{"ok":true}', request=req)
    raw_req = BaseScanner.format_http_request(resp)
    raw_resp = BaseScanner.format_http_response(resp)

    iss = _finding_to_issue(Finding(title="x", url="https://x.com/api?id=1",
                                    request=raw_req, response=raw_resp,
                                    severity=Severity.HIGH), "hunt", "hunt")
    assert iss["request_synthesized"] is False and iss["response_synthesized"] is False
    assert iss["request"].startswith("POST /api?id=1 HTTP/1.1")
    assert '{"a":1}' in iss["request"]              # real body carried through
    # And it parses back cleanly for the Repeater — body stays in the body.
    m, target, _v, headers, body = _parse_raw_request(iss["request"])
    assert m == "POST" and target == "/api?id=1" and body == '{"a":1}'


def test_issue_detail_over_http_carries_reconstructed_request(server):
    # End-to-end: a captured-less finding added to the store surfaces a
    # populated Request tab through /issues/detail.
    from beatrix.core.types import Finding, Severity
    server.issues.add_finding(1, Finding(
        title="Reflected XSS", url="https://x.com/search?q=1", parameter="q",
        payload="<script>alert(1)</script>", severity=Severity.MEDIUM,
        evidence="reflected unescaped in the response body"), "hunt", "hunt")
    lst = json.loads(_get(server, "/issues?project=1")[1])["issues"]
    iid = lst[0]["id"]
    d = json.loads(_get(server, "/issues/detail?project=1&id=%d" % iid)[1])["issue"]
    assert "q=<script>alert(1)</script>" in d["request"]
    assert d["request_synthesized"] is True
    assert d["response"] and d["response_synthesized"] is True


# ── Repeater ← Issues: "Send to Repeater" seeds a tab with the request ──
def test_repeater_new_seeds_request_and_target(server):
    _get(server, "/repeater")                       # ensure the pane is seeded
    _, d = _post(server, "/repeater/new",
                 {"request": "GET /admin HTTP/1.1\nHost: t.com\n\n", "target": "https://t.com"})
    tab = d["tabs"][-1]
    assert d["active"] == tab["id"]                  # the seeded tab is focused
    assert tab["request"].startswith("GET /admin") and tab["target"] == "https://t.com"


def test_repeater_new_without_seed_keeps_template(server):
    _, d = _post(server, "/repeater/new", {})       # backward compatible
    assert d["tabs"][-1]["request"].startswith("GET / HTTP/1.1")
    assert d["tabs"][-1]["target"] == ""


def test_send_to_repeater_end_to_end_from_issue(server):
    # An issue's reconstructed request handed to the Repeater is sendable: seed a
    # tab from it, then send it back at the suite's own /projects endpoint.
    from beatrix.core.types import Finding, Severity
    host = server.url.split("//", 1)[1].rstrip("/")
    server.issues.add_finding(1, Finding(
        title="probe", url=server.url.rstrip("/") + "/projects",
        severity=Severity.INFO), "hunt", "hunt")
    iid = json.loads(_get(server, "/issues?project=1")[1])["issues"][0]["id"]
    issue = json.loads(_get(server, "/issues/detail?project=1&id=%d" % iid)[1])["issue"]
    # The button posts the issue's request + origin as a new tab.
    _, d = _post(server, "/repeater/new",
                 {"request": issue["request"], "target": server.url})
    tid = d["tabs"][-1]["id"]
    _, sent = _post(server, "/repeater/send",
                    {"id": tid, "request": issue["request"], "target": server.url})
    assert sent["response"]["status"] == 200 and '"projects"' in sent["response"]["body"]


# ── Ghost: findings carry the real observed transaction (not a reconstruction) ──
def test_ghost_stored_response_renders_raw_request_and_response():
    from beatrix.ai.ghost2.core.session import StoredResponse
    sr = StoredResponse(id=1, status_code=500, headers={"Server": "nginx"},
                        body="boom", response_time_ms=5, url="https://x.com/a?id=1'",
                        method="GET", request_headers={"User-Agent": "GHOST/2.0"})
    assert sr.to_raw_request().startswith("GET /a?id=1' HTTP/1.1")
    assert "Host: x.com" in sr.to_raw_request()
    assert "User-Agent: GHOST/2.0" in sr.to_raw_request()
    assert sr.to_raw_response().startswith("HTTP/1.1 500")
    assert "Server: nginx" in sr.to_raw_response() and "boom" in sr.to_raw_response()


def test_ghost_capture_http_backfills_from_latest_but_agent_wins():
    import asyncio

    from beatrix.ai.ghost2.core.session import GhostSession, Scope
    from beatrix.ai.ghost2.tools.findings_tool import _capture_http

    async def run():
        s = GhostSession(Scope(target="https://x.com"))
        await s.store_response(status_code=200, headers={"Content-Type": "text/html"},
                               body="ok", response_time_ms=3, url="https://x.com/p",
                               method="GET", request_headers={"User-Agent": "GHOST/2.0"})
        # omitted -> backfilled from the latest stored transaction
        req, resp = _capture_http(s, "", "", 0)
        assert req.startswith("GET /p HTTP/1.1") and resp.startswith("HTTP/1.1 200")
        # anything the agent quoted is preserved verbatim
        assert _capture_http(s, "R", "S", 0) == ("R", "S")
        # nothing stored, nothing supplied -> left empty (no fake evidence)
        s2 = GhostSession(Scope(target="https://y.com"))
        assert _capture_http(s2, "", "", 0) == ("", "")

    asyncio.run(run())


def test_ghost_finding_response_id_selects_that_transaction():
    import asyncio

    from beatrix.ai.ghost2.core.session import GhostSession, Scope
    from beatrix.ai.ghost2.tools.findings_tool import _capture_http

    async def run():
        s = GhostSession(Scope(target="https://x.com"))
        await s.store_response(status_code=200, headers={}, body="first",
                               response_time_ms=1, url="https://x.com/1", method="GET")
        await s.store_response(status_code=404, headers={}, body="second",
                               response_time_ms=1, url="https://x.com/2", method="GET")
        # cite response #1 explicitly, not the latest (#2)
        req, resp = _capture_http(s, "", "", 1)
        assert "/1 HTTP/1.1" in req and "first" in resp

    asyncio.run(run())


# ── Sessions: session > projects; pick/create the workspace at launch ────
def test_session_active_when_state_dir_given(server):
    d = json.loads(_get(server, "/session")[1])
    assert d["active"] is True and d["path"] and d["name"]


def test_sessionless_guards_data_routes(sessionless):
    assert json.loads(_get(sessionless, "/session")[1])["active"] is False
    # every per-session route reports it needs a session instead of crashing
    for path in ("/projects", "/issues?project=1", "/repeater", "/scope?project=1",
                 "/ghost/state", "/hunt/state"):
        assert json.loads(_get(sessionless, path)[1]) == {"needs_session": True}
    # ...but the shell, the static hunt catalog, and fs/session routes still work
    assert _get(sessionless, "/")[0] == 200
    assert "modules" in json.loads(_get(sessionless, "/hunt/catalog")[1])


def test_session_create_then_projects_work(sessionless, tmp_path):
    _, r = _post(sessionless, "/session/new", {"parent": str(tmp_path), "name": "engagement"})
    assert r["ok"] and r["session"]["name"] == "engagement"
    assert (tmp_path / "engagement" / "session.json").exists()
    # now a session is mounted, the data routes come alive with a seeded project
    assert json.loads(_get(sessionless, "/session")[1])["active"] is True
    projects = json.loads(_get(sessionless, "/projects")[1])["projects"]
    assert len(projects) == 1 and projects[0]["label"] == 1


def test_session_open_existing_and_recents(sessionless, tmp_path):
    # Create one session, then create+open a second; both show up in recents.
    _post(sessionless, "/session/new", {"parent": str(tmp_path), "name": "alpha"})
    _post(sessionless, "/session/new", {"parent": str(tmp_path), "name": "beta"})
    _, r = _post(sessionless, "/session/open", {"path": str(tmp_path / "alpha")})
    assert r["ok"] and r["session"]["name"] == "alpha"
    names = [s["name"] for s in json.loads(_get(sessionless, "/sessions")[1])["sessions"]]
    assert "alpha" in names and "beta" in names


def test_session_open_missing_folder_errors(sessionless, tmp_path):
    _, r = _post(sessionless, "/session/open", {"path": str(tmp_path / "nope")})
    assert r["ok"] is False and "exist" in r["error"].lower()


def test_session_create_rejects_bad_name(sessionless, tmp_path):
    _, r = _post(sessionless, "/session/new", {"parent": str(tmp_path), "name": "a/b"})
    assert r["ok"] is False


def test_sessions_are_isolated_from_each_other(sessionless, tmp_path):
    # A project created in session A must not appear in session B.
    _post(sessionless, "/session/new", {"parent": str(tmp_path), "name": "A"})
    _post(sessionless, "/projects/new", {})            # A now has 2 projects
    assert len(json.loads(_get(sessionless, "/projects")[1])["projects"]) == 2
    _post(sessionless, "/session/new", {"parent": str(tmp_path), "name": "B"})
    assert len(json.loads(_get(sessionless, "/projects")[1])["projects"]) == 1  # fresh


def test_fs_mkdir_creates_folder_in_browser(sessionless, tmp_path):
    # The file explorer's "+ Folder" button — works with NO session mounted
    # (that's exactly when you're setting up a folder to hold a new session).
    r = _post(sessionless, "/fs/mkdir", {"parent": str(tmp_path), "name": "engagement-1"})
    assert r[1]["ok"] is True and (tmp_path / "engagement-1").is_dir()
    assert r[1]["path"] == str(tmp_path / "engagement-1")
    # It then shows up in the listing, so the UI can step into it.
    names = [e["name"] for e in json.loads(_get(sessionless, "/fs/list?path=" + str(tmp_path))[1])["entries"]]
    assert "engagement-1" in names
    # Duplicate and path-traversal names are rejected.
    assert _post(sessionless, "/fs/mkdir", {"parent": str(tmp_path), "name": "engagement-1"})[1]["ok"] is False
    assert _post(sessionless, "/fs/mkdir", {"parent": str(tmp_path), "name": "../evil"})[1]["ok"] is False


def test_fs_list_browses_directories(sessionless, tmp_path):
    (tmp_path / "folder-a").mkdir()
    (tmp_path / "folder-b").mkdir()
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "a-file.txt").write_text("x")
    d = json.loads(_get(sessionless, "/fs/list?path=" + str(tmp_path))[1])
    names = [e["name"] for e in d["entries"]]
    assert names == ["folder-a", "folder-b"]           # dirs only, sorted, no dotfolders/files
    assert d["parent"] and d["home"]


def test_fs_list_flags_session_folders(sessionless, tmp_path):
    _post(sessionless, "/session/new", {"parent": str(tmp_path), "name": "S"})
    d = json.loads(_get(sessionless, "/fs/list?path=" + str(tmp_path))[1])
    s = next(e for e in d["entries"] if e["name"] == "S")
    assert s["is_session"] is True


def test_fs_list_survives_an_unreadable_subdirectory(sessionless, tmp_path):
    # Regression: a mode-000 folder (like /root) must not truncate the listing —
    # its session-probe raises PermissionError, which used to abort the whole scan
    # and hide every alphabetically-later folder (that's how /workspaces vanished).
    import os
    locked = tmp_path / "aaa_locked"
    later = tmp_path / "zzz_after"
    locked.mkdir()
    later.mkdir()
    os.chmod(locked, 0o000)
    try:
        d = json.loads(_get(sessionless, "/fs/list?path=" + str(tmp_path))[1])
        names = [e["name"] for e in d["entries"]]
        assert "zzz_after" in names          # the later folder survives
        assert "aaa_locked" in names         # the locked folder still lists (just not a session)
    finally:
        os.chmod(locked, 0o755)              # let pytest clean tmp_path up


def test_fs_list_reaches_any_typed_path_and_files_show_parent(sessionless, tmp_path):
    # Typing an absolute path outside home must work (the reported issue), and a
    # file path lands you in its containing folder.
    (tmp_path / "sub").mkdir()
    f = tmp_path / "sub" / "note.txt"
    f.write_text("x")
    d = json.loads(_get(sessionless, "/fs/list?path=" + str(tmp_path / "sub"))[1])
    assert d["path"] == str(tmp_path / "sub")
    d2 = json.loads(_get(sessionless, "/fs/list?path=" + str(f))[1])
    assert d2["path"] == str(tmp_path / "sub")         # file → its parent folder


# ── AutoRepeater (Intruder-style automated attacks) ─────────────────────
def _ar_reqs(template, attack_type, sets):
    lits, bases = _ar_parse_positions(template)
    return [pl for pl, _req in _ar_generate(lits, bases, attack_type, sets)]


def test_ar_position_parsing_and_unbalanced_markers():
    lits, bases = _ar_parse_positions("GET /a?x=§1§&y=§2§ HTTP/1.1")
    assert bases == ["1", "2"] and len(lits) == 3
    assert _ar_parse_positions("GET /§oops HTTP/1.1") == (None, None)   # unbalanced


def test_ar_attack_type_combinatorics():
    tpl = "x=§1§&y=§2§"                                 # 2 positions
    n = 2
    # sniper: one set, one position at a time → n * |set|
    assert _ar_count(n, "sniper", [["A", "B"]]) == 4
    assert _ar_reqs(tpl, "sniper", [["A", "B"]]) == [["A"], ["B"], ["A"], ["B"]]
    # battering ram: same payload in every position → |set|
    assert _ar_count(n, "batteringram", [["A", "B"]]) == 2
    assert _ar_reqs(tpl, "batteringram", [["A", "B"]]) == [["A"], ["B"]]
    # pitchfork: zip the sets → min length
    assert _ar_count(n, "pitchfork", [["A", "B"], ["1", "2"]]) == 2
    assert _ar_reqs(tpl, "pitchfork", [["A", "B"], ["1", "2"]]) == [["A", "1"], ["B", "2"]]
    # cluster bomb: cartesian product
    assert _ar_count(n, "clusterbomb", [["A", "B"], ["1", "2"]]) == 4
    assert _ar_reqs(tpl, "clusterbomb", [["A", "B"], ["1", "2"]]) == \
        [["A", "1"], ["A", "2"], ["B", "1"], ["B", "2"]]


def _ar_poll(server, project=1, tries=150):
    # Wait for the attack to finish, then return the authoritative full result
    # set from /state (avoids any streaming/accumulation race in the test).
    last = {}
    for _ in range(tries):
        last = json.loads(_get(server, "/autorepeater/events?since=0&project=%d" % project)[1])
        if last["done"] and last["count"] >= last["total"]:
            break
        time.sleep(0.03)
    st = json.loads(_get(server, "/autorepeater/state?project=%d" % project)[1])
    return st.get("results", []), last


def test_autorepeater_run_streams_results_with_grep(server):
    host = server.url.split("//", 1)[1].rstrip("/")
    template = "GET /§projects§ HTTP/1.1\r\nHost: %s\r\n\r\n" % host
    _, r = _post(server, "/autorepeater/run", {
        "template": template, "target": server.url, "attack_type": "sniper",
        "payload_sets": [["projects", "nope"]], "grep": "active", "concurrency": 4})
    assert r["ok"] and r["total"] == 2
    rows, last = _ar_poll(server)
    assert last["done"] is True and len(rows) == 2
    by_payload = {tuple(x["payloads"]): x for x in rows}
    assert by_payload[("projects",)]["status"] == 200
    assert by_payload[("projects",)]["grep"] == 1        # "active" appears in the projects JSON
    assert by_payload[("nope",)]["status"] == 404
    assert by_payload[("nope",)]["grep"] == 0
    # a row's full request/response is retrievable
    d = json.loads(_get(server, "/autorepeater/result?project=1&index=1")[1])["result"]
    assert d["request"].startswith("GET /") and d["response"].startswith("HTTP/")


def test_autorepeater_rejects_bad_configs(server):
    host = server.url.split("//", 1)[1].rstrip("/")
    base = {"target": server.url, "attack_type": "sniper", "payload_sets": [["a"]]}
    # no positions marked
    _, r = _post(server, "/autorepeater/run", dict(base, template="GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host))
    assert r["ok"] is False and "position" in r["error"].lower()
    # unbalanced markers
    _, r = _post(server, "/autorepeater/run", dict(base, template="GET /§x HTTP/1.1\r\n\r\n"))
    assert r["ok"] is False and "§" in r["error"]
    # pitchfork needs one set per position
    _, r = _post(server, "/autorepeater/run", {
        "template": "GET /§a§/§b§ HTTP/1.1\r\nHost: %s\r\n\r\n" % host, "target": server.url,
        "attack_type": "pitchfork", "payload_sets": [["x"]]})
    assert r["ok"] is False and "each" in r["error"].lower()


def test_ar_payload_type_expansion():
    assert _ar_expand_set({"type": "list", "items": ["a", "b"]}) == ["a", "b"]
    assert _ar_expand_set(["x", 1]) == ["x", "1"]                 # bare list, stringified
    assert _ar_expand_set({"type": "numbers", "from": 1, "to": 5, "step": 2}) == ["1", "3", "5"]
    assert _ar_expand_set({"type": "numbers", "from": 3, "to": 1, "step": -1}) == ["3", "2", "1"]
    assert _ar_expand_set({"type": "brute", "charset": "ab", "min": 1, "max": 2}) == \
        ["a", "b", "aa", "ab", "ba", "bb"]


def test_ar_payload_processing_rules():
    assert _ar_process("x", [{"type": "prefix", "value": "<"}, {"type": "suffix", "value": ">"}]) == "<x>"
    assert _ar_process("a b&c", [{"type": "urlencode"}]) == "a%20b%26c"
    assert _ar_process("hi", [{"type": "base64"}]) == "aGk="
    assert _ar_process("abc", [{"type": "upper"}]) == "ABC"
    assert _ar_process("x", [{"type": "sha256"}]) == \
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
    # processing applies to the payload, not to a position's base value
    lits, bases = _ar_parse_positions("id=§1§&y=§2§")
    _pl, req = next(_ar_generate(lits, bases, "sniper", [["' OR 1"]], [{"type": "urlencode"}]))
    assert req.startswith("id=%27%20OR%201&y=2")


def test_autorepeater_grep_extract_captures_value(server):
    host = server.url.split("//", 1)[1].rstrip("/")
    template = "GET /§projects§ HTTP/1.1\r\nHost: %s\r\n\r\n" % host
    _, r = _post(server, "/autorepeater/run", {
        "template": template, "target": server.url, "attack_type": "sniper",
        "payload_sets": [{"type": "list", "items": ["projects"]}],
        "extract": r'"active":\s*(\d+)'})           # capture group → Extract column
    assert r["ok"]
    rows, last = _ar_poll(server)
    assert last["done"] and rows[0]["extract"] == "1"   # /projects has "active": 1


def test_autorepeater_numbers_payload_with_processing(server):
    host = server.url.split("//", 1)[1].rstrip("/")
    _, r = _post(server, "/autorepeater/run", {
        "template": "GET /a?n=§1§ HTTP/1.1\r\nHost: %s\r\n\r\n" % host, "target": server.url,
        "attack_type": "sniper", "payload_sets": [{"type": "numbers", "from": 1, "to": 3, "step": 1}],
        "processing": [{"type": "prefix", "value": "P"}]})
    assert r["ok"] and r["total"] == 3
    rows, _last = _ar_poll(server)
    assert sorted(tuple(x["payloads"]) for x in rows) == [("P1",), ("P2",), ("P3",)]


def test_autorepeater_bad_extract_regex_rejected(server):
    host = server.url.split("//", 1)[1].rstrip("/")
    _, r = _post(server, "/autorepeater/run", {
        "template": "GET /§projects§ HTTP/1.1\r\nHost: %s\r\n\r\n" % host, "target": server.url,
        "attack_type": "sniper", "payload_sets": [["projects"]], "extract": "([unclosed"})
    assert r["ok"] is False and "regex" in r["error"].lower()


def test_autorepeater_stop_and_state(server):
    host = server.url.split("//", 1)[1].rstrip("/")
    template = "GET /§projects§ HTTP/1.1\r\nHost: %s\r\n\r\n" % host
    _post(server, "/autorepeater/run", {"template": template, "target": server.url,
        "attack_type": "sniper", "payload_sets": [["projects"]], "concurrency": 2})
    _ar_poll(server)                                     # let it finish
    st = json.loads(_get(server, "/autorepeater/state?project=1")[1])
    assert st["running"] is False and st["total"] == 1 and len(st["results"]) == 1
    assert _post(server, "/autorepeater/stop", {"project": 1})[1]["ok"] is True


# ── Feed Issues → Ghost for validation (token-saving: validate, don't re-discover) ──
def test_ghost_validation_target_and_objective():
    issues = [
        {"id": 1, "severity": "high", "title": "Reflected XSS in q",
         "url": "https://public-firing-range.appspot.com/reflected/body?q=x",
         "parameter": "q", "module": "injection", "evidence": "svg onload reflected"},
        {"id": 2, "severity": "info", "title": "Internal Hostnames Disclosed",
         "url": "https://public-firing-range.appspot.com/", "module": "js_bundle"},
    ]
    assert _ghost_validation_target(issues) == "https://public-firing-range.appspot.com"
    obj = _ghost_validation_objective(issues)
    assert "Validate 2 findings" in obj
    assert "do NOT run a full scan".lower() in obj.lower()   # steers it away from re-discovery
    assert "Reflected XSS in q" in obj and "svg onload reflected" in obj[:2000]
    # single issue reads naturally
    assert _ghost_validation_objective(issues[:1]).startswith("Validate 1 finding ")
    # empty target when no URLs
    assert _ghost_validation_target([{"id": 9, "title": "x"}]) == ""


def test_ghost_validate_route_rejects_empty_and_missing(server):
    assert _post(server, "/ghost/validate", {"project": 1, "ids": []})[1] == \
        {"ok": False, "error": "No matching issues to validate."}
    assert _post(server, "/ghost/validate", {"project": 1, "ids": [999]})[1]["ok"] is False


def test_ghost_validate_route_gathers_real_issues(server):
    from beatrix.core.types import Finding, Severity
    server.issues.add_finding(1, Finding(
        title="Reflected XSS in q", severity=Severity.HIGH, parameter="q",
        url="https://public-firing-range.appspot.com/reflected/body?q=x",
        scanner_module="injection", evidence="reflected unencoded"), "injection", "hunt")
    # Reaches the real Ghost launch path; without an LLM key in the test env it
    # returns a clean error rather than starting — the point is it doesn't crash
    # and it got past id-gathering/target/objective (never "No matching issues").
    _, r = _post(server, "/ghost/validate", {"project": 1, "ids": [1]})
    assert "ok" in r and r.get("error") != "No matching issues to validate."


# ── GraphQL schema discovery (predictive Repeater parameters) ────────────
# The Repeater's "Schema" button asks a GraphQL endpoint for its exact type
# system (introspection) rather than guessing parameter names, then generates a
# typed, ready-to-send operation stencil. These cover the normalisation of a
# raw __schema payload, stencil generation, the disabled-introspection path,
# and a real introspection round trip over HTTP.

def _gql_nn(t):
    return {"kind": "NON_NULL", "ofType": t}


def _gql_list(t):
    return {"kind": "LIST", "ofType": t}


def _gql_named(kind, name):
    return {"kind": kind, "name": name}


def _demo_schema():
    """A small but representative __schema payload: a required scalar arg, an
    enum arg with a default, and a mutation taking a nested input object."""
    nn, lst, nm = _gql_nn, _gql_list, _gql_named
    return {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "user", "description": "Fetch a user", "isDeprecated": False,
                 "args": [
                     {"name": "id", "type": nn(nm("SCALAR", "ID")), "defaultValue": None,
                      "description": "the user id"},
                     {"name": "role", "type": nm("ENUM", "Role"), "defaultValue": "USER",
                      "description": ""}],
                 "type": nm("OBJECT", "User")},
                {"name": "ping", "args": [], "type": nn(nm("SCALAR", "String")),
                 "isDeprecated": False},
            ]},
            {"kind": "OBJECT", "name": "Mutation", "fields": [
                {"name": "login", "isDeprecated": False,
                 "args": [{"name": "input", "type": nn(nm("INPUT_OBJECT", "LoginInput")),
                           "defaultValue": None}],
                 "type": nm("OBJECT", "AuthPayload")},
            ]},
            {"kind": "OBJECT", "name": "User", "fields": [
                {"name": "id", "args": [], "type": nn(nm("SCALAR", "ID"))},
                {"name": "email", "args": [], "type": nm("SCALAR", "String")},
                {"name": "role", "args": [], "type": nm("ENUM", "Role")},
                {"name": "friends", "args": [], "type": lst(nm("OBJECT", "User"))},
            ]},
            {"kind": "OBJECT", "name": "AuthPayload", "fields": [
                {"name": "token", "args": [], "type": nm("SCALAR", "String")},
            ]},
            {"kind": "INPUT_OBJECT", "name": "LoginInput", "inputFields": [
                {"name": "username", "type": nn(nm("SCALAR", "String")), "defaultValue": None},
                {"name": "password", "type": nn(nm("SCALAR", "String")), "defaultValue": None},
                {"name": "remember", "type": nm("SCALAR", "Boolean"), "defaultValue": None},
            ]},
            {"kind": "ENUM", "name": "Role",
             "enumValues": [{"name": "ADMIN"}, {"name": "USER"}, {"name": "GUEST"}]},
        ],
    }


def test_gql_type_str_renders_modifiers():
    nn, lst, nm = _gql_nn, _gql_list, _gql_named
    assert _gql_type_str(nm("SCALAR", "ID")) == "ID"
    assert _gql_type_str(nn(nm("SCALAR", "ID"))) == "ID!"
    assert _gql_type_str(lst(nn(nm("OBJECT", "User")))) == "[User!]"
    assert _gql_type_str(nn(lst(nn(nm("OBJECT", "User"))))) == "[User!]!"


def test_gql_normalize_extracts_operations_and_rulesets():
    m = _gql_normalize(_demo_schema())
    assert m["roots"] == {"query": "Query", "mutation": "Mutation", "subscription": None}
    assert [o["name"] for o in m["operations"]["query"]] == ["user", "ping"]
    user = m["operations"]["query"][0]
    assert user["signature"] == "user(id: ID!, role: Role): User"
    id_arg, role_arg = user["args"]
    assert id_arg["required"] is True and id_arg["type"] == "ID!"
    assert role_arg["required"] is False and role_arg["default"] == "USER"
    # The enum's full accepted-value set is the ruleset for that parameter.
    assert role_arg["enum"] == ["ADMIN", "USER", "GUEST"]


def test_gql_stencil_builds_typed_operation_with_variables():
    m = _gql_normalize(_demo_schema())
    user = m["operations"]["query"][0]
    st = _gql_stencil(user, "query", m)
    # Arguments are declared as typed $variables and passed through by name.
    assert "query BeatrixUser($id: ID!, $role: Role)" in st["gql"]
    assert "user(id: $id, role: $role)" in st["gql"]
    # Selection set is the return type's scalar/enum leaves (not the object child).
    assert "id email role" in st["gql"] and "friends" not in st["gql"]
    # Variables skeleton: empty string for ID, first enum value for the enum.
    assert st["variables"] == {"id": "", "role": "ADMIN"}


def test_gql_stencil_expands_nested_input_object():
    m = _gql_normalize(_demo_schema())
    login = m["operations"]["mutation"][0]
    st = _gql_stencil(login, "mutation", m)
    assert st["gql"].startswith("mutation BeatrixLogin($input: LoginInput!)")
    assert st["variables"] == {"input": {"username": "", "password": "", "remember": False}}


def test_gql_stencil_scalar_return_has_no_selection_set():
    m = _gql_normalize(_demo_schema())
    ping = m["operations"]["query"][1]
    gql = _gql_stencil(ping, "query", m)["gql"]
    assert "ping" in gql and "{" not in gql.split("ping", 1)[1]


def test_gql_find_hints_harvests_did_you_mean():
    payload = {"errors": [{"message": 'Cannot query field "usr" on type "Query". '
                                       'Did you mean "user" or "users"?'}]}
    assert _gql_find_hints(payload) == ["user", "users"]


class _GqlMock:
    """A throwaway GraphQL endpoint for the round-trip tests. /graphql answers
    introspection (and echoes the Authorization header it saw); /nointro refuses
    introspection the way a locked-down server does."""

    def __init__(self, schema):
        import http.server
        import threading
        sch = schema
        saw = {}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n).decode() or "{}")
                saw["auth"] = self.headers.get("Authorization")
                saw["ctype"] = self.headers.get("Content-Type")
                if self.path == "/nointro":
                    out = {"errors": [{"message": "GraphQL introspection is not allowed."}],
                           "data": None}
                elif "__schema" in body.get("query", ""):
                    out = {"data": {"__schema": sch}}
                else:
                    out = {"data": {}}
                b = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.saw = saw
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.base = "http://127.0.0.1:%d" % self.port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def gql_mock():
    m = _GqlMock(_demo_schema())
    try:
        yield m
    finally:
        m.close()


def test_graphql_discover_introspects_live_endpoint(gql_mock):
    raw = ("POST /graphql HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
           "Authorization: Bearer SECRET\r\nContent-Type: application/json\r\n\r\n"
           '{"query":"{ping}"}' % gql_mock.port)
    d = _graphql_discover(raw, gql_mock.base)
    assert d["ok"] is True and d["introspection"] is True
    assert d["endpoint"] == gql_mock.base + "/graphql"
    assert d["counts"]["query"] == 2 and d["counts"]["mutation"] == 1
    # The tester's auth header was reused for the introspection request.
    assert gql_mock.saw["auth"] == "Bearer SECRET"
    # ...and would be reused for the stencil too (returned, not re-sent here).
    assert ["Authorization", "Bearer SECRET"] in d["headers"]
    user = d["operations"]["query"][0]
    assert user["signature"] == "user(id: ID!, role: Role): User"
    assert '"id": ""' in user["body"] and "$id: ID!" in user["body"]


def test_graphql_discover_reports_disabled_introspection(gql_mock):
    raw = ("POST /nointro HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
           "Content-Type: application/json\r\n\r\n{}" % gql_mock.port)
    d = _graphql_discover(raw, gql_mock.base)
    assert d["ok"] is False and d["introspection"] is False
    assert "introspection is disabled" in d["error"]


def test_graphql_discover_without_target_is_a_clean_error():
    d = _graphql_discover("GET / HTTP/1.1\r\n\r\n", "")
    assert d["ok"] is False and "No target" in d["error"]


def test_repeater_schema_route_wired(server, gql_mock):
    raw = ("POST /graphql HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
           "Content-Type: application/json\r\n\r\n{}" % gql_mock.port)
    code, body = _post(server, "/repeater/schema", {"request": raw, "target": gql_mock.base})
    assert code == 200 and body["ok"] is True
    assert body["counts"]["mutation"] == 1
    assert body["operations"]["mutation"][0]["name"] == "login"


# ── Predictive parameters for ALL parameterized queries ──────────────────
# GraphQL (above) gives an exact ruleset because it declares a schema. These
# cover the generalization to every endpoint: OpenAPI/Swagger + HTML forms
# (declared), captured traffic (observed), and active verification (Arjun /
# Clairvoyance, both availability-gated and monkeypatched here so CI needs no
# external CLI).

_OAPI_SPEC = {
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com/api"}],
    "paths": {
        "/users/{id}": {
            "get": {"summary": "Get user", "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                {"name": "expand", "in": "query", "required": False,
                 "schema": {"type": "string", "enum": ["posts", "friends"]}}]},
            "post": {"summary": "Update", "requestBody": {"content": {"application/json": {
                "schema": {"type": "object", "required": ["name"], "properties": {
                    "name": {"type": "string"}, "age": {"type": "integer"},
                    "role": {"type": "string", "enum": ["admin", "user"]}}}}}}},
        }
    },
}


def test_param_shape_detection():
    def shape(raw, target="https://h.example.com", resp=""):
        from beatrix.cli.suite import _param_ctx
        return _param_shape(_param_ctx(raw, target), resp)
    assert shape("GET /search?q=x HTTP/1.1\r\nHost: h.example.com\r\n\r\n") == "query"
    assert shape("POST /u HTTP/1.1\r\nHost: h.example.com\r\nContent-Type: application/json\r\n\r\n{\"a\":1}") == "json"
    assert shape("POST /u HTTP/1.1\r\nHost: h.example.com\r\n"
                 "Content-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2") == "form"
    assert shape("POST /graphql HTTP/1.1\r\nHost: h.example.com\r\n"
                 "Content-Type: application/json\r\n\r\n{\"query\":\"{x}\"}") == "graphql"


def test_param_discover_openapi_matches_templated_path_and_builds_stencil():
    fetch = lambda p: json.dumps(_OAPI_SPEC) if p == "/openapi.json" else None
    raw = ("GET /api/users/123?expand=posts HTTP/1.1\r\nHost: api.example.com\r\n"
           "Authorization: Bearer T\r\n\r\n")
    d = _param_discover(raw, "https://api.example.com", history=[], response_body="", fetch=fetch)
    assert d["ok"] is True
    oapi = [s for s in d["stencils"] if s["source"] == "openapi"]
    assert {s["label"] for s in oapi} == {"GET /users/{id}", "POST /users/{id}"}
    get = next(s for s in oapi if s["label"].startswith("GET"))
    names = {(p["name"], p["in"], p["required"]) for p in get["params"]}
    assert ("id", "path", True) in names and ("expand", "query", False) in names
    expand = next(p for p in get["params"] if p["name"] == "expand")
    assert expand["enum"] == ["posts", "friends"] and expand["confidence"] == "exact"
    # The POST operation expands its JSON requestBody into typed body params.
    post = next(s for s in oapi if s["label"].startswith("POST"))
    assert any(p["name"] == "name" and p["in"] == "body-json" and p["required"] for p in post["params"])
    assert "Authorization: Bearer T" in get["request"]  # auth reused in the stencil


def test_param_discover_html_forms():
    html = ('<form method="POST" action="/login">'
            '<input name="user" required><input type="password" name="pass" required>'
            '<input type="hidden" name="csrf" value="abc">'
            '<select name="role"><option value="admin">A</option><option value="user">U</option></select>'
            '</form>')
    raw = "GET /login HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"
    d = _param_discover(raw, "https://shop.example.com", history=[], response_body=html)
    form = [s for s in d["stencils"] if s["source"] == "form"][0]
    byname = {p["name"]: p for p in form["params"]}
    assert set(byname) == {"user", "pass", "csrf", "role"}
    assert byname["user"]["required"] and byname["csrf"]["required"]      # required + hidden
    assert byname["role"]["enum"] == ["admin", "user"]
    assert byname["csrf"]["default"] == "abc"
    assert "csrf=abc" in form["request"] and form["request"].startswith("POST /login")


def test_html_forms_parser_ignores_fieldless_and_malformed():
    assert _html_forms("") == []
    assert _html_forms("<form></form>") == []                              # no fields → dropped
    forms = _html_forms("<form><input name=q></form><p>not html<form><input name=x></form>")
    assert [f["fields"][0]["name"] for f in forms] == ["q", "x"]


def test_param_discover_observed_infers_types_and_confidence():
    hist = [
        {"method": "GET", "url": "https://x.example.com/search?q=hi&page=2",
         "req_headers": {"Host": "x.example.com"}, "req_body": ""},
        {"method": "GET", "url": "https://x.example.com/search?q=yo&page=5&debug=true",
         "req_headers": {"Host": "x.example.com"}, "req_body": ""},
    ]
    raw = "GET /search?q=foo HTTP/1.1\r\nHost: x.example.com\r\n\r\n"
    d = _param_discover(raw, "https://x.example.com", history=hist)
    obs = [s for s in d["stencils"] if s["source"] == "observed"][0]
    by = {p["name"]: p for p in obs["params"]}
    assert set(by) == {"q", "page", "debug"}
    assert by["q"]["confidence"] == "high" and by["q"]["required"] is True   # 3/3 requests
    assert by["page"]["type"] == "integer" and by["page"]["confidence"] == "medium"
    assert by["debug"]["type"] == "boolean" and by["debug"]["confidence"] == "low"
    assert obs["request"].startswith("GET /search?")                         # query-string stencil


class _FakeArjun:
    available = True

    async def discover(self, url, method="GET", headers=None, **kw):
        _FakeArjun.seen_headers = headers or {}
        return {"params": ["debug", "admin_override"], "url": url, "method": method}


def test_param_active_verify_rest_uses_arjun(monkeypatch):
    import beatrix.core.external_tools as et
    monkeypatch.setattr(et, "ArjunRunner", _FakeArjun)
    raw = "GET /api/thing HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer T\r\n\r\n"
    d = _param_active_verify(raw, "https://api.example.com")
    assert d["ok"] is True and d["tool"] == "arjun"
    names = {p["name"] for p in d["stencils"][0]["params"]}
    assert names == {"debug", "admin_override"}
    assert all(p["source"] == "probed" for p in d["stencils"][0]["params"])
    assert _FakeArjun.seen_headers.get("Authorization") == "Bearer T"   # auth forwarded


class _FakeClair:
    available = True

    async def reconstruct_schema(self, url, **kw):
        nn = {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}
        schema = {"data": {"__schema": {"queryType": {"name": "Query"},
                  "mutationType": None, "subscriptionType": None, "types": [
                      {"kind": "OBJECT", "name": "Query", "fields": [
                          {"name": "secret", "isDeprecated": False,
                           "args": [{"name": "key", "type": nn, "defaultValue": None}],
                           "type": {"kind": "SCALAR", "name": "String"}}]}]}}}
        return {"success": True, "schema": json.dumps(schema)}


def test_param_active_verify_graphql_uses_clairvoyance(monkeypatch):
    import beatrix.core.external_tools as et
    monkeypatch.setattr(et, "ClairvoyanceRunner", _FakeClair)
    raw = ("POST /graphql HTTP/1.1\r\nHost: g.example.com\r\n"
           "Content-Type: application/json\r\n\r\n{\"query\":\"{x}\"}")
    d = _param_active_verify(raw, "https://g.example.com")
    assert d["ok"] is True and d["tool"] == "clairvoyance"
    st = d["stencils"][0]
    assert st["label"] == "query: secret" and "$key: String!" in st["request"]


def test_param_active_verify_graphql_tool_absent_is_clean(monkeypatch):
    import beatrix.core.external_tools as et

    class _Off:
        available = False
    monkeypatch.setattr(et, "ClairvoyanceRunner", _Off)
    raw = ("POST /graphql HTTP/1.1\r\nHost: g.example.com\r\n"
           "Content-Type: application/json\r\n\r\n{\"query\":\"{x}\"}")
    d = _param_active_verify(raw, "https://g.example.com")
    assert d["ok"] is False and "clairvoyance" in d["error"]


def test_repeater_params_route_discovers_graphql(server, gql_mock):
    raw = ("POST /graphql HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
           "Content-Type: application/json\r\n\r\n{}" % gql_mock.port)
    code, body = _post(server, "/repeater/params", {"request": raw, "target": gql_mock.base})
    assert code == 200 and body["ok"] is True and body["request_shape"] == "graphql"
    labels = {s["label"] for s in body["stencils"] if s["source"] == "introspection"}
    assert "mutation: login" in labels


def test_repeater_params_verify_is_scope_gated(server):
    _post(server, "/scope/add", {"project": 1, "text": "example.com"})
    raw = "GET /x HTTP/1.1\r\nHost: 10.9.9.9\r\n\r\n"
    code, body = _post(server, "/repeater/params/verify",
                       {"project": 1, "request": raw, "target": "http://10.9.9.9"})
    assert code == 200 and body["ok"] is False and body["needs_confirm"] is True
    assert body["host"] == "10.9.9.9"


# ── JWT workbench (operator module: analyze via jwt_tool → Issues; tamper) ──
class _FakeJwt:
    available = True

    async def analyze(self, token):
        return {"vulnerabilities": [{"type": "Algorithm None Attack", "detail": "accepts alg=none"}],
                "header": {}, "payload": {}, "output": "[+] jwt_tool done"}

    async def tamper(self, token, claim, value):
        return "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."


def test_jwt_analyze_route_parses_and_files_issue(server, monkeypatch):
    import beatrix.core.external_tools as et
    monkeypatch.setattr(et, "JwtToolRunner", _FakeJwt)
    code, body = _post(server, "/jwt/analyze", {"project": 1, "token": "eyJ.eyJ.x"})
    assert code == 200 and body["available"] is True
    assert any("none" in ((v.get("type", "") + v.get("detail", "")).lower()) for v in body["vulnerabilities"])
    assert any("JWT" in (i.get("title", "") or "") for i in server.issues.list(1))   # landed in Issues


def test_jwt_analyze_route_tool_absent_is_clean(server, monkeypatch):
    import beatrix.core.external_tools as et

    class _Off:
        available = False
    monkeypatch.setattr(et, "JwtToolRunner", _Off)
    code, body = _post(server, "/jwt/analyze", {"project": 1, "token": "eyJ.eyJ.x"})
    assert code == 200 and body["available"] is False      # clean degrade, no crash


def test_jwt_tamper_route(server, monkeypatch):
    import beatrix.core.external_tools as et
    monkeypatch.setattr(et, "JwtToolRunner", _FakeJwt)
    code, body = _post(server, "/jwt/tamper", {"token": "eyJ.eyJ.x", "claim": "role", "value": "admin"})
    assert code == 200 and body.get("token", "").startswith("eyJ")


# ── OAST / Collaborator (Weaponization) ──
def test_oast_mint_and_callback_recorded(server):
    code, body = _post(server, "/oast/mint", {"project": 1, "vuln_type": "ssrf", "note": "q param"})
    assert code == 200 and body["uid"]
    uid = body["uid"]
    base = server.url.rstrip("/")
    # a target "fetches" the canary (GET) ...
    urllib.request.urlopen(base + "/cb/" + uid, timeout=5).read()
    # ... and again via POST with a body
    req = urllib.request.Request(base + "/cb/" + uid, data=b"leaked=secret", method="POST")
    urllib.request.urlopen(req, timeout=5).read()
    st = json.loads(_get(server, "/oast/state?project=1")[1])
    assert st["count"] >= 2
    cb = st["callbacks"][0]                       # newest first
    assert cb["uid"] == uid and cb["vuln_type"] == "ssrf" and cb["note"] == "q param" and cb["known"] is True
    assert any(c["method"] == "POST" and "secret" in c["body"] for c in st["callbacks"])


def test_oast_unknown_uid_still_recorded(server):
    base = server.url.rstrip("/")
    urllib.request.urlopen(base + "/cb/deadbeef", timeout=5).read()
    st = json.loads(_get(server, "/oast/state")[1])
    hit = next((c for c in st["callbacks"] if c["uid"] == "deadbeef"), None)
    assert hit is not None and hit["known"] is False


def test_oast_base_override(server):
    _post(server, "/oast/base", {"base": "https://pub.example.com/"})
    assert json.loads(_get(server, "/oast/state")[1])["base"] == "https://pub.example.com"  # trailing slash stripped


# ── SPA Recon module (client-side / source-map recon) ────────────────────
def test_spa_recon_catalog(server):
    code, body = _get(server, "/sparecon/catalog")
    assert code == 200
    data = json.loads(body)
    assert "sources" in data and len(data["sources"]) >= 1


def test_spa_recon_run_requires_target(server):
    pid = server.projects.state().get("active")
    code, data = _post(server, "/sparecon/run",
                       {"project": pid, "target": "", "use_sitemap": False})
    assert code == 200 and data.get("ok") is False
