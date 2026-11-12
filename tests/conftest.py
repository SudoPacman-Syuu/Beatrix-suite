# BEATRIX Test Configuration

import pytest

# Exclude live_integration.py from pytest collection —
# it makes real HTTP calls and is meant to be run standalone.
collect_ignore = ["live_integration.py"]


@pytest.fixture(autouse=True)
def _isolated_findings_db(tmp_path, monkeypatch):
    """Point FindingsDB's default at a per-test temp file. Tests that drive a CLI hunt record
    it through FindingsDB(), whose default is ~/.beatrix/findings.db, so every pytest run used
    to add fixture hunts to the developer's real findings history."""
    from beatrix.core import findings_db
    monkeypatch.setattr(findings_db, "DEFAULT_DB_PATH", tmp_path / "findings.db")


@pytest.fixture(autouse=True)
def _isolated_token_file(tmp_path, monkeypatch):
    """Keep the web UIs' access token (normally ~/.beatrix/suite.token) per-test, so starting
    a SuiteServer in a test never creates or rotates the developer's real token."""
    from beatrix.cli import _webauth
    monkeypatch.setattr(_webauth, "TOKEN_FILE", tmp_path / "suite.token")
