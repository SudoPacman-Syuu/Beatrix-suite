"""
GHOST v2 — Strix-style autonomous pentesting agent for Beatrix.

Built on ``openai-agents[litellm]`` (provider-agnostic via LiteLLM), with
tools that drive Beatrix's existing arsenal (32 scanners, external tools,
findings DB). Requires the ``[agent]`` extra, which install.sh installs; by hand,
from your checkout:

    ~/.beatrix/venv/bin/python -m pip install -e '.[agent]'

Public surface:
    from beatrix.ai.ghost2 import run_investigation, GhostV2Config
"""

from __future__ import annotations

from .config import GhostV2Config

__all__ = ["GhostV2Config", "run_investigation", "agent_extra_hint"]


def agent_extra_hint() -> str:
    """How to install the ``[agent]`` extra into the environment Beatrix is running from.
    (``beatrix-cli`` isn't on PyPI, so a plain ``pip install 'beatrix-cli[agent]'`` can't work.)"""
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]          # beatrix/ai/ghost2/ → the checkout
    if (root / "pyproject.toml").exists():
        return "%s -m pip install -e '%s[agent]'   (or re-run install.sh)" % (sys.executable, root)
    return "re-run install.sh from your Beatrix checkout — it installs the 'agent' extra"


def run_investigation(*args, **kwargs):
    """Lazy proxy to :func:`core.runner.run_investigation`.

    Kept lazy so importing this package never pulls openai-agents unless a run
    actually starts (keeps ``import beatrix.ai`` cheap and dependency-free).
    """
    from .core.runner import run_investigation as _run

    return _run(*args, **kwargs)
