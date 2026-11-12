# ═══════════════════════════════════════════════════════════
#  BEATRIX — The Black Mamba
#  Makefile for install/uninstall/dev
# ═══════════════════════════════════════════════════════════

# The venv install.sh creates. ~/.beatrix itself holds your data — never point this at it.
VENV_DIR ?= $(HOME)/.beatrix/venv
PY       := $(VENV_DIR)/bin/python
SHELL    := /bin/bash

.PHONY: help install install-core install-dev setup uninstall clean test lint check

# ── Default ──────────────────────────────────────────────

help: ## Show this help
	@echo ""
	@echo "  ⚔️  BEATRIX — Makefile"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Install ──────────────────────────────────────────────

install: ## Full install: Beatrix (editable) + every external tool, with a post-install check
	@chmod +x install.sh && ./install.sh

install-core: ## Beatrix only, no external tools (add them later with: make setup)
	@chmod +x install.sh && ./install.sh --no-tools

install-dev: ## Add the dev tools (pytest, ruff, black) to the install.sh venv
	@test -x "$(PY)" || { echo "No venv at $(VENV_DIR) — run 'make install' first"; exit 1; }
	@if command -v uv >/dev/null; then uv pip install --python "$(PY)" -e ".[dev,extended,agent]"; \
	 else "$(PY)" -m pip install -e ".[dev,extended,agent]"; fi
	@echo "✓ Dev install complete"

setup: ## Install or repair the external tool arsenal (same as: beatrix setup)
	@chmod +x install.sh && BEATRIX_VENV="$(VENV_DIR)" bash -c 'source ./install.sh && install_external_tools'

# ── Uninstall ────────────────────────────────────────────

uninstall: ## Remove Beatrix (asks before touching your data in ~/.beatrix)
	@chmod +x uninstall.sh && ./uninstall.sh

# ── Dev ──────────────────────────────────────────────────

test: ## Run tests (needs: make install-dev)
	"$(PY)" -m pytest tests/ --ignore=tests/live_integration.py

lint: ## Run linter
	"$(PY)" -m ruff check beatrix/

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info .eggs __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "✓ Cleaned"

# ── Info ─────────────────────────────────────────────────

check: ## Check if beatrix is installed and show info
	@echo ""
	@if command -v beatrix &>/dev/null; then \
		echo "  ✓ beatrix is installed"; \
		echo "  Location: $$(which beatrix)"; \
		beatrix --version; \
	else \
		echo "  ✗ beatrix is not on PATH"; \
		echo "  Run: make install"; \
	fi
	@echo ""
