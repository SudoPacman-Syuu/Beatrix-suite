# GHOST v2 sandbox image.
#
# The container GHOST v2 runs shell/python_exec/external tools inside (see
# beatrix/ai/ghost2/runtime/sandbox.py::DockerRuntime). It bundles Beatrix plus
# the same external arsenal install.sh provisions, so run_external_tool and
# shell have the real binaries available without touching the host.
#
# Build:   docker build -f docker/ghost-sandbox.Dockerfile -t beatrix/ghost-sandbox:latest .
#   (or:   ./install.sh --with-docker)
# Use:     automatic once built — DockerRuntime prefers beatrix/ghost-sandbox:latest when
#          ai.sandbox_image isn't set in config.yaml (otherwise it uses python:3.11-slim).
#
# Builds on amd64 and arm64. Keep the tool list in sync with the Go tool map in install.sh.

FROM python:3.11-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    GOPATH=/opt/go \
    PATH=/opt/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH

# ── System deps: build tools, nmap, sqlmap, git ──────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential libpcap-dev \
        nmap sqlmap whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ── Go toolchain (current release, this image's architecture) + the arsenal ─
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    ver="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n1)"; \
    curl -fsSL "https://go.dev/dl/${ver}.linux-${arch}.tar.gz" | tar -C /usr/local -xz
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install -v github.com/ffuf/ffuf/v2@latest \
 && go install -v github.com/hahwul/dalfox/v2@latest \
 && go install -v github.com/lc/gau/v2/cmd/gau@latest \
 && go install -v github.com/jaeles-project/gospider@latest \
 && go install -v github.com/hakluke/hakrawler@latest \
 && go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest \
 && rm -rf /root/.cache/go-build

# ── Beatrix + the agent extra, installed into the image ──────────────────
# docs/manual is part of the wheel (pyproject's force-include), so the build needs it.
WORKDIR /opt/beatrix
COPY pyproject.toml README.md ./
COPY docs/manual ./docs/manual
COPY beatrix ./beatrix
RUN pip install ".[agent]"

# Playwright's Chromium plus the system libraries it needs (Beatrix's browser
# transport / auto_login; nuclei headless uses the same libraries).
RUN python -m playwright install --with-deps chromium

# ── Nuclei templates (best-effort; scans still run without a fresh set) ───
RUN nuclei -update-templates >/dev/null 2>&1 || true

# Default work dir is bind-mounted by DockerRuntime at run time.
WORKDIR /work
CMD ["sleep", "infinity"]
