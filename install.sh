#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  BEATRIX — The Black Mamba
#  One-command installer for Linux (apt, dnf, pacman, apk)
#
#  Usage:
#    git clone https://github.com/SudoPacman-Syuu/Beatrix-suite.git && cd Beatrix-suite && ./install.sh
#
#  Or:
#    curl -sSL https://raw.githubusercontent.com/SudoPacman-Syuu/Beatrix-suite/main/install.sh | bash
#
#  Options:
#    --with-sudo-rules  Let Beatrix run packet capture and raw-socket nmap scans as root without
#                       a password prompt (/etc/sudoers.d/beatrix). Root-equivalent for your user.
#    --with-android     Android SDK command-line tools + emulator, for the mobile interceptor.
#    --with-docker      Docker + the GHOST v2 sandbox image.
#    --no-tools         Install Beatrix only; skip the external tool arsenal (later: beatrix setup).
#    -h, --help         Show this help.
#
#  Environment:
#    BEATRIX_PYTHON       Interpreter for the venv (default: Python 3.12)
#    BEATRIX_VENV         venv location (default: ~/.beatrix/venv)
#    BEATRIX_INSTALL_DIR  Where the beatrix / beatrix-suite / beatrix-update launchers go
#                         (default: /usr/local/bin)
#
#  Your data in ~/.beatrix (findings, sessions, config, API keys) is never deleted.
#  Exit status: 0 = everything required works; 2 = a required part is missing (see the summary).
#
#  "Those of you lucky enough to have your lives, take them with you."
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

MIN_PYTHON="3.11"
BEATRIX_HOME="$HOME/.beatrix"                       # your data: findings, sessions, config, keys
INSTALL_DIR="${BEATRIX_INSTALL_DIR:-/usr/local/bin}"
VENV_DIR="${BEATRIX_VENV:-$BEATRIX_HOME/venv}"
REPO_URL="https://github.com/SudoPacman-Syuu/Beatrix-suite.git"
TOOLS_BIN="$HOME/.local/bin"                        # uv tools, release binaries, tool launchers
SHARE_DIR="$HOME/.local/share"                      # tool data: wordlists, payloads, sources
KITE_URL="https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz"
WEBANALYZE_DB_URL="https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json"
ANDROID_CMDLINE_TOOLS="11076708"
ORIG_PATH="$PATH"                                   # PATH as your shells already have it

WITH_SUDO_RULES=0
WITH_ANDROID=0
WITH_DOCKER=0
NO_TOOLS=0

PKG_MGR=""
USE_UV=""
PYTHON=""
PYTHON_VERSION=""
SRC_DIR=""
CLONE_DIR=""
EDITABLE=0
LOG_DIR=""
LAUNCH_DIR="$INSTALL_DIR"
GOBIN_DIR=""
TOOLS_OK=()
TOOLS_FAILED=()
REQUIRED_FAILED=()

# ── Banner ───────────────────────────────────────────────────

banner() {
    echo -e "${YELLOW}"
    cat <<'EOF'
    ____             __       _
   / __ )___  ____ _/ /______(_)  __
  / __  / _ \/ __ `/ __/ ___/ / |/_/
 / /_/ /  __/ /_/ / /_/ /  / />  <
/_____/\___/\__,_/\__/_/  /_/_/|_|
EOF
    echo -e "${RESET}"
    echo -e "${DIM}The Black Mamba — Installer${RESET}"
    echo ""
}

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

  --with-sudo-rules  Let Beatrix run packet capture and raw-socket nmap scans as root without
                     a password prompt (/etc/sudoers.d/beatrix). Root-equivalent for your user.
  --with-android     Android SDK command-line tools + emulator, for the mobile interceptor.
  --with-docker      Docker + the GHOST v2 sandbox image.
  --no-tools         Install Beatrix only; skip the external tool arsenal (later: beatrix setup).
  -h, --help         Show this help.

Environment: BEATRIX_PYTHON (default 3.12), BEATRIX_VENV (default ~/.beatrix/venv),
             BEATRIX_INSTALL_DIR (default /usr/local/bin).
Your data in ~/.beatrix is never deleted. Exit status 2 = a required part is missing.
EOF
}

# ── Helpers ──────────────────────────────────────────────────

info()    { echo -e "  ${CYAN}▸${RESET} $*"; }
success() { echo -e "  ${GREEN}✓${RESET} $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $*"; }
fail()    { echo -e "  ${RED}✗${RESET} $*" >&2; exit 1; }
section() { echo ""; echo -e "${BOLD}$*${RESET}"; }

command_exists() { command -v "$1" &>/dev/null; }

version_gte() {
    # 0 if $1 >= $2
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# Root-only steps: directly when we are root (containers), else through sudo.
as_root() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif command_exists sudo; then
        sudo "$@"
    else
        return 1
    fi
}

# run_logged <name> <command…>: run quietly, keeping the output in the install log. On failure,
# say which step failed and show the end of its log instead of swallowing the error.
run_logged() {
    local name="$1"; shift
    if [[ -z "$LOG_DIR" ]]; then
        LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/beatrix-install.XXXXXX")"
    fi
    local log
    log="$LOG_DIR/$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_').log"
    if "$@" >"$log" 2>&1; then
        return 0
    fi
    warn "$name failed — end of $log:"
    tail -n 8 "$log" | sed 's/^/        /' >&2
    return 1
}

tool_ok()     { success "$1${2:+ ($2)}"; TOOLS_OK+=("$1"); }
tool_failed() { warn "${2:-$1 could not be installed}"; TOOLS_FAILED+=("$1"); }

# A Python entry-point script (#!…python) rather than a compiled binary — PD httpx and the Go
# s3scanner share their names with Python packages that install such scripts.
_is_python_script() {
    local first=""
    IFS= read -r -n 256 first < "$1" 2>/dev/null || true
    [[ "$first" == '#!'*python* ]]
}

# A compiled binary named $1 on PATH, in ~/.local/bin or in the Go bin dir.
_have_bin() {
    local p
    for p in ${GOBIN_DIR:+"$GOBIN_DIR/$1"} "$TOOLS_BIN/$1" "$(command -v "$1" 2>/dev/null || true)"; do
        if [[ -n "$p" && -f "$p" && -x "$p" ]] && ! _is_python_script "$p"; then
            return 0
        fi
    done
    return 1
}

# Put $1 on PATH now, and in your shell rc unless your shells already have it.
_add_to_path() {
    local dir="$1" line rc
    case ":$PATH:" in *":$dir:"*) ;; *) export PATH="$dir:$PATH" ;; esac
    case ":$ORIG_PATH:" in *":$dir:"*) return 0 ;; esac
    line="export PATH=\"$dir:\$PATH\""
    for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
        [[ -f "$rc" ]] || continue
        if ! grep -qxF "$line" "$rc"; then
            printf '\n# Added by the Beatrix installer\n%s\n' "$line" >> "$rc"
            info "Added $dir to PATH in $rc — open a new terminal to pick it up"
        fi
        return 0
    done
    return 0
}

# ── Package manager ──────────────────────────────────────────

detect_pkg_manager() {
    if command_exists apt-get; then
        PKG_MGR="apt"
    elif command_exists dnf; then
        PKG_MGR="dnf"
    elif command_exists pacman; then
        PKG_MGR="pacman"
    elif command_exists apk; then
        PKG_MGR="apk"
    else
        PKG_MGR="unknown"
    fi
}

_PKG_REFRESHED=0
pkg_refresh() {
    [[ $_PKG_REFRESHED -eq 0 ]] || return 0
    _PKG_REFRESHED=1
    case "$PKG_MGR" in
        apt)    run_logged "apt-get update" as_root apt-get update -qq || true ;;
        pacman) run_logged "pacman -Sy" as_root pacman -Sy --noconfirm || true ;;
        apk)    run_logged "apk update" as_root apk update -q || true ;;
    esac
    return 0
}

# pkg_install <package>…: one transaction, output kept in the install log.
pkg_install() {
    [[ $# -gt 0 ]] || return 0
    pkg_refresh
    case "$PKG_MGR" in
        apt)    run_logged "apt-get install $*" as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
        dnf)    run_logged "dnf install $*" as_root dnf install -y -q "$@" ;;
        pacman) run_logged "pacman -S $*" as_root pacman -S --noconfirm --needed "$@" ;;
        apk)    run_logged "apk add $*" as_root apk add --quiet "$@" ;;
        *)      return 1 ;;
    esac
}

# pkg_install_any "a|b": the first alternative this distro has (package names change across releases).
pkg_install_any() {
    local alts p
    IFS='|' read -r -a alts <<< "$1"
    pkg_refresh
    for p in "${alts[@]}"; do
        if [[ $PKG_MGR == apt ]] && ! apt-cache show "$p" >/dev/null 2>&1; then
            continue
        fi
        if pkg_install "$p"; then
            return 0
        fi
    done
    return 1
}

# ── Checks ───────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --with-sudo-rules) WITH_SUDO_RULES=1 ;;
            --with-android)    WITH_ANDROID=1 ;;
            --with-docker)     WITH_DOCKER=1 ;;
            --no-tools)        NO_TOOLS=1 ;;
            -h|--help)         usage; exit 0 ;;
            *)                 fail "Unknown option: $1 (see --help)" ;;
        esac
        shift
    done
}

check_invocation() {
    if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        fail "Run install.sh as yourself, without sudo — it uses sudo itself where it must.
    Under sudo, Beatrix would be installed into root's home instead of yours."
    fi
}

preflight() {
    section "Checking requirements..."
    detect_pkg_manager
    info "Package manager: ${BOLD}${PKG_MGR}${RESET}"
    if [[ $EUID -ne 0 ]]; then
        if ! command_exists sudo; then
            warn "sudo isn't installed: system packages will be skipped, launchers go to $TOOLS_BIN"
        elif ! sudo -n true 2>/dev/null; then
            info "Some steps install system packages — sudo may ask for your password."
            sudo -v || warn "No sudo rights: system packages will be skipped"
        fi
    fi
    local c
    for c in curl git tar; do
        command_exists "$c" || pkg_install "$c" || true
    done
    command_exists curl || fail "curl is required — install it and re-run"
    command_exists git  || fail "git is required — install it and re-run"
    command_exists tar  || fail "tar is required — install it and re-run"
    success "curl, git and tar available"
}

find_python() {
    local cands=() c ver
    if [[ -n "${BEATRIX_PYTHON:-}" ]]; then
        cands+=("$BEATRIX_PYTHON")
    fi
    # 3.12 / 3.11 first: the newest CPython often lacks wheels for part of the dependency tree.
    cands+=(python3.12 python3.11)
    while IFS= read -r c; do
        cands+=("$c")
    done < <(compgen -c python3. 2>/dev/null | grep -E '^python3\.[0-9]+$' | sort -t. -k2 -rn | uniq || true)
    cands+=(python3)
    for c in "${cands[@]}"; do
        command_exists "$c" || continue
        ver="$("$c" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null)" || continue
        if version_gte "$ver" "$MIN_PYTHON"; then
            PYTHON="$(command -v "$c")"
            PYTHON_VERSION="$ver"
            return 0
        fi
    done
    return 1
}

ensure_uv() {
    if ! command_exists uv; then
        info "Installing uv (fast Python package manager)..."
        if run_logged "uv installer" sh -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'; then
            export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
        fi
    fi
    if command_exists uv; then
        USE_UV=1
        success "uv $(uv --version 2>/dev/null | awk '{print $2}')"
    else
        USE_UV=0
        warn "uv unavailable — using python -m venv + pip instead"
    fi
}

_is_beatrix_tree() {
    [[ -f "$1/pyproject.toml" && -d "$1/beatrix" ]] && grep -q '^name = "beatrix-cli"' "$1/pyproject.toml"
}

locate_source() {
    local here=""
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi
    if [[ -n "$here" ]] && _is_beatrix_tree "$here"; then
        SRC_DIR="$here"
    elif _is_beatrix_tree "$PWD"; then
        SRC_DIR="$PWD"
    else
        CLONE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/beatrix-src.XXXXXX")"
        info "Fetching Beatrix from $REPO_URL..."
        run_logged "git clone" git clone --depth 1 "$REPO_URL" "$CLONE_DIR" || fail "Could not clone $REPO_URL"
        SRC_DIR="$CLONE_DIR"
    fi
    # A checkout you keep (git clone) is installed editable, so `beatrix update` / git pull
    # change what actually runs. A throwaway clone (curl | bash) gets a regular install.
    if [[ -z "$CLONE_DIR" && -e "$SRC_DIR/.git" ]]; then
        EDITABLE=1
        success "Source: $SRC_DIR (git checkout, installed editable)"
    else
        EDITABLE=0
        success "Source: $SRC_DIR"
    fi
}

cleanup_clone() {
    if [[ -n "$CLONE_DIR" && -d "$CLONE_DIR" ]]; then
        rm -rf -- "$CLONE_DIR"
    fi
}

# ── Python environment ───────────────────────────────────────

# Before this installer, the venv WAS ~/.beatrix — the folder that also holds your findings,
# sessions, config and keys — and every reinstall ran `rm -rf` on it. The venv now lives in
# ~/.beatrix/venv. Remove only the old venv's own files; never anything else in there.
migrate_old_layout() {
    [[ -f "$BEATRIX_HOME/pyvenv.cfg" ]] || return 0
    section "Moving the Python environment out of your data folder..."
    info "Older installs put the venv straight into $BEATRIX_HOME; it now lives in $VENV_DIR."
    if pgrep -f "$BEATRIX_HOME/bin/python" >/dev/null 2>&1; then
        warn "Beatrix is running from the old environment — restart it once the install finishes."
    fi
    local p
    if [[ -f "$BEATRIX_HOME/bin/activate" ]]; then
        rm -rf -- "${BEATRIX_HOME:?}/bin"
    fi
    if [[ -L "$BEATRIX_HOME/lib64" ]]; then
        rm -f -- "$BEATRIX_HOME/lib64"
    fi
    for p in "$BEATRIX_HOME"/lib/python3* "$BEATRIX_HOME"/include/python3* "$BEATRIX_HOME/include/site" \
             "$BEATRIX_HOME/share/man" "$BEATRIX_HOME/share/jupyter" "$BEATRIX_HOME/share/doc"; do
        if [[ -e "$p" ]]; then
            rm -rf -- "$p"
        fi
    done
    for p in lib include share; do
        rmdir "$BEATRIX_HOME/$p" 2>/dev/null || true          # only if now empty
    done
    rm -f -- "$BEATRIX_HOME/pyvenv.cfg" "$BEATRIX_HOME/CACHEDIR.TAG" "$BEATRIX_HOME/.lock"
    if [[ "$(cat "$BEATRIX_HOME/.gitignore" 2>/dev/null)" == "*" ]]; then
        rm -f -- "$BEATRIX_HOME/.gitignore"                   # uv's marker, not yours
    fi
    success "Old environment removed — your data in $BEATRIX_HOME is untouched"
}

create_venv() {
    section "Creating the Python environment..."
    if [[ "${VENV_DIR%/}" == "$BEATRIX_HOME" ]]; then
        fail "BEATRIX_VENV can't be $BEATRIX_HOME — that folder holds your data"
    fi
    if [[ -e "$VENV_DIR" ]]; then
        [[ -f "$VENV_DIR/pyvenv.cfg" ]] || fail "$VENV_DIR exists and isn't a Python venv — move it away and re-run"
        rm -rf -- "$VENV_DIR"
    fi
    mkdir -p "$(dirname "$VENV_DIR")"
    local made=0
    if [[ $USE_UV -eq 1 ]]; then
        # uv uses a matching interpreter on the system, or fetches one.
        if run_logged "uv venv (Python ${BEATRIX_PYTHON:-3.12})" uv venv --seed --python "${BEATRIX_PYTHON:-3.12}" "$VENV_DIR"; then
            made=1
        elif [[ -n "$PYTHON" ]] && run_logged "uv venv ($PYTHON)" uv venv --seed --python "$PYTHON" "$VENV_DIR"; then
            made=1
        fi
    fi
    if [[ $made -eq 0 ]]; then
        [[ -n "$PYTHON" ]] || fail "Python >= $MIN_PYTHON is required. Install it first:
         ${DIM}sudo apt install python3     # Debian/Ubuntu
         sudo dnf install python3     # Fedora
         sudo pacman -S python        # Arch${RESET}"
        rm -rf -- "$VENV_DIR"
        if ! run_logged "python -m venv" "$PYTHON" -m venv "$VENV_DIR"; then
            # Debian/Ubuntu ship venv/ensurepip as a separate package.
            if [[ $PKG_MGR == apt ]]; then
                pkg_install "python${PYTHON_VERSION%.*}-venv" || pkg_install python3-venv || true
            fi
            rm -rf -- "$VENV_DIR"
            run_logged "python -m venv (retry)" "$PYTHON" -m venv "$VENV_DIR" || fail "Could not create a venv with $PYTHON"
        fi
        run_logged "pip upgrade" "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel || true
    fi
    success "$VENV_DIR ($("$VENV_DIR/bin/python" --version 2>&1))"
}

# _pip_install <label> <pip args…>: into the Beatrix venv.
_pip_install() {
    local label="$1"; shift
    if [[ "${USE_UV:-0}" == 1 ]]; then
        run_logged "$label" uv pip install --python "$VENV_DIR/bin/python" "$@"
    else
        run_logged "$label" "$VENV_DIR/bin/python" -m pip install "$@"
    fi
}

install_beatrix() {
    section "Installing Beatrix..."
    local mode=() extras installed=""
    if [[ $EDITABLE -eq 1 ]]; then
        mode=(-e)
    fi
    for extras in "[extended,agent]" "[extended]" ""; do
        if _pip_install "install beatrix${extras}" ${mode[@]+"${mode[@]}"} "$SRC_DIR$extras"; then
            installed="${extras:-[core only]}"
            break
        fi
    done
    [[ -n "$installed" ]] || fail "Could not install Beatrix into $VENV_DIR — see the log above"
    if [[ "$installed" != "[extended,agent]" ]]; then
        warn "Installed $installed — the rest failed (see the log above); some features won't work"
        REQUIRED_FAILED+=("python extras")
    fi
    success "Beatrix $installed"
}

# ── Launchers (sudo-compatible) ──────────────────────────────
# Small scripts rather than symlinks into the venv: they hard-code the venv's Python, so
# `sudo beatrix` works (root has a different PATH), and keep the invoking user's HOME so
# ~/.beatrix is still found under sudo. -P keeps the current directory off sys.path, so the
# installed Beatrix runs wherever you launch it from.

_put_launcher() {
    local path="$LAUNCH_DIR/$1" content="$2"
    # rm first: an old install may have left a symlink here, and writing through it would
    # land in the old venv.
    if [[ -w "$LAUNCH_DIR" ]]; then
        rm -f -- "$path"
        printf '%s\n' "$content" > "$path" && chmod 755 "$path"
    else
        as_root rm -f -- "$path"
        printf '%s\n' "$content" | as_root tee "$path" >/dev/null && as_root chmod 755 "$path"
    fi
}

install_launchers() {
    section "Installing the launchers..."
    LAUNCH_DIR="$INSTALL_DIR"
    if [[ ! -d "$LAUNCH_DIR" ]]; then
        mkdir -p "$LAUNCH_DIR" 2>/dev/null || as_root mkdir -p "$LAUNCH_DIR" 2>/dev/null || true
    fi
    if [[ ! -w "$LAUNCH_DIR" ]] && ! as_root true 2>/dev/null; then
        LAUNCH_DIR="$TOOLS_BIN"
        mkdir -p "$LAUNCH_DIR"
        warn "No root access: the launchers go to $LAUNCH_DIR instead of $INSTALL_DIR"
        _add_to_path "$LAUNCH_DIR"
    fi
    local py="$VENV_DIR/bin/python" head
    head="#!/usr/bin/env bash
# Beatrix launcher — written by install.sh.
if [ -n \"\${SUDO_USER:-}\" ] && [ \"\$SUDO_USER\" != root ]; then
    HOME=\"\$(getent passwd \"\$SUDO_USER\" | cut -d: -f6)\"
    export HOME
fi"
    _put_launcher beatrix "$head
exec \"$py\" -P -W ignore::RuntimeWarning -m beatrix.cli.main \"\$@\""
    _put_launcher beatrix-suite "$head
exec \"$py\" -P -W ignore::RuntimeWarning -m beatrix.cli.main suite \"\$@\""
    _put_launcher beatrix-update "$head
exec \"$py\" -P -W ignore::RuntimeWarning -m beatrix.cli.main update \"\$@\""
    success "beatrix, beatrix-suite, beatrix-update → $LAUNCH_DIR"
}

# ── Go ───────────────────────────────────────────────────────

ensure_go() {
    if command_exists go; then
        return 0
    fi
    if [[ -x /usr/local/go/bin/go ]]; then
        _add_to_path /usr/local/go/bin
        return 0
    fi
    info "Installing the Go toolchain..."
    local ver arch tmp
    ver="$(curl -fsSL 'https://go.dev/VERSION?m=text' 2>/dev/null | head -n1 | sed 's/^go//' | tr -d '[:space:]' || true)"
    [[ "$ver" =~ ^[0-9]+\.[0-9]+ ]] || ver="1.23.4"
    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv6l|armv7l) arch="armv6l" ;;
        *)             arch="amd64" ;;
    esac
    tmp="$(mktemp -d)"
    if run_logged "download go$ver" curl -fsSL "https://go.dev/dl/go${ver}.linux-${arch}.tar.gz" -o "$tmp/go.tgz" \
       && as_root rm -rf /usr/local/go \
       && run_logged "extract go$ver" as_root tar -C /usr/local -xzf "$tmp/go.tgz"; then
        rm -rf -- "$tmp"
        _add_to_path /usr/local/go/bin
        command_exists go
        return
    fi
    rm -rf -- "$tmp"
    return 1
}

# GOPATH/GOBIN the toolchain is configured with (e.g. /go in devcontainers), falling back to
# ~/go when that isn't writable — go install also writes its module cache under GOPATH.
_go_env() {
    local gp
    gp="$(go env GOPATH 2>/dev/null | cut -d: -f1)"
    if [[ -z "$gp" ]] || ! mkdir -p "$gp/bin" 2>/dev/null || [[ ! -w "$gp" ]]; then
        export GOPATH="$HOME/go"
        mkdir -p "$GOPATH/bin"
    fi
    GOBIN_DIR="$(go env GOBIN 2>/dev/null)"
    if [[ -z "$GOBIN_DIR" ]]; then
        GOBIN_DIR="$(go env GOPATH 2>/dev/null | cut -d: -f1)/bin"
    fi
    if ! mkdir -p "$GOBIN_DIR" 2>/dev/null || [[ ! -w "$GOBIN_DIR" ]]; then
        export GOBIN="$HOME/go/bin"
        GOBIN_DIR="$GOBIN"
        mkdir -p "$GOBIN_DIR"
    fi
    _add_to_path "$GOBIN_DIR"
}

# ── External tools ───────────────────────────────────────────

_tools_system() {
    section "System packages"
    local -A pkgs=()
    case "$PKG_MGR" in
        apt)    pkgs=([nmap]=nmap [sqlmap]=sqlmap [whois]=whois [dig]=dnsutils [tshark]=tshark [adb]="adb|android-tools-adb") ;;
        dnf)    pkgs=([nmap]=nmap [sqlmap]=sqlmap [whois]=whois [dig]=bind-utils [tshark]=wireshark-cli [adb]=android-tools) ;;
        pacman) pkgs=([nmap]=nmap [sqlmap]=sqlmap [whois]=whois [dig]=bind [tshark]=wireshark-cli [adb]=android-tools) ;;
        apk)    pkgs=([nmap]=nmap [sqlmap]=sqlmap [whois]=whois [dig]=bind-tools [tshark]=tshark [adb]=android-tools) ;;
    esac
    # whois + dig: OSINT WHOIS and origin-IP discovery. tshark: packet dissection in the
    # Packets module. adb: the mobile interceptor.
    local tool
    for tool in nmap sqlmap whois dig tshark adb; do
        if command_exists "$tool"; then
            tool_ok "$tool" "already installed"
        elif [[ -n "${pkgs[$tool]:-}" ]] && pkg_install_any "${pkgs[$tool]}" && command_exists "$tool"; then
            tool_ok "$tool"
        else
            tool_failed "$tool"
        fi
    done
    # A C toolchain + libpcap (naabu is built against it) + the headers native Ruby gems need.
    local libs=()
    case "$PKG_MGR" in
        apt)    libs=(build-essential libpcap-dev libcurl4-openssl-dev zlib1g-dev libffi-dev) ;;
        dnf)    libs=(gcc gcc-c++ make libpcap-devel libcurl-devel zlib-devel libffi-devel) ;;
        pacman) libs=(base-devel libpcap curl zlib libffi) ;;
        apk)    libs=(build-base libpcap-dev curl-dev zlib-dev libffi-dev) ;;
    esac
    if [[ ${#libs[@]} -gt 0 ]]; then
        if pkg_install "${libs[@]}"; then
            success "build tools + libpcap, libcurl, zlib, libffi headers"
        else
            warn "Some build libraries didn't install — naabu and the Ruby gems may fail to build"
        fi
    fi
}

_nomore403_payloads() {
    # nomore403 reads its payload lists from a payloads/ folder (next to the binary unless told
    # otherwise); go install doesn't ship one. Copy it from the module source.
    local dest="$SHARE_DIR/nomore403/payloads" src
    if [[ -f "$dest/httpmethods" ]]; then
        success "nomore403 payloads (already present)"
        return 0
    fi
    src="$(go mod download -json github.com/devploit/nomore403@latest 2>/dev/null \
            | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p' | head -n1 || true)"
    if [[ -n "$src" && -f "$src/payloads/httpmethods" ]]; then
        mkdir -p "$(dirname "$dest")"
        rm -rf -- "$dest"
        cp -r "$src/payloads" "$dest"
        chmod -R u+w "$dest"                                   # the module cache is read-only
        success "nomore403 payloads → $dest"
    else
        tool_failed nomore403-payloads "Could not fetch nomore403's payloads — most of its bypass techniques will be skipped"
    fi
}

_webanalyze_db() {
    # webanalyze refuses to run without its fingerprint database. Refresh it every install.
    local dir="$SHARE_DIR/webanalyze" cached
    mkdir -p "$dir"
    if curl -fsSL "$WEBANALYZE_DB_URL" -o "$dir/technologies.json.new" 2>/dev/null && [[ -s "$dir/technologies.json.new" ]]; then
        mv "$dir/technologies.json.new" "$dir/technologies.json"
        success "webanalyze fingerprint database"
        return 0
    fi
    rm -f "$dir/technologies.json.new"
    cached="$(find "$(go env GOMODCACHE 2>/dev/null || echo "$HOME/go/pkg/mod")" -name technologies.json -path '*webanalyze*' 2>/dev/null | head -n1 || true)"
    if [[ -n "$cached" ]]; then
        cp "$cached" "$dir/technologies.json" && chmod u+w "$dir/technologies.json"
        success "webanalyze fingerprint database (from the Go module cache)"
    elif [[ -s "$dir/technologies.json" ]]; then
        warn "Couldn't refresh the webanalyze database — keeping the existing copy"
    else
        tool_failed webanalyze-db "Couldn't fetch the webanalyze database ($WEBANALYZE_DB_URL)"
    fi
}

_tools_go() {
    section "Go tools"
    if ! ensure_go; then
        tool_failed go "The Go toolchain isn't available — skipping every Go tool"
        return 0
    fi
    _go_env
    success "Go $(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//') → binaries in $GOBIN_DIR"

    local -A mods=(
        [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        [ffuf]="github.com/ffuf/ffuf/v2@latest"
        [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
        [gospider]="github.com/jaeles-project/gospider@latest"
        [hakrawler]="github.com/hakluke/hakrawler@latest"
        [gau]="github.com/lc/gau/v2/cmd/gau@latest"
        [dalfox]="github.com/hahwul/dalfox/v2@latest"
        [amass]="github.com/owasp-amass/amass/v4/...@master"
        [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        [tlsx]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
        [gowitness]="github.com/sensepost/gowitness@latest"
        [interactsh-client]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        [notify]="github.com/projectdiscovery/notify/cmd/notify@latest"
        [webanalyze]="github.com/rverton/webanalyze/cmd/webanalyze@latest"
        [nomore403]="github.com/devploit/nomore403@latest"
        [crlfuzz]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        [s3scanner]="github.com/sa7mon/s3scanner@latest"
    )
    local tool
    for tool in nuclei httpx subfinder ffuf katana gospider hakrawler gau dalfox amass naabu dnsx \
                tlsx gowitness interactsh-client notify webanalyze nomore403 crlfuzz s3scanner; do
        # _have_bin skips same-named Python scripts: pip's httpx CLI and the old PyPI s3scanner.
        if _have_bin "$tool"; then
            tool_ok "$tool" "already installed"
            continue
        fi
        info "Installing $tool..."
        if run_logged "go install $tool" go install "${mods[$tool]}" && _have_bin "$tool"; then
            tool_ok "$tool"
        else
            tool_failed "$tool"
        fi
    done
    _nomore403_payloads
    _webanalyze_db

    # Create the tools' config dirs as you now, so a later sudo run doesn't make them root-owned.
    if command_exists subfinder; then subfinder -h >/dev/null 2>&1 || true; fi
    if command_exists amass; then amass -h >/dev/null 2>&1 || true; fi
    # nuclei needs its templates (~500 MB); fetch them now rather than mid-scan.
    if command_exists nuclei; then
        info "Updating nuclei templates (first time: ~500 MB)..."
        if run_logged "nuclei templates" nuclei -update-templates; then
            success "nuclei templates"
        else
            tool_failed nuclei-templates "Couldn't download the nuclei templates (retry: nuclei -update-templates)"
        fi
    fi
}

# gh_release_bin <owner/repo> <asset-prefix> <binary>: the newest release's
# <prefix>_<version>_linux_<arch>.tar.gz, binary into ~/.local/bin. The tag comes from the
# /releases/latest redirect, not the API, so there's no API rate limit to hit.
gh_release_bin() {
    local repo="$1" prefix="$2" bin="$3" arch tag ver tmp found
    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             return 1 ;;
    esac
    tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")" || return 1
    tag="${tag##*/}"
    ver="${tag#v}"
    [[ -n "$ver" && "$ver" != "latest" ]] || return 1
    tmp="$(mktemp -d)"
    if curl -fsSL "https://github.com/$repo/releases/download/$tag/${prefix}_${ver}_linux_${arch}.tar.gz" -o "$tmp/a.tgz" \
       && tar -xzf "$tmp/a.tgz" -C "$tmp"; then
        found="$(find "$tmp" -type f -name "$bin" | head -n1 || true)"
        if [[ -n "$found" ]]; then
            install -m 755 "$found" "$TOOLS_BIN/$bin"
            rm -rf -- "$tmp"
            return 0
        fi
    fi
    rm -rf -- "$tmp"
    return 1
}

_tools_release() {
    section "Release binaries"
    # trufflehog's go.mod uses replace directives, so `go install` can't build it.
    if _have_bin trufflehog; then
        tool_ok trufflehog "already installed"
    elif run_logged "trufflehog release" gh_release_bin trufflesecurity/trufflehog trufflehog trufflehog; then
        tool_ok trufflehog
    else
        tool_failed trufflehog
    fi
    if _have_bin kr; then
        tool_ok kiterunner "already installed"
    elif run_logged "kiterunner release" gh_release_bin assetnote/kiterunner kiterunner kr; then
        tool_ok kiterunner
    else
        tool_failed kiterunner
    fi
    # The routes wordlist kiterunner scans with (where Beatrix looks for it).
    local kd="$SHARE_DIR/kiterunner"
    mkdir -p "$kd"
    if [[ -s "$kd/routes-small.kite" ]]; then
        success "kiterunner routes wordlist (already present)"
    elif run_logged "kiterunner wordlist" sh -c "curl -fsSL '$KITE_URL' | tar -xz -C '$kd'" && [[ -s "$kd/routes-small.kite" ]]; then
        success "kiterunner routes wordlist"
    else
        tool_failed kiterunner-wordlist "Couldn't fetch the kiterunner wordlist ($KITE_URL)"
    fi
}

# _py_tool_install <package>: an isolated venv per tool, its commands linked into ~/.local/bin.
# (A user-level pip install fails on PEP 668 distros and mixes the tools' dependencies.)
_py_tool_install() {
    if command_exists uv; then
        run_logged "uv tool install $1" uv tool install --force "$1" \
            || run_logged "uv tool install $1 (Python 3.12)" uv tool install --force --python 3.12 "$1"
    elif command_exists pipx; then
        run_logged "pipx install $1" pipx install --force "$1"
    else
        return 1
    fi
}

_mkvenv() {
    rm -rf -- "$1"
    if command_exists uv; then
        uv venv "$1"
    else
        "${PYTHON:-python3}" -m venv "$1"
    fi
}

_venv_pip() {
    local v="$1"; shift
    if command_exists uv; then
        uv pip install --python "$v/bin/python" "$@"
    else
        "$v/bin/python" -m pip install "$@"
    fi
}

_jwt_tool() {
    local dir="$SHARE_DIR/jwt_tool" launcher="$TOOLS_BIN/jwt_tool"
    if [[ -x "$launcher" ]] && "$launcher" -h >/dev/null 2>&1; then
        tool_ok jwt_tool "already installed"
        return 0
    fi
    info "Installing jwt_tool (own venv in $dir)..."
    mkdir -p "$dir"
    if run_logged "jwt_tool download" curl -fsSL "https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py" -o "$dir/jwt_tool.py" \
       && run_logged "jwt_tool venv" _mkvenv "$dir/venv" \
       && run_logged "jwt_tool deps" _venv_pip "$dir/venv" termcolor pycryptodomex requests ratelimit; then
        printf '#!/usr/bin/env bash\nexec "%s" "%s" "$@"\n' "$dir/venv/bin/python" "$dir/jwt_tool.py" > "$launcher"
        chmod 755 "$launcher"
        if "$launcher" -h >/dev/null 2>&1; then
            tool_ok jwt_tool
            return 0
        fi
    fi
    tool_failed jwt_tool
}

# The old installer pip-installed the PyPI "s3scanner" (a different tool with different flags);
# its script sits first on PATH and shadows the Go v3 CLI Beatrix drives.
_remove_pypi_s3scanner() {
    local p interp
    p="$(command -v s3scanner 2>/dev/null)" || return 0
    if _is_python_script "$p" && grep -q 'S3Scanner' "$p" 2>/dev/null; then
        interp="$(head -n1 "$p" | sed 's/^#!//' | awk '{print $1}')"
        if [[ -x "$interp" ]] && run_logged "remove PyPI s3scanner" "$interp" -m pip uninstall -y s3scanner; then
            info "Removed the old PyPI s3scanner (Beatrix uses the Go v3 CLI)"
        fi
    fi
    return 0
}

_tools_python() {
    section "Python tools (each in its own environment)"
    # package → the command it provides
    local -A cmd=([mitmproxy]=mitmdump [commix]=commix [arjun]=arjun [clairvoyance]=clairvoyance
                  [dirsearch]=dirsearch [wafw00f]=wafw00f [waymore]=waymore)
    local pkg
    for pkg in mitmproxy commix arjun clairvoyance dirsearch wafw00f waymore; do
        if command_exists "${cmd[$pkg]}"; then
            tool_ok "$pkg" "already installed"
        elif _py_tool_install "$pkg" && { hash -r; command_exists "${cmd[$pkg]}"; }; then
            tool_ok "$pkg"
        else
            tool_failed "$pkg"
        fi
    done
    _remove_pypi_s3scanner
    _jwt_tool
}

_whatweb() {
    local src="$SHARE_DIR/whatweb"
    if command_exists whatweb && whatweb --version >/dev/null 2>&1; then
        tool_ok whatweb "already installed"
        return 0
    fi
    if ! command_exists ruby; then
        tool_failed whatweb "whatweb needs Ruby, which isn't available"
        return 0
    fi
    # From source: the distro package breaks under rbenv/RVM Rubies (it hard-codes the
    # system Ruby's load path).
    rm -rf -- "$src"
    if run_logged "whatweb clone" git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git "$src"; then
        chmod +x "$src/whatweb"
        ln -sf "$src/whatweb" "$TOOLS_BIN/whatweb"
        if command_exists gem; then
            run_logged "gem install addressable" gem install addressable || true
        fi
        if "$src/whatweb" --version >/dev/null 2>&1; then
            tool_ok whatweb
        else
            tool_failed whatweb "whatweb was cloned but doesn't start (missing gems? see the log)"
        fi
    else
        tool_failed whatweb
    fi
}

_tools_ruby_node() {
    section "Ruby and Node tools"
    if ! command_exists ruby || ! command_exists gem; then
        case "$PKG_MGR" in
            apt)    pkg_install ruby-full ruby-dev || true ;;
            dnf)    pkg_install ruby ruby-devel rubygems || true ;;
            pacman) pkg_install ruby rubygems || true ;;
            apk)    pkg_install ruby ruby-dev || true ;;
        esac
        hash -r
    fi
    _whatweb
    if command_exists wpscan; then
        tool_ok wpscan "already installed"
    elif ! command_exists gem; then
        tool_failed wpscan "wpscan needs Ruby (gem), which isn't available"
    elif run_logged "gem install wpscan" gem install wpscan || run_logged "sudo gem install wpscan" as_root gem install wpscan; then
        hash -r
        if command_exists wpscan; then tool_ok wpscan; else tool_failed wpscan "wpscan installed, but its gem bin dir isn't on PATH"; fi
    else
        tool_failed wpscan
    fi
    # rea: upstream npm package only (impostor builds of REA circulate).
    if ! command_exists npm; then
        pkg_install npm || true
        hash -r
    fi
    if command_exists rea; then
        tool_ok rea "already installed"
    elif ! command_exists npm; then
        tool_failed rea "rea needs npm, which isn't available"
    elif run_logged "npm install -g rea-agents" npm install -g rea-agents || run_logged "sudo npm install -g rea-agents" as_root npm install -g rea-agents; then
        hash -r
        if command_exists rea; then tool_ok rea; else tool_failed rea "rea installed, but npm's global bin dir isn't on PATH"; fi
    else
        tool_failed rea
    fi
}

_chromium_ok() {
    "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
from pathlib import Path
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    assert Path(p.chromium.executable_path).exists()
PY
}

_tools_playwright() {
    section "Playwright Chromium (capture browser, SPA recon, auto-login)"
    local py="$VENV_DIR/bin/python"
    if ! "$py" -c 'import playwright' >/dev/null 2>&1; then
        tool_failed chromium "playwright isn't installed in $VENV_DIR"
        return 0
    fi
    # The shared libraries Chromium needs. Playwright knows the right package names for each
    # Debian/Ubuntu release (a fixed list broke on Ubuntu 24.04, where libasound2 is virtual).
    # nuclei's headless mode needs the same libraries.
    if [[ $PKG_MGR == apt ]]; then
        run_logged "playwright install-deps" as_root "$py" -m playwright install-deps chromium \
            || warn "Some Chromium libraries didn't install — the browser may not start"
    fi
    if run_logged "playwright install chromium" "$py" -m playwright install chromium && _chromium_ok; then
        tool_ok chromium
    else
        tool_failed chromium
    fi
    if [[ -x "$VENV_DIR/bin/playwright" ]]; then
        ln -sf "$VENV_DIR/bin/playwright" "$TOOLS_BIN/playwright"
    fi
}

_tools_metasploit() {
    section "Metasploit Framework"
    if command_exists msfconsole; then
        tool_ok metasploit "already installed"
        return 0
    fi
    info "Installing Metasploit with Rapid7's installer (a few minutes)..."
    local f
    f="$(mktemp)"
    if run_logged "msfinstall download" curl -fsSL "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb" -o "$f" \
       && chmod +x "$f" && run_logged "msfinstall" as_root "$f"; then
        hash -r
        if command_exists msfconsole; then tool_ok metasploit; else tool_failed metasploit; fi
    else
        tool_failed metasploit
    fi
    rm -f -- "$f"
}

_tools_android() {
    section "Android SDK + emulator (--with-android)"
    local sdk="${ANDROID_HOME:-$HOME/Android/Sdk}" arch img tmp avds
    if ! command_exists java; then
        case "$PKG_MGR" in
            apt)    pkg_install openjdk-17-jdk-headless || true ;;
            dnf)    pkg_install java-17-openjdk-headless || true ;;
            pacman) pkg_install jdk17-openjdk || true ;;
            apk)    pkg_install openjdk17-jdk || true ;;
        esac
    fi
    command_exists unzip || pkg_install unzip || true
    hash -r
    if ! command_exists java || ! command_exists unzip; then
        tool_failed android-sdk "The Android SDK tools need Java 17 and unzip"
        return 0
    fi
    local sm="$sdk/cmdline-tools/latest/bin/sdkmanager" am="$sdk/cmdline-tools/latest/bin/avdmanager"
    if [[ ! -x "$sm" ]]; then
        tmp="$(mktemp -d)"
        if run_logged "android cmdline-tools" curl -fsSL "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS}_latest.zip" -o "$tmp/t.zip" \
           && run_logged "unzip cmdline-tools" unzip -q "$tmp/t.zip" -d "$tmp"; then
            mkdir -p "$sdk/cmdline-tools"
            rm -rf -- "$sdk/cmdline-tools/latest"
            mv "$tmp/cmdline-tools" "$sdk/cmdline-tools/latest"
        fi
        rm -rf -- "$tmp"
    fi
    if [[ ! -x "$sm" ]]; then
        tool_failed android-sdk
        return 0
    fi
    case "$(uname -m)" in
        aarch64|arm64) arch="arm64-v8a" ;;
        *)             arch="x86_64" ;;
    esac
    img="system-images;android-34;google_apis;$arch"
    if run_logged "sdkmanager licenses" sh -c "yes | '$sm' --sdk_root='$sdk' --licenses" \
       && run_logged "sdkmanager packages" "$sm" --sdk_root="$sdk" platform-tools emulator "platforms;android-34" "$img"; then
        tool_ok android-sdk
    else
        tool_failed android-sdk
        return 0
    fi
    # The AVD the mobile interceptor launches by default.
    avds="$("$am" list avd 2>/dev/null || true)"
    if [[ "$avds" == *"Name: beatrix_hunter"* ]]; then
        success "AVD beatrix_hunter (already exists)"
    elif run_logged "avdmanager create" sh -c "echo no | '$am' create avd -n beatrix_hunter -k '$img' -d pixel_6"; then
        tool_ok avd-beatrix_hunter
    else
        tool_failed avd-beatrix_hunter
    fi
    _add_to_path "$sdk/platform-tools"
    if [[ "$sdk" != "$HOME/Android/Sdk" ]]; then
        info "Beatrix finds this SDK through ANDROID_HOME=$sdk — keep it set in your shell."
    fi
    if [[ ! -e /dev/kvm ]]; then
        warn "No /dev/kvm here: the emulator needs hardware virtualisation to run at a usable speed"
    fi
}

_tools_docker() {
    section "Docker + GHOST v2 sandbox image (--with-docker)"
    if ! command_exists docker; then
        case "$PKG_MGR" in
            apt)    pkg_install docker.io || true ;;
            dnf)    pkg_install moby-engine || pkg_install docker || true ;;
            pacman) pkg_install docker || true ;;
            apk)    pkg_install docker || true ;;
        esac
        hash -r
        as_root systemctl enable --now docker >/dev/null 2>&1 || as_root service docker start >/dev/null 2>&1 || true
    fi
    if ! command_exists docker; then
        tool_failed docker
        return 0
    fi
    local dk=(docker)
    if ! docker info >/dev/null 2>&1 && [[ $EUID -ne 0 ]]; then
        if as_root usermod -aG docker "$(id -un)" >/dev/null 2>&1; then
            info "Added $(id -un) to the docker group — log out and back in for GHOST to use Docker"
        fi
        dk=(as_root docker)
    fi
    if ! "${dk[@]}" info >/dev/null 2>&1; then
        tool_failed docker "The Docker daemon isn't reachable"
        return 0
    fi
    tool_ok docker
    info "Building beatrix/ghost-sandbox:latest (several minutes)..."
    if run_logged "docker build ghost-sandbox" "${dk[@]}" build -f "$SRC_DIR/docker/ghost-sandbox.Dockerfile" \
            -t beatrix/ghost-sandbox:latest "$SRC_DIR"; then
        tool_ok ghost-sandbox "GHOST v2 uses it automatically"
    else
        tool_failed ghost-sandbox
    fi
}

_write_sudo_rules() {
    local py="$1" nmap_bin="$2" user tmp cmds
    user="$(id -un)"
    cmds="$py -m beatrix.core.scapy_worker"
    if [[ -n "$nmap_bin" ]]; then
        cmds="$nmap_bin, $cmds"
    fi
    warn "Writing /etc/sudoers.d/beatrix. This is ROOT-EQUIVALENT for $user: nmap's NSE scripts"
    warn "and the Beatrix venv's Python both run code $user controls as root. Delete the file to revoke."
    tmp="$(mktemp)"
    {
        echo "# Written by Beatrix install.sh --with-sudo-rules: packet capture and raw-socket nmap."
        echo "# Root-equivalent for $user (nmap NSE scripts, the venv's Python). Delete to revoke."
        echo "$user ALL=(root) NOPASSWD: $cmds"
    } > "$tmp"
    if as_root visudo -cf "$tmp" >/dev/null && as_root install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/beatrix; then
        success "Passwordless sudo for packet capture and raw-socket nmap (/etc/sudoers.d/beatrix)"
    else
        warn "Couldn't install the sudoers rule"
    fi
    rm -f -- "$tmp"
}

_tools_privileges() {
    section "Privileges (packet capture, raw-socket nmap scans)"
    if [[ $EUID -eq 0 ]]; then
        success "Running as root — nothing to set up"
        return 0
    fi
    if ! command_exists sudo; then
        warn "sudo isn't installed: packet capture and raw-socket nmap scans (-sS, -O, -A) won't be available"
        return 0
    fi
    local py="$VENV_DIR/bin/python" nmap_bin cap=0 raw=0
    nmap_bin="$(command -v nmap 2>/dev/null || true)"
    # Ask sudo about these exact commands — that is how Beatrix checks too.
    if sudo -n -l "$py" -m beatrix.core.scapy_worker >/dev/null 2>&1; then cap=1; fi
    if [[ -n "$nmap_bin" ]] && sudo -n -l "$nmap_bin" >/dev/null 2>&1; then raw=1; fi
    if [[ $cap -eq 1 && ( $raw -eq 1 || -z "$nmap_bin" ) ]]; then
        success "Passwordless sudo already covers packet capture and raw-socket nmap"
    elif [[ $WITH_SUDO_RULES -eq 1 ]]; then
        _write_sudo_rules "$py" "$nmap_bin"
    else
        warn "Packet capture and raw-socket nmap scans need passwordless sudo, which $(id -un) doesn't have."
        info "  Re-run with ${BOLD}--with-sudo-rules${RESET} to allow exactly those two commands (root-equivalent)."
    fi
}

# Install or repair the whole external arsenal. Also called on its own by `beatrix setup` and
# `make setup` (they source this file, which doesn't run main()).
install_external_tools() {
    local saved_opts
    saved_opts="$(set +o)"
    set +e                                    # one failed tool must not stop the others
    [[ -n "$PKG_MGR" ]] || detect_pkg_manager
    if [[ -z "$USE_UV" ]]; then
        if command_exists uv; then USE_UV=1; else USE_UV=0; fi
    fi
    if [[ -z "$SRC_DIR" && -n "${BASH_SOURCE[0]:-}" ]]; then
        SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi
    TOOLS_OK=()
    TOOLS_FAILED=()
    mkdir -p "$TOOLS_BIN" "$SHARE_DIR"
    _add_to_path "$TOOLS_BIN"

    echo ""
    echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}${BOLD}║       ⚔️  ARMING THE ARSENAL  ⚔️         ║${RESET}"
    echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════╝${RESET}"

    _tools_system
    _tools_go
    _tools_release
    _tools_python
    _tools_ruby_node
    _tools_playwright
    _tools_metasploit
    if [[ $WITH_ANDROID -eq 1 ]]; then _tools_android; fi
    if [[ $WITH_DOCKER -eq 1 ]]; then _tools_docker; fi
    _tools_privileges

    section "Arsenal summary"
    echo -e "  ${GREEN}✓ Ready:${RESET}  ${#TOOLS_OK[@]}"
    if [[ ${#TOOLS_FAILED[@]} -gt 0 ]]; then
        echo -e "  ${RED}✗ Failed:${RESET} ${#TOOLS_FAILED[@]} — ${TOOLS_FAILED[*]}"
        echo -e "  ${DIM}Logs: $LOG_DIR · retry anytime: beatrix setup${RESET}"
    fi
    eval "$saved_opts"
    return 0
}

# ── Post-install check ───────────────────────────────────────

post_install_check() {
    section "Checking the installation..."
    local out rc=0
    if out="$("$LAUNCH_DIR/beatrix" --version 2>&1)"; then
        success "beatrix runs: $(tail -n1 <<<"$out")"
    else
        warn "$LAUNCH_DIR/beatrix doesn't run: $(tail -n1 <<<"$out")"
        REQUIRED_FAILED+=("beatrix launcher")
    fi
    BEATRIX_CHECK_TOOLS=$((1 - NO_TOOLS)) "$VENV_DIR/bin/python" - "$SHARE_DIR" <<'PY' || rc=$?
import importlib.util, os, shutil, subprocess, sys
from pathlib import Path

share = Path(sys.argv[1])
tools = os.environ.get("BEATRIX_CHECK_TOOLS") == "1"
G, Y, R, D, X = "\033[0;32m", "\033[1;33m", "\033[0;31m", "\033[2m", "\033[0m"
failed = []

def line(ok, name, detail="", required=False):
    mark = G + "✓" + X if ok else (R + "✗" + X if required else Y + "○" + X)
    print("  %s %s%s" % (mark, name, ("  " + D + detail + X) if detail else ""))
    if required and not ok:
        failed.append(name)

# Required: every package Beatrix imports (core + extended + agent extras).
mods = {"click": "click", "rich": "rich", "httpx": "httpx", "aiohttp": "aiohttp", "requests": "requests",
        "urllib3": "urllib3", "pyyaml": "yaml", "boto3": "boto3", "PyJWT": "jwt", "cryptography": "cryptography",
        "dnspython": "dns", "python-nmap": "nmap", "paramiko": "paramiko", "scapy": "scapy",
        "playwright": "playwright", "msgpack": "msgpack", "mmh3": "mmh3", "zstandard": "zstandard",
        "mitmproxy": "mitmproxy", "cloudscraper": "cloudscraper", "networkx": "networkx",
        "matplotlib": "matplotlib", "openai-agents": "agents", "litellm": "litellm", "docker": "docker",
        "rank-bm25": "rank_bm25", "beatrix": "beatrix"}
missing = sorted(p for p, m in mods.items() if importlib.util.find_spec(m) is None)
line(not missing, "Python packages", ("missing: " + ", ".join(missing)) if missing else "all %d present" % len(mods), True)

if tools:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            exe = p.chromium.executable_path
        line(Path(exe).exists(), "Playwright Chromium", exe, True)
    except Exception as e:  # noqa: BLE001
        line(False, "Playwright Chromium", ("%s: %s" % (type(e).__name__, e))[:120], True)

    go = shutil.which("go") or ("/usr/local/go/bin/go" if Path("/usr/local/go/bin/go").exists() else None)
    line(bool(go), "Go toolchain", go or "not found", True)

    # The external tools, found the way Beatrix finds them.
    from beatrix.core.external_tools import ExternalToolkit, go_bin_dirs
    status = dict(ExternalToolkit().status())
    for name in ("nuclei", "subfinder", "ffuf", "nmap", "mitmdump", "whois", "dig", "tshark", "adb"):
        status[name] = any(c and Path(c).exists() for c in [shutil.which(name), *(str(Path(d) / name) for d in go_bin_dirs()),
                                                            str(Path.home() / ".local" / "bin" / name)])
    absent = sorted(k for k, v in status.items() if not v)
    line(not absent, "External tools: %d of %d" % (len(status) - len(absent), len(status)),
         ("missing: " + ", ".join(absent)) if absent else "")

    data = {"nuclei templates": Path.home() / "nuclei-templates",
            "webanalyze fingerprints": share / "webanalyze" / "technologies.json",
            "kiterunner wordlist": share / "kiterunner" / "routes-small.kite",
            "nomore403 payloads": share / "nomore403" / "payloads" / "httpmethods"}
    for name, p in data.items():
        line(p.exists(), name, str(p))

    if os.geteuid() == 0:
        line(True, "Root privileges", "running as root")
    elif shutil.which("sudo"):
        def can(*argv):
            try:
                return subprocess.run(["sudo", "-n", "-l", *argv], capture_output=True, timeout=5).returncode == 0
            except Exception:  # noqa: BLE001
                return False
        cap = can(sys.executable, "-m", "beatrix.core.scapy_worker")
        nm = shutil.which("nmap")
        raw = bool(nm) and can(nm)
        hint = "re-run install.sh with --with-sudo-rules"
        line(cap, "Packet capture (passwordless sudo)", "" if cap else hint)
        line(raw, "Raw-socket nmap scans (passwordless sudo)", "" if raw else hint)

if failed:
    print("REQUIRED_FAILED:" + ",".join(failed), file=sys.stderr)
sys.exit(2 if failed else 0)
PY
    if [[ $rc -ne 0 ]]; then
        REQUIRED_FAILED+=("see the ✗ lines above")
    fi
    return 0
}

final_summary() {
    echo ""
    if [[ ${#REQUIRED_FAILED[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}══════════════════════════════════════════${RESET}"
        echo -e "${RED}${BOLD}  Installed, but required parts are missing:${RESET} ${REQUIRED_FAILED[*]}"
        echo -e "${RED}${BOLD}══════════════════════════════════════════${RESET}"
        echo -e "  ${DIM}Logs: ${LOG_DIR:-none} — fix the cause and re-run ./install.sh${RESET}"
        echo ""
        return 2
    fi
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${BOLD}Quick start:${RESET}"
    echo -e "    ${CYAN}beatrix-suite${RESET}                    The dashboard (open the link it prints)"
    echo -e "    ${CYAN}beatrix hunt example.com${RESET}         Scan a target"
    echo -e "    ${CYAN}beatrix setup --check${RESET}            Tool status"
    echo ""
    echo -e "  ${DIM}Python environment: $VENV_DIR · your data: $BEATRIX_HOME${RESET}"
    if [[ ${#TOOLS_FAILED[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Optional tools that didn't install:${RESET} ${TOOLS_FAILED[*]} ${DIM}(retry: beatrix setup)${RESET}"
    fi
    echo ""
    echo -e "  ${DIM}\"Revenge is a dish best served with a working PoC.\"${RESET}"
    echo ""
    return 0
}

# ── Main ─────────────────────────────────────────────────────

main() {
    parse_args "$@"
    banner
    check_invocation
    trap cleanup_clone EXIT
    preflight
    find_python || true
    ensure_uv
    if [[ -z "$PYTHON" && $USE_UV -eq 0 ]]; then
        fail "Python >= $MIN_PYTHON is required (or uv, which can fetch one)"
    fi
    locate_source
    migrate_old_layout
    create_venv
    install_beatrix
    install_launchers
    if [[ $NO_TOOLS -eq 0 ]]; then
        install_external_tools
    else
        info "Skipping the external tools (--no-tools) — install them later with: beatrix setup"
    fi
    post_install_check
    final_summary || exit 2
}

# Run only when executed (./install.sh, bash install.sh, curl … | bash) — not when sourced:
# `beatrix setup` and `make setup` source this file just to call install_external_tools.
if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
