#!/usr/bin/env bash
# BEATRIX — Uninstaller
#
# Removes the Python environment, the beatrix / beatrix-suite / beatrix-update launchers and the
# optional sudoers rule. Your data in ~/.beatrix (findings, sessions, config, API keys) is only
# deleted if you say so. The external tools (nuclei, nmap, …) stay — they're general-purpose.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

BEATRIX_HOME="$HOME/.beatrix"
INSTALL_DIR="${BEATRIX_INSTALL_DIR:-/usr/local/bin}"
VENV_DIR="${BEATRIX_VENV:-$BEATRIX_HOME/venv}"

done_msg() { echo -e "  ${GREEN}✓${RESET} $*"; }
as_root() { if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

echo ""
echo -e "${BOLD}Uninstalling Beatrix...${RESET}"
echo ""

# Launchers — only files install.sh wrote (or symlinks into a Beatrix venv).
for dir in "$INSTALL_DIR" "$HOME/.local/bin"; do
    for bin in beatrix beatrix-suite beatrix-update; do
        f="$dir/$bin"
        [[ -e "$f" || -L "$f" ]] || continue
        if [[ -L "$f" ]] || grep -q "beatrix.cli.main" "$f" 2>/dev/null; then
            if [[ -w "$dir" ]]; then rm -f -- "$f"; else as_root rm -f -- "$f"; fi
            done_msg "Removed $f"
        fi
    done
done

# The venv (current layout) — only if it really is one.
if [[ -f "$VENV_DIR/pyvenv.cfg" && "${VENV_DIR%/}" != "$BEATRIX_HOME" ]]; then
    rm -rf -- "$VENV_DIR"
    done_msg "Removed the Python environment ($VENV_DIR)"
fi

# Older installs put the venv straight into ~/.beatrix: remove just its files.
if [[ -f "$BEATRIX_HOME/pyvenv.cfg" ]]; then
    [[ -f "$BEATRIX_HOME/bin/activate" ]] && rm -rf -- "${BEATRIX_HOME:?}/bin"
    [[ -L "$BEATRIX_HOME/lib64" ]] && rm -f -- "$BEATRIX_HOME/lib64"
    for p in "$BEATRIX_HOME"/lib/python3* "$BEATRIX_HOME"/include/python3* "$BEATRIX_HOME/include/site" \
             "$BEATRIX_HOME/share/man" "$BEATRIX_HOME/share/jupyter" "$BEATRIX_HOME/share/doc"; do
        [[ -e "$p" ]] && rm -rf -- "$p"
    done
    for p in lib include share; do rmdir "$BEATRIX_HOME/$p" 2>/dev/null || true; done
    rm -f -- "$BEATRIX_HOME/pyvenv.cfg" "$BEATRIX_HOME/CACHEDIR.TAG" "$BEATRIX_HOME/.lock"
    done_msg "Removed the old Python environment from $BEATRIX_HOME"
fi

# Other ways Beatrix was installed in the past.
if command -v pipx &>/dev/null && [[ "$(pipx list 2>/dev/null || true)" == *beatrix-cli* ]]; then
    pipx uninstall beatrix-cli >/dev/null 2>&1 && done_msg "Removed the pipx install"
fi
if python3 -m pip show beatrix-cli &>/dev/null; then
    python3 -m pip uninstall -y beatrix-cli >/dev/null 2>&1 && done_msg "Removed the pip install"
fi

# The opt-in sudoers rule (install.sh --with-sudo-rules).
if [[ -f /etc/sudoers.d/beatrix ]]; then
    as_root rm -f /etc/sudoers.d/beatrix && done_msg "Removed /etc/sudoers.d/beatrix"
fi

# Your data — ask; the default keeps it.
if [[ -d "$BEATRIX_HOME" && -n "$(ls -A "$BEATRIX_HOME" 2>/dev/null)" ]]; then
    echo ""
    echo -e "  Your data is still in ${BOLD}$BEATRIX_HOME${RESET}: findings, sessions, config, API keys."
    answer="n"
    if [[ -t 0 ]]; then
        read -rp "  Delete it too? This can't be undone. [y/N] " answer
    fi
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        rm -rf -- "$BEATRIX_HOME"
        echo -e "  ${RED}✓${RESET} Deleted $BEATRIX_HOME"
    else
        echo -e "  ${YELLOW}○${RESET} Kept $BEATRIX_HOME"
    fi
fi

echo ""
echo -e "${GREEN}${BOLD}Beatrix has been uninstalled.${RESET}"
echo -e "${DIM}The external tools (nuclei, nmap, …) were left in place.${RESET}"
echo -e "${DIM}\"You and I have unfinished business.\"${RESET}"
echo ""
