#!/usr/bin/env bash
# install.sh — install or remove the guacd TLS compatibility shim
#
# Usage:
#   sudo bash install.sh            # install
#   sudo bash install.sh uninstall  # remove

set -euo pipefail

SO_PATH="/usr/local/lib/tls12_cap.so"
OVERRIDE_DIR="/etc/systemd/system/guacd.service.d"
OVERRIDE_FILE="${OVERRIDE_DIR}/tls-compat.conf"
CONF_DIR="/etc/guacamole"
CONF_FILE="${CONF_DIR}/tls-compat-hosts.conf"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root (sudo $0 $*)"

# ════════════════════════════════════════════════════════════════════════════
# UNINSTALL
# ════════════════════════════════════════════════════════════════════════════
if [[ "${1:-}" == "uninstall" ]]; then
    info "Removing guacd TLS compatibility shim..."

    changed=0

    if [[ -f "$OVERRIDE_FILE" ]]; then
        rm -f "$OVERRIDE_FILE"
        rmdir --ignore-fail-on-non-empty "$OVERRIDE_DIR" 2>/dev/null || true
        info "Removed systemd override: $OVERRIDE_FILE"
        changed=1
    else
        warn "Systemd override not found (already removed?)"
    fi

    if [[ -f "$SO_PATH" ]]; then
        rm -f "$SO_PATH"
        info "Removed shared library: $SO_PATH"
        changed=1
    else
        warn "Shared library not found (already removed?)"
    fi

    if [[ $changed -eq 1 ]]; then
        systemctl daemon-reload
        if systemctl is-active --quiet guacd 2>/dev/null; then
            systemctl restart guacd
            info "guacd restarted (TLS shim removed)."
        else
            warn "guacd is not running; skipping restart."
        fi
    fi

    info "Uninstall complete."
    info "Note: $CONF_FILE was not removed. Delete it manually if no longer needed."
    exit 0
fi

# ════════════════════════════════════════════════════════════════════════════
# INSTALL
# ════════════════════════════════════════════════════════════════════════════
info "Installing guacd TLS compatibility shim..."

# ── dependency check ──────────────────────────────────────────────────────
missing=()
command -v gcc  &>/dev/null || missing+=(gcc)
command -v make &>/dev/null || missing+=(make)
if ! { dpkg -s libssl-dev &>/dev/null 2>&1 || \
       rpm -q openssl-devel &>/dev/null 2>&1 || \
       [[ -f /usr/include/openssl/ssl.h ]]; }; then
    missing+=(libssl-dev)
fi

if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing dependencies: ${missing[*]}"
    warn "On Debian/Ubuntu:  apt-get install -y gcc make libssl-dev"
    warn "On RHEL/Rocky:     dnf install -y gcc make openssl-devel"
    error "Install the above packages and re-run this script."
fi

# ── build ─────────────────────────────────────────────────────────────────
info "Building shim..."
make -C "$SCRIPT_DIR" clean all
[[ -s "${SCRIPT_DIR}/tls12_cap.so" ]] \
    || error "Build produced an empty or missing library."
info "Built: tls12_cap.so ($(du -h "${SCRIPT_DIR}/tls12_cap.so" | cut -f1))"

# ── verify versioned symbol ───────────────────────────────────────────────
for sym in SSL_set_bio SSL_set_fd; do
    nm -D "${SCRIPT_DIR}/tls12_cap.so" | grep -q "${sym}@@OPENSSL_3.0.0" \
        || error "Versioned symbol ${sym}@@OPENSSL_3.0.0 missing — build problem."
done
info "Versioned symbol verified."

# ── install library ───────────────────────────────────────────────────────
install -Dm 755 "${SCRIPT_DIR}/tls12_cap.so" "$SO_PATH"
info "Installed: $SO_PATH"

# ── host config file ──────────────────────────────────────────────────────
mkdir -p "$CONF_DIR"
if [[ ! -f "$CONF_FILE" ]]; then
    cat > "$CONF_FILE" << 'EOF'
# tls-compat-hosts.conf
# List legacy RDP hosts that require the TLS 1.2 compatibility shim.
# One entry per line — single IP address or CIDR notation. Examples:
#
#   192.168.10.50
#   10.0.5.0/24
#   2001:db8::1
#   fd00::/8
#
# See README.md for guidance on which hosts qualify as legacy hosts.
EOF
    info "Created host config: $CONF_FILE"
    warn "Add your legacy RDP host IPs/CIDRs to $CONF_FILE before connecting."
else
    info "Host config already exists: $CONF_FILE (not overwritten)"
fi

# ── systemd override ──────────────────────────────────────────────────────
mkdir -p "$OVERRIDE_DIR"
cat > "$OVERRIDE_FILE" << EOF
[Service]
Environment="LD_PRELOAD=${SO_PATH}"
EOF
info "Systemd override written: $OVERRIDE_FILE"

# ── reload & restart ──────────────────────────────────────────────────────
systemctl daemon-reload

if systemctl is-active --quiet guacd 2>/dev/null; then
    systemctl restart guacd
    info "guacd restarted with TLS shim active."
else
    warn "guacd is not currently running."
    warn "Start it with:  systemctl start guacd"
fi

echo
echo -e "${GREEN}Installation complete.${NC}"
echo "  Library : $SO_PATH"
echo "  Override: $OVERRIDE_FILE"
echo "  Hosts   : $CONF_FILE"
echo
echo "Edit $CONF_FILE to list the legacy RDP hosts you need to reach."
echo "See README.md for supported host types and config format."
echo
echo "Verify the shim is loaded after guacd starts:"
echo "  grep tls12_cap /proc/\$(pgrep guacd)/maps"
echo
echo "Remove the shim:"
echo "  sudo bash $0 uninstall"
