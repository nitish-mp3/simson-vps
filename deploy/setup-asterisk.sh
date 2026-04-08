#!/usr/bin/env bash
# ------------------------------------------------------------
# setup-asterisk.sh
# Install Asterisk 20 LTS on Ubuntu/Debian and prepare the
# directory layout expected by Simson VPS auto-configure.
#
# Run as root (or with sudo) on the VPS before starting
# the simson-server binary for the first time.
# ------------------------------------------------------------
set -euo pipefail

ASTERISK_VERSION="${ASTERISK_VERSION:-20}"

info()  { printf '\e[32m[+]\e[0m %s\n' "$*"; }
warn()  { printf '\e[33m[!]\e[0m %s\n' "$*"; }
die()   { printf '\e[31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run this script as root (sudo $0)"

info "Updating package index…"
apt-get update -qq

info "Installing Asterisk ${ASTERISK_VERSION} LTS…"
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    asterisk \
    asterisk-modules \
    asterisk-config \
    asterisk-core-sounds-en

info "Enabling and starting Asterisk service…"
systemctl enable asterisk
systemctl start  asterisk

# ── Prepare include-based config layout ─────────────────────
# Simson auto-configure writes into these *.conf.d/ directories
# and adds a single #include line to the parent conf.

info "Creating config.d include directories…"
install -d -m 0750 /etc/asterisk/pjsip.conf.d
install -d -m 0750 /etc/asterisk/manager.conf.d
install -d -m 0750 /etc/asterisk/extensions.conf.d

# ── Ensure pjsip.conf can load PJSIP module ─────────────────
PJSIP_CONF=/etc/asterisk/pjsip.conf
if ! grep -q '#include' "$PJSIP_CONF" 2>/dev/null; then
    info "pjsip.conf: no #include yet (simson will add one at startup)"
fi

# ── Ensure manager.conf has networking enabled ───────────────
MANAGER_CONF=/etc/asterisk/manager.conf
if ! grep -qE '^\s*enabled\s*=\s*yes' "$MANAGER_CONF" 2>/dev/null; then
    warn "manager.conf: AMI may not be enabled. Simson will write its own block."
    warn "If AMI is globally disabled in manager.conf, enable it manually:"
    warn "  [general]"
    warn "  enabled = yes"
fi

# ── Create minimal manager.conf if it is missing ────────────
if [[ ! -f "$MANAGER_CONF" ]]; then
    info "Creating minimal manager.conf…"
    cat > "$MANAGER_CONF" << 'EOF'
[general]
enabled = yes
port = 5038
bindaddr = 127.0.0.1
EOF
fi

# ── Ownership / permissions ──────────────────────────────────
chown -R asterisk:asterisk /etc/asterisk/pjsip.conf.d \
                             /etc/asterisk/manager.conf.d \
                             /etc/asterisk/extensions.conf.d

# ── Summary ─────────────────────────────────────────────────
ASTERISK_FULL=$(asterisk -V 2>/dev/null || echo "unknown")
info "────────────────────────────────────────────────────────"
info "Asterisk ready: $ASTERISK_FULL"
info ""
info "Next steps:"
info "  1. Set 'asterisk.enabled = true' in your simson config."
info "  2. Set 'asterisk.auto_configure = true' to let simson"
info "     write pjsip/manager/dialplan confs automatically."
info "  3. Set 'asterisk.sip_domain' to your VPS public IP or"
info "     FQDN (e.g. sip.example.com)."
info "  4. Start simson-server — it will configure Asterisk and"
info "     maintain a live AMI connection."
info "────────────────────────────────────────────────────────"
