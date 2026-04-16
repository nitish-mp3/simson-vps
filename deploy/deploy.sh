#!/usr/bin/env bash
#
# Simson VPS Deploy Script
# Run on a fresh Ubuntu 20.04+ VPS as root.
#
# Usage:
#   deploy.sh <domain> [admin_token] [github_repo] [release_tag]
#
# Examples:
#   # Use a pre-built binary from GitHub Releases (fast — seconds, not minutes):
#   ./deploy.sh simson-vps.niti.life "" https://github.com/nitish-mp3/simson-vps.git v1.0.0
#
#   # Auto-detect latest release:
#   ./deploy.sh simson-vps.niti.life "" https://github.com/nitish-mp3/simson-vps.git
#
#   # Build from source (slow — 10-20 min due to sqlite compilation):
#   SIMSON_BUILD_FROM_SOURCE=1 ./deploy.sh simson-vps.niti.life "" https://github.com/nitish-mp3/simson-vps.git
#
set -euo pipefail

DOMAIN="${1:?Usage: deploy.sh <domain> [admin_token] [github_repo] [release_tag]}"
ADMIN_TOKEN="${2:-$(openssl rand -hex 32)}"
GITHUB_REPO="${3:-}"
RELEASE_TAG="${4:-latest}"
BUILD_FROM_SOURCE="${SIMSON_BUILD_FROM_SOURCE:-0}"

INSTALL_DIR="/opt/simson"
SERVICE_USER="simson"
GO_VERSION="1.22.5"
GO_ARCH="linux-amd64"
BINARY_NAME="simson-server-linux-amd64"

echo "=== Simson Control Plane Deployment ==="
echo "Domain:      $DOMAIN"
echo "Install dir: $INSTALL_DIR"
echo ""

# Extract GitHub owner/repo from URL (handles https and git@ formats)
_github_slug() {
    local url="$1"
    # https://github.com/owner/repo.git or https://github.com/owner/repo
    url="${url%.git}"
    echo "${url#*github.com/}"
}

# Try to download a pre-built binary from GitHub Releases.
# Returns 0 on success, 1 on failure.
_try_download_release() {
    if [ -z "$GITHUB_REPO" ]; then
        return 1
    fi
    local slug
    slug=$(_github_slug "$GITHUB_REPO")
    local api_url release_url asset_url

    if [ "$RELEASE_TAG" = "latest" ]; then
        api_url="https://api.github.com/repos/${slug}/releases/latest"
    else
        api_url="https://api.github.com/repos/${slug}/releases/tags/${RELEASE_TAG}"
    fi

    echo "  Checking GitHub Releases at ${api_url} ..."
    # Extract the browser_download_url for our binary asset
    asset_url=$(curl -fsSL "$api_url" 2>/dev/null \
        | grep -o "\"browser_download_url\": *\"[^\"]*${BINARY_NAME}[^\"]*\"" \
        | grep -o 'https://[^"]*' | head -1 || true)

    if [ -z "$asset_url" ]; then
        echo "  No pre-built release binary found."
        return 1
    fi

    echo "  Downloading pre-built binary: $asset_url"
    curl -fsSL "$asset_url" -o "$INSTALL_DIR/simson-server"
    chmod +x "$INSTALL_DIR/simson-server"
    echo "  Binary downloaded successfully (fast path)."
    return 0
}

# --- System packages ---
echo "[1/8] Installing system packages..."
apt-get update -qq
apt-get install -y -qq curl sqlite3 git ufw

# Open ports required by Caddy.
# SSH (22) is explicitly allowed first so you can't lock yourself out.

# --- iptables (Oracle Cloud / raw iptables images) ---
# Oracle Cloud Ubuntu images have a default REJECT-all iptables rule that blocks
# inbound traffic on everything except SSH, even when UFW and the cloud Security
# List both allow it.  We insert ACCEPT rules for 80/443 before any REJECT/DROP.
_fix_iptables() {
    if ! command -v iptables &>/dev/null; then return; fi

    # Find the first REJECT or DROP rule number in the INPUT chain.
    local reject_line
    reject_line=$(iptables -L INPUT --line-numbers -n 2>/dev/null \
        | grep -iE 'REJECT|DROP' | head -1 | awk '{print $1}')

    if [ -z "$reject_line" ]; then
        echo "  iptables: no REJECT/DROP rule found — nothing to patch."
        return
    fi

    echo "  iptables: REJECT/DROP rule found at line $reject_line — inserting ACCEPT rules before it."
    for port in 80 443; do
        if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT "$reject_line" -p tcp --dport "$port" -j ACCEPT
            reject_line=$((reject_line + 1))
            echo "    Allowed TCP $port"
        fi
    done
    if ! iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null; then
        iptables -I INPUT "$reject_line" -p udp --dport 443 -j ACCEPT
        echo "    Allowed UDP 443 (HTTP/3)"
    fi

    # Persist rules across reboots.
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    echo "  iptables rules saved."
}
echo "  Fixing iptables (Oracle Cloud / raw iptables)..."
_fix_iptables

# --- UFW (general-purpose) ---
echo "  Configuring UFW firewall..."
ufw allow 22/tcp  comment 'SSH'             2>/dev/null || true
ufw allow 80/tcp  comment 'HTTP (ACME TLS)' 2>/dev/null || true
ufw allow 443/tcp comment 'HTTPS'           2>/dev/null || true
ufw allow 443/udp comment 'HTTP/3'          2>/dev/null || true
if ! ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw --force enable
    echo "  UFW enabled with ports 22/80/443 open."
else
    ufw reload 2>/dev/null || true
    echo "  UFW already active — rules updated."
fi
echo "  NOTE: Also open TCP 80 + 443 in your cloud provider's firewall panel (Security List, Security Group, etc.)."

# --- Install Caddy ---
echo "[2/8] Installing Caddy..."
if ! command -v caddy &>/dev/null; then
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    # Caddy's postinst starts the service; it may fail if port 80 is busy — that's OK.
    apt-get install -y -qq caddy || true
    # Stop the default instance; we'll configure and restart it at the end.
    systemctl stop caddy 2>/dev/null || true
else
    echo "  Caddy already installed."
fi

# --- Create user ---
echo "[3/8] Creating service user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
else
    echo "  User $SERVICE_USER already exists."
fi

# --- Create directories ---
echo "[4/8] Setting up directories..."
mkdir -p "$INSTALL_DIR"

# --- Get source code (needed for config even if we download a binary) ---
echo "[5/8] Getting source code..."
if [ -n "$GITHUB_REPO" ]; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "  Pulling latest..."
        cd "$INSTALL_DIR"
        git pull --ff-only
    else
        echo "  Cloning $GITHUB_REPO..."
        TEMP_CLONE="/tmp/simson-clone-$$"
        git clone "$GITHUB_REPO" "$TEMP_CLONE"
        # Preserve existing config/data
        for f in config.json .env simson.db; do
            if [ -f "$INSTALL_DIR/$f" ]; then
                cp "$INSTALL_DIR/$f" "$TEMP_CLONE/$f"
            fi
        done
        rm -rf "$INSTALL_DIR"
        mv "$TEMP_CLONE" "$INSTALL_DIR"
    fi
else
    if [ ! -f "$INSTALL_DIR/go.mod" ]; then
        echo "  ERROR: No source and no GitHub repo URL specified."
        exit 1
    fi
    echo "  Using existing source at $INSTALL_DIR."
fi

# --- Binary: try release download first, build from source as fallback ---
echo "[6/8] Getting simson-server binary..."
if [ "$BUILD_FROM_SOURCE" != "1" ] && [ -x "$INSTALL_DIR/simson-server" ]; then
    echo "  simson-server already present, skipping download/build."
    echo "  (Set SIMSON_BUILD_FROM_SOURCE=1 to force rebuild.)"
elif [ "$BUILD_FROM_SOURCE" = "1" ]; then
    echo "  SIMSON_BUILD_FROM_SOURCE=1 set — building from source."
    echo "  WARNING: modernc.org/sqlite compilation takes 10-20 minutes on first build."
    _install_go() {
        if [ -d /usr/local/go ]; then
            CURRENT=$(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
            if [ "$CURRENT" != "$GO_VERSION" ]; then
                echo "  Upgrading Go from $CURRENT to $GO_VERSION..."
                rm -rf /usr/local/go
            else
                echo "  Go $GO_VERSION already installed."
                return
            fi
        fi
        echo "  Installing Go $GO_VERSION..."
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    }
    _install_go
    export PATH="/usr/local/go/bin:$PATH"
    echo "  $(go version)"
    cd "$INSTALL_DIR"
    go build -o "$INSTALL_DIR/simson-server" ./cmd/simson-server/
    echo "  Binary built from source."
elif _try_download_release; then
    : # success — binary already placed by _try_download_release
elif [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    echo "  Found pre-built binary in repo directory, using it."
    cp "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/simson-server"
    chmod +x "$INSTALL_DIR/simson-server"
else
    echo "  No release binary available. Building from source..."
    echo "  WARNING: modernc.org/sqlite compilation takes 10-20 minutes on first build."
    # Install Go if needed
    if [ ! -d /usr/local/go ] || [ "$(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}' | sed 's/go//')" != "$GO_VERSION" ]; then
        echo "  Installing Go $GO_VERSION..."
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    fi
    export PATH="/usr/local/go/bin:$PATH"
    cd "$INSTALL_DIR"
    go build -o "$INSTALL_DIR/simson-server" ./cmd/simson-server/
    echo "  Binary built from source."
fi
echo "  Binary ready: $INSTALL_DIR/simson-server"

# --- Config ---
echo "[7/8] Writing configuration..."
if [ ! -f "$INSTALL_DIR/config.json" ]; then
    cat > "$INSTALL_DIR/config.json" <<EOF
{
  "listen": ":8080",
  "db_path": "$INSTALL_DIR/simson.db",
  "log_level": "info",
  "heartbeat_sec": 30,
  "call_timeout_sec": 60,
  "max_nodes_per_account": 10,
  "max_concurrent_calls": 5,
  "rate_limit_per_sec": 20,
  "max_payload_bytes": 65536
}
EOF
    echo "  Created config.json."
else
    echo "  config.json already exists, keeping it."
fi

cat > "$INSTALL_DIR/.env" <<EOF
SIMSON_ADMIN_TOKEN=$ADMIN_TOKEN
SIMSON_DB_PATH=$INSTALL_DIR/simson.db
SIMSON_LISTEN=:8080
EOF
chmod 600 "$INSTALL_DIR/.env"
echo "  Created .env."

# --- Caddy ---
echo "[8/8] Configuring services..."
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    handle /ws {
        reverse_proxy localhost:8080
    }
    handle /sip/ws* {
        reverse_proxy localhost:8088
    }
    handle /admin/* {
        reverse_proxy localhost:8080
    }
    handle /metrics {
        reverse_proxy localhost:8080
    }
    handle {
        respond "Not found" 404
    }
}
EOF

# --- Systemd ---
cat > /etc/systemd/system/simson.service <<'EOF'
[Unit]
Description=Simson Control Plane Server
After=network.target

[Service]
Type=simple
User=simson
Group=simson
WorkingDirectory=/opt/simson
ExecStart=/opt/simson/simson-server /opt/simson/config.json
Restart=always
RestartSec=5
LimitNOFILE=65536
EnvironmentFile=/opt/simson/.env
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/simson
PrivateTmp=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=simson

[Install]
WantedBy=multi-user.target
EOF

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
systemctl daemon-reload
systemctl enable simson
systemctl restart simson

# Start/reload Caddy with the new Caddyfile.
# First, stop anything hogging port 80 (apache2, nginx, etc.)
for svc in apache2 nginx lighttpd; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "  Stopping $svc (it uses port 80, Caddy needs it)..."
        systemctl stop "$svc"
        systemctl disable "$svc" 2>/dev/null || true
    fi
done

if systemctl is-active --quiet caddy; then
    systemctl reload caddy
else
    systemctl start caddy || {
        echo "  WARNING: Caddy failed to start. Something is still using port 80."
        echo "  Run: ss -tlnp | grep ':80' to find it, then stop it."
        echo "  Then: systemctl start caddy"
    }
fi

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Admin token: $ADMIN_TOKEN"
echo "Save this token securely — it is not recoverable."
echo ""
echo "Endpoints:"
echo "  WSS:     wss://$DOMAIN/ws"
echo "  Admin:   https://$DOMAIN/admin/"
echo "  Health:  https://$DOMAIN/admin/health"
echo "  Metrics: https://$DOMAIN/metrics (requires Bearer token)"
echo ""
echo "Quick-start:"
echo "  # Create an account"
echo "  curl -X POST https://$DOMAIN/admin/accounts \\"
echo "    -H 'Authorization: Bearer $ADMIN_TOKEN' \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"id\":\"acct_001\",\"name\":\"My Company\"}'"
echo ""
echo "  # Create a node"
echo "  curl -X POST https://$DOMAIN/admin/accounts/acct_001/nodes \\"
echo "    -H 'Authorization: Bearer $ADMIN_TOKEN' \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"id\":\"node_living_room\",\"label\":\"Living Room\",\"capabilities\":[\"haos\",\"voice\"]}'"
echo ""
echo "Logs:"
echo "  journalctl -u simson -f"
