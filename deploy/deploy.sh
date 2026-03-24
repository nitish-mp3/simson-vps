#!/usr/bin/env bash
#
# Simson VPS Deploy Script
# Run on a fresh Ubuntu 22.04+ VPS as root.
#
# Usage:
#   deploy.sh <domain> [admin_token] [github_repo]
#
# Examples:
#   ./deploy.sh simson-vps.niti.life
#   ./deploy.sh simson-vps.niti.life my-secret-token https://github.com/wirsy/simson-vps.git
#
set -euo pipefail

DOMAIN="${1:?Usage: deploy.sh <domain> [admin_token] [github_repo]}"
ADMIN_TOKEN="${2:-$(openssl rand -hex 32)}"
GITHUB_REPO="${3:-}"

INSTALL_DIR="/opt/simson"
SERVICE_USER="simson"
GO_VERSION="1.22.5"
GO_ARCH="linux-amd64"

echo "=== Simson Control Plane Deployment ==="
echo "Domain:      $DOMAIN"
echo "Install dir: $INSTALL_DIR"
echo "Go version:  $GO_VERSION"
echo ""

# --- System packages ---
echo "[1/9] Installing system packages..."
apt-get update -qq
apt-get install -y -qq curl sqlite3 git debian-keyring debian-archive-keyring apt-transport-https

# --- Install Go ---
echo "[2/9] Installing Go $GO_VERSION..."
if [ -d /usr/local/go ]; then
    CURRENT_GO=$(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
    if [ "$CURRENT_GO" = "$GO_VERSION" ]; then
        echo "  Go $GO_VERSION already installed."
    else
        echo "  Upgrading from Go $CURRENT_GO to $GO_VERSION..."
        rm -rf /usr/local/go
    fi
fi
if [ ! -d /usr/local/go ]; then
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi
export PATH="/usr/local/go/bin:$PATH"
echo "  $(go version)"

# --- Install Caddy ---
echo "[3/9] Installing Caddy..."
if ! command -v caddy &>/dev/null; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
else
    echo "  Caddy already installed."
fi

# --- Create user ---
echo "[4/9] Creating service user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
else
    echo "  User $SERVICE_USER already exists."
fi

# --- Create directories ---
echo "[5/9] Setting up directories..."
mkdir -p "$INSTALL_DIR"

# --- Get source code ---
echo "[6/9] Getting source code..."
if [ -n "$GITHUB_REPO" ]; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "  Pulling latest from $GITHUB_REPO..."
        cd "$INSTALL_DIR"
        git pull --ff-only
    else
        echo "  Cloning $GITHUB_REPO..."
        # Clone into temp then move (in case INSTALL_DIR has config files)
        TEMP_CLONE="/tmp/simson-clone-$$"
        git clone "$GITHUB_REPO" "$TEMP_CLONE"
        # Preserve existing config and data files
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
        echo "  ERROR: No source found at $INSTALL_DIR and no GitHub repo specified."
        echo "  Either provide a GitHub repo URL as the 3rd argument, or copy source to $INSTALL_DIR."
        exit 1
    fi
    echo "  Using existing source at $INSTALL_DIR."
fi

# --- Build ---
echo "[7/9] Building simson-server..."
cd "$INSTALL_DIR"
go build -o "$INSTALL_DIR/simson-server" ./cmd/simson-server/
echo "  Binary built: $INSTALL_DIR/simson-server"
echo "  $("$INSTALL_DIR/simson-server" --version 2>/dev/null || echo 'Build OK')"

# --- Config ---
echo "[8/9] Writing configuration..."
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
echo "[9/9] Configuring services..."
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    handle /ws {
        reverse_proxy localhost:8080
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
systemctl restart caddy

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
