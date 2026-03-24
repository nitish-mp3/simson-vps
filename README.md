# Simson VPS — Control Plane Server

Signaling-only control plane for the Simson HAOS addon system. Routes commands between Home Assistant instances and Asterisk endpoints over persistent WebSocket connections. **No media flows through this server.**

## Architecture

```
┌──────────────┐       WSS        ┌─────────────────┐       WSS        ┌──────────────┐
│  HAOS Addon  │ ───────────────► │  Simson VPS     │ ◄─────────────── │  HAOS Addon  │
│  (Node A)    │                  │  Control Plane  │                  │  (Node B)    │
│              │                  │                 │                  │              │
│  Asterisk ◄──┤                  │  - Auth         │                  ├──► Asterisk  │
│  (local)     │                  │  - Routing      │                  │    (local)   │
└──────────────┘                  │  - Presence     │                  └──────────────┘
                                  │  - Call Mgmt    │
                                  │  - Audit Logs   │
                                  │  - Admin API    │
                                  └─────────────────┘
                                         │
                                    Caddy (TLS)
                                         │
                                    Internet
```

## Components

| Directory | Purpose |
|-----------|---------|
| `cmd/simson-server/` | Main entry point |
| `protocol/` | Wire protocol — message types, envelope, HMAC signing |
| `config/` | Configuration loading & validation |
| `store/` | SQLite persistence — accounts, nodes, tokens, audit |
| `hub/` | In-memory live session management |
| `calls/` | In-memory call state machine |
| `ratelimit/` | Per-key token bucket rate limiter |
| `logging/` | Structured JSON logger |
| `server/` | WebSocket gateway, auth, routing, call dispatch |
| `admin/` | REST API for management |
| `deploy/` | Caddy, systemd, deploy script |

## Protocol

All messages are JSON envelopes:

```json
{
  "type": "call.request",
  "id": "uuid",
  "ts": "2025-01-15T10:30:00Z",
  "nonce": "hex",
  "signature": "hmac-sha256-hex",
  "payload": { ... }
}
```

### Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `hello` | Node → Server | Authentication handshake |
| `auth.result` | Server → Node | Auth response with server capabilities |
| `heartbeat` | Node → Server | Keep-alive |
| `heartbeat.ack` | Server → Node | Keep-alive response |
| `call.request` | Node → Server | Initiate a call |
| `call.invite` | Server → Node | Forward call to target |
| `call.accept` | Node → Server | Target accepts the call |
| `call.reject` | Node → Server | Target rejects the call |
| `call.end` | Node → Server | Either party hangs up |
| `call.status` | Server → Node | Status update to both parties |
| `error` | Server → Node | Error response |

### Call Flow

```
Caller Node          VPS               Target Node
    │                 │                      │
    ├─ call.request ─►│                      │
    │                 ├── call.invite ──────►│
    │◄─ call.status ──┤  (ringing)           │
    │   (ringing)     │                      │
    │                 │◄── call.accept ──────┤
    │◄─ call.status ──┤                      │
    │   (active)      ├── call.status ──────►│
    │                 │    (active)           │
    │   ... media handled locally ...        │
    │                 │                      │
    ├─ call.end ─────►│                      │
    │                 ├── call.status ──────►│
    │◄─ call.status ──┤    (ended)           │
    │   (ended)       │                      │
```

## Security

- **TLS only** via Caddy (auto certificates)
- **Per-install auth tokens** (64-char hex, `stk_` prefixed)
- **HMAC-SHA256 signatures** with nonce + timestamp (replay prevention)
- **Account isolation** — nodes can only interact within their account
- **Rate limiting** — per-IP at connection, per-node on messages
- **Token revocation** — instant via admin API, disconnects active session
- **Systemd hardening** — `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`
- **Payload size limits** — configurable max message size

## Quick Start

### 1. Build

```bash
# On your development machine (cross-compile for Linux VPS)
cd vps
go mod tidy
GOOS=linux GOARCH=amd64 go build -o bin/simson-server-linux-amd64 ./cmd/simson-server/
```

### 2. Deploy

```bash
# Copy to VPS
scp bin/simson-server-linux-amd64 root@your-vps:/opt/simson/simson-server
scp deploy/deploy.sh root@your-vps:/opt/simson/

# On VPS
ssh root@your-vps
cd /opt/simson
chmod +x deploy.sh
./deploy.sh simson-vps.niti.life
```

### 3. Create Your First Account & Node

```bash
DOMAIN="simson-vps.niti.life"
TOKEN="the-admin-token-from-deploy-output"

# Create account
curl -s -X POST "https://$DOMAIN/admin/accounts" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"acct_001","name":"My Home"}' | jq .

# Create node
curl -s -X POST "https://$DOMAIN/admin/accounts/acct_001/nodes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"node_living_room","label":"Living Room","capabilities":["haos","voice"]}' | jq .
# → Returns install_token — give this to the addon
```

## Admin API Reference

All admin endpoints require `Authorization: Bearer <admin_token>`.

### Health (no auth required)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/health` | Server status, connected nodes, active calls |

### Accounts

| Method | Path | Description |
|--------|------|-------------|
| POST | `/admin/accounts` | Create account |
| GET | `/admin/accounts` | List all accounts |
| GET | `/admin/accounts/{id}` | Get account details |
| PUT | `/admin/accounts/{id}/license` | Update license status |

### Nodes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/admin/accounts/{accountId}/nodes` | Create node (returns install token) |
| GET | `/admin/accounts/{accountId}/nodes` | List nodes with online status |
| GET | `/admin/nodes/{id}` | Get node details |
| PUT | `/admin/nodes/{id}/enable` | Enable node |
| PUT | `/admin/nodes/{id}/disable` | Disable node (disconnects if online) |
| POST | `/admin/nodes/{id}/revoke-token` | Revoke and regenerate token |
| DELETE | `/admin/nodes/{id}` | Delete node |

### Live State

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/sessions` | All connected nodes with metadata |
| GET | `/admin/calls` | All active/recent calls |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/audit?account_id=X&limit=100` | Query audit log |

## Configuration

Config file (`config.json`):

```json
{
  "listen": ":8080",
  "db_path": "/opt/simson/simson.db",
  "log_level": "info",
  "heartbeat_sec": 30,
  "call_timeout_sec": 60,
  "max_nodes_per_account": 10,
  "max_concurrent_calls": 5,
  "rate_limit_per_sec": 20,
  "max_payload_bytes": 65536
}
```

Environment overrides (in `/opt/simson/.env`):

| Variable | Purpose |
|----------|---------|
| `SIMSON_ADMIN_TOKEN` | Admin API bearer token |
| `SIMSON_DB_PATH` | SQLite database path |
| `SIMSON_LISTEN` | Listen address |

## Monitoring

- **Health:** `GET /admin/health`
- **Prometheus metrics:** `GET /metrics` (connected nodes, active calls)
- **Logs:** `journalctl -u simson -f` — structured JSON
- **Audit:** `GET /admin/audit` — all connection/call/auth events

## Limits & Guardrails

| Limit | Default | Purpose |
|-------|---------|---------|
| Max nodes per account | 10 | Licensing |
| Max concurrent calls | 5 | Resource protection |
| Rate limit | 20 req/s per node | Abuse prevention |
| Max payload | 64 KB | Memory protection |
| Heartbeat timeout | 90s (3x interval) | Stale detection |
| Call ring timeout | 60s | Cleanup unanswered calls |
