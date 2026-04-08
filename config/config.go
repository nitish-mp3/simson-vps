package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ICEConfig holds WebRTC ICE server settings published to clients via the API.
type ICEConfig struct {
	STUNServers []string `json:"stun_servers"` // public STUN URIs (no auth)
	TURNEnabled bool     `json:"turn_enabled"`
	TURNURLs    []string `json:"turn_urls"`     // e.g. ["turn:vps.example.com:3478"]
	TURNUsername string  `json:"turn_username"`
	TURNSecret  string   `json:"turn_secret"`  // static TURN credential (rotate periodically)
}

// SIPWebRTCConfig holds the shared SIP-over-WebSocket credentials used by browser clients.
// A single "webrtc-pool" endpoint in Asterisk accepts any connection with these credentials.
type SIPWebRTCConfig struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"` // SIP auth username (e.g. "webrtc-pool")
	Password string `json:"password"` // SIP auth password
	WSPath   string `json:"ws_path"`  // WebSocket path Caddy exposes (default: /sip/ws)
}

// AsteriskConfig holds settings for the optional central VPS Asterisk integration.
type AsteriskConfig struct {
	Enabled       bool            `json:"enabled"`          // false → AMI disabled
	Host          string          `json:"host"`             // AMI host (default: 127.0.0.1)
	Port          int             `json:"port"`             // AMI port  (default: 5038)
	User          string          `json:"user"`             // AMI user name
	Secret        string          `json:"secret"`           // AMI password
	AutoConfigure bool            `json:"auto_configure"`   // write pjsip/manager/dialplan conf on start
	SIPDomain     string          `json:"sip_domain"`       // hostname phones register to
	ExternalIP    string          `json:"external_ip"`      // VPS public IP for RTP NAT (auto-detected if empty)
	InContext      string         `json:"in_context"`       // incoming-SIP dialplan context
	NodeContext   string          `json:"node_context"`     // node-callback dialplan context
	SIPWebRTC     SIPWebRTCConfig `json:"sip_webrtc"`       // shared browser SIP endpoint
}

// Config holds all server configuration.
type Config struct {
	Listen             string         `json:"listen"`               // e.g. ":8443"
	DBPath             string         `json:"db_path"`              // SQLite file
	LogLevel           string         `json:"log_level"`            // "debug","info","warn","error"
	HeartbeatSec       int            `json:"heartbeat_sec"`        // expected heartbeat interval
	HeartbeatTimeout   time.Duration  `json:"-"`                    // computed
	CallTimeoutSec     int            `json:"call_timeout_sec"`     // ring timeout
	MaxNodesPerAcct    int            `json:"max_nodes_per_account"`
	MaxConcurrentCalls int            `json:"max_concurrent_calls"`
	RateLimitPerSec    int            `json:"rate_limit_per_sec"`
	MaxPayloadBytes    int            `json:"max_payload_bytes"`
	AdminToken         string         `json:"admin_token"`          // bearer token for admin API
	TLSCert            string         `json:"tls_cert,omitempty"`
	TLSKey             string         `json:"tls_key,omitempty"`
	Asterisk           AsteriskConfig `json:"asterisk"`             // optional central PBX
	ICE                ICEConfig      `json:"ice"`                  // WebRTC ICE/TURN settings
}

// DefaultConfig returns production defaults.
func DefaultConfig() *Config {
	return &Config{
		Listen:             ":8443",
		DBPath:             "./simson.db",
		LogLevel:           "info",
		HeartbeatSec:       30,
		CallTimeoutSec:     60,
		MaxNodesPerAcct:    10,
		MaxConcurrentCalls: 5,
		RateLimitPerSec:    20,
		MaxPayloadBytes:    65536,
		AdminToken:         "",
		Asterisk: AsteriskConfig{
			Enabled:     false,
			Host:        "127.0.0.1",
			Port:        5038,
			InContext:   "from-simson-sip",
			NodeContext: "from-simson-node",
			SIPWebRTC: SIPWebRTCConfig{
				Enabled:  false,
				Username: "webrtc-pool",
				WSPath:   "/sip/ws",
			},
		},
		ICE: ICEConfig{
			STUNServers: []string{
				"stun:stun.l.google.com:19302",
				"stun:stun1.l.google.com:19302",
			},
			TURNEnabled: false,
		},
	}
}

// Load reads config from a JSON file. Missing fields keep their defaults.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.finalise()
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.finalise()
	return cfg, nil
}

func (c *Config) finalise() {
	c.HeartbeatTimeout = time.Duration(c.HeartbeatSec*3) * time.Second
}

// Validate performs basic sanity checks.
func (c *Config) Validate() error {
	if c.AdminToken == "" {
		return fmt.Errorf("admin_token must be set")
	}
	if c.HeartbeatSec < 5 {
		return fmt.Errorf("heartbeat_sec must be >= 5")
	}
	if c.MaxPayloadBytes < 1024 {
		return fmt.Errorf("max_payload_bytes must be >= 1024")
	}
	return nil
}
