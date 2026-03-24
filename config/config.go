package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds all server configuration.
type Config struct {
	Listen          string        `json:"listen"`            // e.g. ":8443"
	DBPath          string        `json:"db_path"`           // SQLite file
	LogLevel        string        `json:"log_level"`         // "debug","info","warn","error"
	HeartbeatSec    int           `json:"heartbeat_sec"`     // expected heartbeat interval
	HeartbeatTimeout time.Duration `json:"-"`                // computed
	CallTimeoutSec  int           `json:"call_timeout_sec"`  // ring timeout
	MaxNodesPerAcct int           `json:"max_nodes_per_account"`
	MaxConcurrentCalls int        `json:"max_concurrent_calls"`
	RateLimitPerSec int           `json:"rate_limit_per_sec"`
	MaxPayloadBytes int           `json:"max_payload_bytes"`
	AdminToken      string        `json:"admin_token"`       // bearer token for admin API
	TLSCert         string        `json:"tls_cert,omitempty"`
	TLSKey          string        `json:"tls_key,omitempty"`
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
