package config

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

func (ice ICEConfig) Servers(consumer string, now time.Time) []map[string]any {
	servers := []map[string]any{}
	for _, stun := range ice.STUNServers {
		servers = append(servers, map[string]any{"urls": stun})
	}
	if !ice.TURNEnabled || len(ice.TURNURLs) == 0 {
		return servers
	}
	username, password := ice.TURNUsername, ice.TURNSecret
	if ice.TURNAuthSecret != "" {
		identity := sha256.Sum256([]byte(consumer))
		username = fmt.Sprintf("%d:%x", now.Add(time.Hour).Unix(), identity[:8])
		mac := hmac.New(sha1.New, []byte(ice.TURNAuthSecret))
		mac.Write([]byte(username))
		password = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	if username != "" && password != "" {
		servers = append(servers, map[string]any{"urls": ice.TURNURLs, "username": username, "credential": password})
	}
	return servers
}
