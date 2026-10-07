package config

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTURNRESTCredentialsExpireAndDoNotExposeMasterSecret(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ice := ICEConfig{TURNEnabled: true, TURNURLs: []string{"turn:relay.example:3478"}, TURNAuthSecret: "master-test-secret"}
	entry := ice.Servers("private-node", now)[0]
	username := entry["username"].(string)
	expires, _ := strconv.ParseInt(strings.Split(username, ":")[0], 10, 64)
	if expires != now.Add(time.Hour).Unix() || strings.Contains(username, "private-node") {
		t.Fatal("credential lifetime/identity is unsafe")
	}
	mac := hmac.New(sha1.New, []byte(ice.TURNAuthSecret))
	mac.Write([]byte(username))
	if entry["credential"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || entry["credential"] == ice.TURNAuthSecret {
		t.Fatal("invalid or exposed TURN REST secret")
	}
	if ice.Servers("other-node", now)[0]["username"] == username {
		t.Fatal("credentials were not site scoped")
	}
	ice.TURNEnabled = false
	if len(ice.Servers("node", now)) != 0 {
		t.Fatal("disabled TURN credentials exposed")
	}
}
