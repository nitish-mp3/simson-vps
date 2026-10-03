package asterisk

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayRTPTimeoutIsScoped(t *testing.T) {
	root := t.TempDir()
	cfg := SetupConfig{GatewayRTPTimeouts: map[string]int{"1701": 120}}
	endpoints := []SIPEndpointDef{
		{Extension: "1701", Username: "1701", Password: "secret", Enabled: true},
		{Extension: "1027", Username: "1027", Password: "secret", Enabled: true},
	}
	if err := writePJSIPConf(root, cfg, endpoints); err != nil {
		t.Fatal(err)
	}
	data := readTestFile(t, filepath.Join(root, "pjsip.d", "simson.conf"))
	if !strings.Contains(section(data, "[1701](simson-ep-tpl)", "[1701-auth]"), "rtp_timeout=120") {
		t.Fatal("gateway did not receive its bounded media watchdog")
	}
	if strings.Contains(section(data, "[1027](simson-ep-tpl)", "[1027-auth]"), "rtp_timeout=") {
		t.Fatal("unrelated handset settings changed")
	}
	cfg.GatewayRTPTimeouts["1701"] = 1
	if err := writePJSIPConf(root, cfg, endpoints); err == nil {
		t.Fatal("unsafe RTP timeout accepted")
	}
}
