package asterisk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoorStationVideoIsOptInAndDialplanExists(t *testing.T) {
	root := t.TempDir()
	cfg := SetupConfig{
		SIPDomain:   "simson-vps.vipsy.in",
		InContext:   "from-simson-sip",
		NodeContext: "from-simson-node",
		OutContext:  "from-simson-out",
	}
	endpoints := []SIPEndpointDef{
		{ID: "door", Extension: "1101", Username: "door", Password: "secret", VideoEnabled: true, Enabled: true},
		{ID: "desk", Extension: "1025", Username: "desk", Password: "secret", Enabled: true},
	}
	if err := writePJSIPConf(root, cfg, endpoints); err != nil {
		t.Fatal(err)
	}
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, nil); err != nil {
		t.Fatal(err)
	}

	pjsip := readTestFile(t, filepath.Join(root, "pjsip.d", "simson.conf"))
	if !strings.Contains(section(pjsip, "[1101](simson-ep-tpl)", "[1101-auth]"), "allow=h264") {
		t.Fatal("video-capable door endpoint does not opt into H.264")
	}
	if strings.Contains(section(pjsip, "[1025](simson-ep-tpl)", "[1025-auth]"), "allow=h264") {
		t.Fatal("audio-only desk endpoint unexpectedly opts into H.264")
	}
	if strings.Contains(section(pjsip, "[simson-gateway-in-tpl](!)", "[simson-webrtc-ep-tpl](!)"), "allow=h264") {
		t.Fatal("gateway template unexpectedly opts into H.264")
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	if !strings.Contains(dialplan, "[from-simson-door]") || !strings.Contains(dialplan, "Dial(PJSIP/${EXTEN}") {
		t.Fatal("native door station bridge dialplan missing")
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func section(content, start, end string) string {
	startIndex := strings.Index(content, start)
	if startIndex < 0 {
		return ""
	}
	content = content[startIndex:]
	endIndex := strings.Index(content, end)
	if endIndex < 0 {
		return content
	}
	return content[:endIndex]
}
