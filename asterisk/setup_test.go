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
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, nil, endpoints); err != nil {
		t.Fatal(err)
	}

	pjsip := readTestFile(t, filepath.Join(root, "pjsip.d", "simson.conf"))
	if strings.Contains(section(pjsip, "[simson-ep-tpl](!)", "[simson-auth-tpl](!)"), "transport=") {
		t.Fatal("SIP phone template should allow the registered contact transport")
	}
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
	if strings.Contains(section(dialplan, "[from-simson-door]", "[from-simson-out]"), "Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},r") {
		t.Fatal("door station bridge should not force local ringback because it suppresses early media/video preview")
	}
	if !strings.Contains(dialplan, "exten => 1101,1,NoOp(Simson direct SIP-video endpoint") {
		t.Fatal("video-capable SIP endpoint direct route missing")
	}
	if strings.Contains(dialplan, "exten => 1025,1,NoOp(Simson direct SIP-video endpoint") {
		t.Fatal("audio-only SIP endpoint unexpectedly got direct video route")
	}
}

func TestStockAsteriskSamplesAreNeutralized(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pjsip.conf"), []byte(`
[1001]
type=endpoint
context=default
disallow=all
allow=opus,ulaw
auth=1001
aors=1001
webrtc=yes

[1001]
type=auth
auth_type=userpass
username=1001
password=1234

[1001]
type=aor
max_contacts=1
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "extensions.conf"), []byte(`
[default]
exten => 1001,1,Answer()
 same => n,Playback(hello-world)
 same => n,Hangup()
`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := writePJSIPConf(root, SetupConfig{SIPDomain: "simson-vps.vipsy.in"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := writeDialplanConf(root, "from-simson-sip", "from-simson-node", "from-simson-out", nil, nil); err != nil {
		t.Fatal(err)
	}

	pjsipBase := readTestFile(t, filepath.Join(root, "pjsip.conf"))
	if strings.Contains(pjsipBase, "[1001]") || strings.Contains(pjsipBase, "password=1234") {
		t.Fatal("stock pjsip sample endpoint was not neutralized")
	}
	if !strings.Contains(pjsipBase, "#include pjsip.d/*.conf") {
		t.Fatal("minimal pjsip base does not include Simson snippets")
	}
	if _, err := os.Stat(filepath.Join(root, "pjsip.conf.simson-sample.bak")); err != nil {
		t.Fatalf("stock pjsip backup missing: %v", err)
	}

	extensionsBase := readTestFile(t, filepath.Join(root, "extensions.conf"))
	if strings.Contains(extensionsBase, "Playback(hello-world)") {
		t.Fatal("stock demo dialplan was not neutralized")
	}
	if !strings.Contains(extensionsBase, "#include extensions.d/*.conf") {
		t.Fatal("minimal extensions base does not include Simson snippets")
	}
	if _, err := os.Stat(filepath.Join(root, "extensions.conf.simson-sample.bak")); err != nil {
		t.Fatalf("stock extensions backup missing: %v", err)
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
