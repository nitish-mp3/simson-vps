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
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, "7009", nil, endpoints); err != nil {
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
	if !strings.Contains(dialplan, "exten => 1101,1,NoOp(Simson direct SIP endpoint") {
		t.Fatal("video-capable SIP endpoint direct route missing")
	}
	if !strings.Contains(dialplan, "exten => 1025,1,NoOp(Simson direct SIP endpoint") {
		t.Fatal("audio-only SIP endpoint should still get a direct extension route")
	}
	if !strings.Contains(dialplan, "Set(JITTERBUFFER(adaptive)=default)") {
		t.Fatal("generated dialplan should enable adaptive jitter buffering on bridge media paths")
	}
	inboundSIP := section(dialplan, "\n[from-simson-sip]\n", "\n[from-simson-node]\n")
	if strings.Contains(inboundSIP, "@7009") {
		t.Fatal("SIP-phone PSTN calls should route through SimsonRoute, not a hardwired default trunk")
	}
	if !strings.Contains(inboundSIP, "UserEvent(SimsonRoute") {
		t.Fatal("SIP-phone PSTN calls must reach SimsonRoute for per-account gateway selection")
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
	if err := writeDialplanConf(root, "from-simson-sip", "from-simson-node", "from-simson-out", "", nil, nil); err != nil {
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

func TestNoAuthGatewayDoesNotSwallowRegisteredPhonesBehindSameNAT(t *testing.T) {
	root := t.TempDir()
	cfg := SetupConfig{
		SIPDomain:               "simson-vps.vipsy.in",
		TrustedGatewayIPs:       []string{"122.176.123.212"},
		NoAuthInboundExtensions: []string{"7009"},
		InContext:               "from-simson-sip",
		NodeContext:             "from-simson-node",
		OutContext:              "from-simson-out",
		DefaultPSTNTrunk:        "7009",
	}
	endpoints := []SIPEndpointDef{
		{ID: "desk", Extension: "0001", Username: "0001", Password: "secret", Enabled: true},
		{ID: "gateway", Extension: "7009", Username: "7009", Password: "secret", RouteTo: "office2", Enabled: true},
		{ID: "new-gateway", Extension: "7010", Username: "7010", Password: "secret", Enabled: true},
	}
	if err := writePJSIPConf(root, cfg, endpoints); err != nil {
		t.Fatal(err)
	}
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, cfg.DefaultPSTNTrunk, cfg.NoAuthInboundExtensions, endpoints); err != nil {
		t.Fatal(err)
	}

	pjsip := readTestFile(t, filepath.Join(root, "pjsip.d", "simson.conf"))
	if !strings.Contains(pjsip, "endpoint_identifier_order=username,anonymous") {
		t.Fatal("no-auth gateway ingress must not use IP identify because phones can share the same public NAT IP")
	}
	if strings.Contains(pjsip, "simson-trusted-gateway-in-identify") || strings.Contains(pjsip, "match=122.176.123.212") {
		t.Fatal("trusted gateway IP identify would swallow desk-phone REGISTERs from the same public NAT")
	}
	if !strings.Contains(pjsip, "[0001](simson-ep-tpl)") || !strings.Contains(pjsip, "username=0001") {
		t.Fatal("leading-zero SIP endpoint was not generated as a normal registered phone")
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	if !strings.Contains(dialplan, "exten => 7009,1,NoOp(Simson anonymous gateway call") {
		t.Fatal("no-auth gateway extension missing from locked-down anonymous dialplan")
	}
	if strings.Contains(section(dialplan, "\n[from-simson-sip]\n", "\n[from-simson-node]\n"), "exten => 7009,1,NoOp(Simson direct SIP endpoint") {
		t.Fatal("gateway/HAOS-routed endpoint must not be generated as a direct phone extension")
	}
	if strings.Contains(section(dialplan, "\n[from-simson-sip]\n", "\n[from-simson-node]\n"), "exten => 7010,1,NoOp(Simson direct SIP endpoint") {
		t.Fatal("reserved 70xx gateway-style endpoint must not be generated as a direct phone extension")
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
