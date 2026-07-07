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
		{ID: "desk", Extension: "1025", Username: "desk", Password: "secret", AutoAnswer: true, Enabled: true},
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
	if !strings.Contains(dialplan, "exten => 1025,1,NoOp(Simson dial auto-answer SIP endpoint") ||
		!strings.Contains(dialplan, "Answer-Mode)=Auto") {
		t.Fatal("auto-answer SIP endpoint dialplan headers missing")
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

func TestGatewayWelcomeAnnouncementIsScopedToGatewayIngress(t *testing.T) {
	root := t.TempDir()
	cfg := SetupConfig{
		SIPDomain:               "simson-vps.vipsy.in",
		InContext:               "from-simson-sip",
		NodeContext:             "from-simson-node",
		OutContext:              "from-simson-out",
		NoAuthInboundExtensions: []string{"7013"},
	}
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, "7009", cfg.NoAuthInboundExtensions, nil); err != nil {
		t.Fatal(err)
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	announcement := section(dialplan, "[simson-gateway-announcement]", "[simson-auto-answer]")
	for _, want := range []string{
		"Answer()",
		"STAT(e,/usr/share/asterisk/sounds/custom/simson-architech-welcome.wav)",
		"Playback(queue-thankyou&one-moment-please&pls-hold-while-try)",
		"Playback(custom/simson-architech-welcome)",
		"Return()",
	} {
		if !strings.Contains(announcement, want) {
			t.Fatalf("gateway welcome announcement missing %q:\n%s", want, announcement)
		}
	}

	inboundSIP := section(dialplan, "\n[from-simson-sip]\n", "\n[from-simson-node]\n")
	if !strings.Contains(inboundSIP, `GosubIf($["${CHANNEL(pjsip,endpoint)}" = "${EXTEN}"]?simson-gateway-announcement,s,1)`) {
		t.Fatalf("authenticated gateway ingress should conditionally play the announcement:\n%s", inboundSIP)
	}

	anonymous := section(dialplan, "\n[from-simson-anonymous]\n", "\n[from-simson-sip-outbound]")
	if !strings.Contains(anonymous, "exten => 7013,1,NoOp(Simson anonymous gateway call") ||
		!strings.Contains(anonymous, "Gosub(simson-gateway-announcement,s,1)") {
		t.Fatalf("no-auth gateway ingress should play the announcement before routing:\n%s", anonymous)
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

func TestRouteSpecificAutoAnswerHeadersAreConditional(t *testing.T) {
	root := t.TempDir()
	cfg := SetupConfig{
		SIPDomain:   "simson-vps.vipsy.in",
		InContext:   "from-simson-sip",
		NodeContext: "from-simson-node",
		OutContext:  "from-simson-out",
	}
	endpoints := []SIPEndpointDef{
		{ID: "caller", Extension: "1025", Username: "1025", Password: "secret", Enabled: true},
		{ID: "target", Extension: "1603", Username: "1603", Password: "secret", AutoAnswer: true, AutoAnswerCallers: "1025", AutoSpeaker: true, Enabled: true},
	}
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, "7009", nil, endpoints); err != nil {
		t.Fatal(err)
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	target := section(dialplan, "exten => 1603,1,NoOp(Simson direct SIP endpoint", "exten => _+X.")
	if !strings.Contains(target, `"${SIMSON_CALLER_ENDPOINT}" = "1025"`) {
		t.Fatal("direct SIP route should condition auto-answer on the caller endpoint")
	}
	if !strings.Contains(target, "SIMSON_AUTO_ANSWER_MODE=speaker") {
		t.Fatal("route-specific auto-speaker should set speaker mode only after caller match")
	}
	if !strings.Contains(target, "b(simson-auto-answer^s^1(${SIMSON_AUTO_ANSWER_MODE}))") {
		t.Fatal("direct SIP route should inject auto-answer headers with a called-channel pre-dial handler")
	}
	if !strings.Contains(target, "Goto(simson-auto-answer-done)") {
		t.Fatal("route-specific auto-answer must fall through to a normal dial when caller does not match")
	}
	if !strings.Contains(dialplan, "[simson-auto-answer]") ||
		!strings.Contains(dialplan, `\;info=intercom`) ||
		!strings.Contains(dialplan, "P-Auto-Answer)=intercom") ||
		!strings.Contains(dialplan, "Answer-After)=0") ||
		!strings.Contains(dialplan, "Alert-Info)=answer-after=0") {
		t.Fatal("auto-answer pre-dial handler with compatibility speaker hint headers missing")
	}
	autoHandler := section(dialplan, "[simson-auto-answer]", "[simson-extension-predial]")
	jumpIdx := strings.Index(autoHandler, `GotoIf($["${ARG1}" = "speaker"]?speaker)`)
	normalIdx := strings.Index(autoHandler, "P-Auto-Answer)=normal")
	speakerIdx := strings.Index(autoHandler, `n(speaker),Set(PJSIP_HEADER(add,Alert-Info)=<http://www.notused.com>\;info=alert-autoanswer)`)
	if jumpIdx < 0 || speakerIdx < 0 || normalIdx < 0 {
		t.Fatal("auto-answer handler missing speaker jump, speaker branch, or normal branch")
	}
	if strings.Contains(autoHandler, "<http://www.notused.com>;info=") ||
		strings.Contains(autoHandler, "<sip:simson>;answer-after=") {
		t.Fatal("headers with semicolon parameters must escape semicolons in extensions.conf")
	}
	if jumpIdx > normalIdx {
		t.Fatal("speaker mode must jump away before normal auto-answer headers are emitted")
	}
	speakerBranch := autoHandler[speakerIdx:]
	if !strings.Contains(speakerBranch, `\;info=alert-autoanswer`) ||
		!strings.Contains(speakerBranch, "P-Auto-Answer)=normal") {
		t.Fatal("speaker mode should include normal auto-answer compatibility hints as well as intercom hints")
	}
	normalHintIdx := strings.Index(speakerBranch, "P-Auto-Answer)=normal")
	intercomHintIdx := strings.LastIndex(speakerBranch, "P-Auto-Answer)=intercom")
	if normalHintIdx < 0 || intercomHintIdx < normalHintIdx {
		t.Fatal("speaker/intercom hints must be emitted after normal compatibility hints so last-header-wins phones enter speaker mode")
	}
	caller := section(dialplan, "exten => 1025,1,NoOp(Simson direct SIP endpoint", "exten => 1603,1,NoOp")
	if strings.Contains(caller, "Answer-Mode)=Auto") {
		t.Fatal("caller endpoint should not receive target endpoint auto-answer headers")
	}
}

func TestCallbackBridgeDialplanIsAllowlistedAndCarriesBothAutoModes(t *testing.T) {
	root := t.TempDir()
	cfg := SetupConfig{
		SIPDomain:   "simson-vps.vipsy.in",
		InContext:   "from-simson-sip",
		NodeContext: "from-simson-node",
		OutContext:  "from-simson-out",
	}
	endpoints := []SIPEndpointDef{
		{ID: "caller", Extension: "1025", Username: "1025", Password: "secret", Enabled: true},
		{
			ID:                        "target",
			Extension:                 "1603",
			Username:                  "1603",
			Password:                  "secret",
			Enabled:                   true,
			AutoAnswer:                true,
			AutoAnswerCallers:         "1025",
			AutoSpeaker:               true,
			AutoSpeakerCallers:        "1025",
			CallbackBridge:            true,
			CallbackBridgeCallers:     "1025",
			CallbackCallerAutoAnswer:  true,
			CallbackCallerAutoSpeaker: true,
		},
	}
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, "7009", nil, endpoints); err != nil {
		t.Fatal(err)
	}

	dialplan := buildDirectEndpointDialplan(endpoints)
	target := section(dialplan, "exten => 1603,1,NoOp(Simson direct SIP endpoint", "exten => _+X.")
	for _, want := range []string{
		`"${SIMSON_CALLER_ENDPOINT}" = "1025"`,
		`UserEvent(SimsonIntercomCallback`,
		`Source: ${SIMSON_CALLBACK_SOURCE}`,
		`Target: ${EXTEN}`,
		`SourceAutoMode: speaker`,
		`TargetAutoMode: ${SIMSON_AUTO_ANSWER_MODE}`,
		`ControlCode: no`,
		`Answer()`,
		`Wait(0.2)`,
		`Hangup()`,
		`Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=60},${SIMSON_DIAL_OPTIONS})`,
	} {
		if !strings.Contains(target, want) {
			t.Fatalf("callback bridge dialplan missing %q:\n%s", want, target)
		}
	}
	eventIdx := strings.Index(target, `UserEvent(SimsonIntercomCallback`)
	answerIdx := strings.Index(target, `Answer()`)
	waitIdx := strings.Index(target, `Wait(0.2)`)
	hangupIdx := strings.Index(target, `Hangup()`)
	if eventIdx < 0 || answerIdx < eventIdx || waitIdx < answerIdx || hangupIdx < waitIdx {
		t.Fatalf("callback bridge must arm the VPS event, answer as a clean control leg, then short-teardown:\n%s", target)
	}
	if strings.Contains(target, "SourceAutoMode: normal") {
		t.Fatal("speaker mode should take precedence over normal caller auto-answer mode")
	}
	feature := section(dialplan, "exten => *1603,1,NoOp(Simson callback feature code", "exten => _+X.")
	for _, want := range []string{
		`Target: 1603`,
		`SourceAutoMode: speaker`,
		`TargetAutoMode: ${SIMSON_AUTO_ANSWER_MODE}`,
		`ControlCode: yes`,
		`Wait(0.03)`,
		`Hangup()`,
	} {
		if !strings.Contains(feature, want) {
			t.Fatalf("callback feature-code route missing %q:\n%s", want, feature)
		}
	}
	if strings.Contains(feature, `Dial(PJSIP/${EXTEN}`) || strings.Contains(feature, `Dial(PJSIP/1603`) {
		t.Fatalf("feature-code route must not directly ring the target before VPS callback:\n%s", feature)
	}

	fullDialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	callbackSource := section(fullDialplan, "[from-simson-callback-source]", "[from-simson-callback-target]")
	for _, want := range []string{
		`Tb(simson-auto-answer^s^1(${SIMSON_SOURCE_AUTO_MODE}))`,
		`Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},${SIMSON_DIAL_OPTIONS})`,
	} {
		if !strings.Contains(callbackSource, want) {
			t.Fatalf("callback source dialplan missing %q:\n%s", want, callbackSource)
		}
	}
	callbackTarget := section(fullDialplan, "[from-simson-callback-target]", "[from-simson-out]")
	for _, want := range []string{
		`Set(CALLERID(num)=${SIMSON_TARGET_LEG_CALLER_NUM})`,
		`Set(CALLERID(name)=${SIMSON_TARGET_LEG_CALLER_NAME})`,
		`Tb(simson-auto-answer^s^1(${SIMSON_TARGET_AUTO_MODE}))`,
	} {
		if !strings.Contains(callbackTarget, want) {
			t.Fatalf("callback target dialplan missing %q:\n%s", want, callbackTarget)
		}
	}
	targetFirst := section(fullDialplan, "[from-simson-callback-target-first]", "[from-simson-callback-source-after-target]")
	for _, want := range []string{
		`Set(CALLERID(num)=${SIMSON_TARGET_LEG_CALLER_NUM})`,
		`Tb(simson-auto-answer^s^1(${SIMSON_TARGET_AUTO_MODE}))`,
		`Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},${SIMSON_DIAL_OPTIONS})`,
	} {
		if !strings.Contains(targetFirst, want) {
			t.Fatalf("callback target-first dialplan missing %q:\n%s", want, targetFirst)
		}
	}
	sourceAfterTarget := section(fullDialplan, "[from-simson-callback-source-after-target]", "[from-simson-out]")
	for _, want := range []string{
		`Set(CALLERID(all)=${SIMSON_SOURCE_LEG_CALLER_ID})`,
		`Tb(simson-auto-answer^s^1(${SIMSON_SOURCE_AUTO_MODE}))`,
		`Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},${SIMSON_DIAL_OPTIONS})`,
	} {
		if !strings.Contains(sourceAfterTarget, want) {
			t.Fatalf("callback source-after-target dialplan missing %q:\n%s", want, sourceAfterTarget)
		}
	}
}

func TestBLFHintsAreGeneratedForDirectRegisteredEndpointsOnly(t *testing.T) {
	root := t.TempDir()
	cfg := SetupConfig{
		SIPDomain:   "simson-vps.vipsy.in",
		InContext:   "from-simson-sip",
		NodeContext: "from-simson-node",
		OutContext:  "from-simson-out",
	}
	endpoints := []SIPEndpointDef{
		{ID: "desk", Extension: "1027", Username: "1027", Password: "secret", Enabled: true},
		{ID: "target", Extension: "1603", Username: "1603", Password: "secret", Enabled: true},
		{ID: "gateway", Extension: "7009", Username: "7009", Password: "secret", Enabled: true},
		{ID: "node-route", Extension: "198", Username: "198", Password: "secret", RouteTo: "office2", Enabled: true},
	}
	if err := writePJSIPConf(root, cfg, endpoints); err != nil {
		t.Fatal(err)
	}
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, "7009", nil, endpoints); err != nil {
		t.Fatal(err)
	}

	pjsip := readTestFile(t, filepath.Join(root, "pjsip.d", "simson.conf"))
	template := section(pjsip, "[simson-ep-tpl](!)", "[simson-auth-tpl](!)")
	for _, want := range []string{
		"allow_subscribe=yes",
		"subscribe_context=simson-blf",
		"notify_early_inuse_ringing=yes",
	} {
		if !strings.Contains(template, want) {
			t.Fatalf("SIP endpoint template missing BLF setting %q:\n%s", want, template)
		}
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	blfStart := strings.Index(dialplan, "[simson-blf]")
	if blfStart < 0 {
		t.Fatalf("BLF context missing:\n%s", dialplan)
	}
	blf := dialplan[blfStart:]
	for _, want := range []string{
		"exten => 1027,hint,PJSIP/1027",
		"exten => 1603,hint,PJSIP/1603",
	} {
		if !strings.Contains(blf, want) {
			t.Fatalf("BLF hints missing %q:\n%s", want, blf)
		}
	}
	for _, notWant := range []string{
		"exten => 7009,hint",
		"exten => 198,hint",
	} {
		if strings.Contains(blf, notWant) {
			t.Fatalf("BLF hints should not include gateway or HAOS-routed endpoint %q:\n%s", notWant, blf)
		}
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
	if !strings.Contains(dialplan, "GatewaySource: ${EXTEN}") {
		t.Fatal("anonymous gateway dialplan must pass the gateway source extension to the router")
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
