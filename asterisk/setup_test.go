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
	if !strings.Contains(pjsip, "[simson-udp-alt]\ntype=transport\nprotocol=udp\nbind=0.0.0.0:15060") {
		t.Fatal("alternate SIP UDP transport must listen on port 15060")
	}
	if !strings.Contains(pjsip, "keep_alive_interval=25") {
		t.Fatal("PJSIP global config must keep TCP/TLS phone NAT bindings alive")
	}
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
	directDesk := section(dialplan, "exten => 1025,1,NoOp(Simson direct SIP endpoint", "; Explicit HAOS-card bypass.")
	if strings.Count(directDesk, "Set(JITTERBUFFER(adaptive)=default)") != 1 {
		t.Fatalf("direct SIP caller leg should receive exactly one adaptive jitter buffer:\n%s", directDesk)
	}
	if !strings.Contains(directDesk, "Ttb(simson-extension-predial^s^1(${SIMSON_CALL_ID}^))") {
		t.Fatalf("direct SIP called leg should receive the media pre-dial handler:\n%s", directDesk)
	}
	if !strings.Contains(directDesk, "U(simson-direct-observer-answer^${SIMSON_CALL_ID}^${CALLERID(num)}^${EXTEN}^)") {
		t.Fatalf("direct SIP answer observer must use Dial U(context^args), without b/B-style extension and priority fields:\n%s", directDesk)
	}
	if strings.Contains(directDesk, "U(simson-direct-observer-answer^s^1(") {
		t.Fatalf("direct SIP answer observer uses invalid Dial U syntax:\n%s", directDesk)
	}
	inboundSIP := section(dialplan, "\n[from-simson-sip]\n", "\n[from-simson-node]\n")
	if strings.Contains(inboundSIP, "@7009") {
		t.Fatal("SIP-phone PSTN calls should route through SimsonRoute, not a hardwired default trunk")
	}
	if !strings.Contains(inboundSIP, "UserEvent(SimsonRoute") {
		t.Fatal("SIP-phone PSTN calls must reach SimsonRoute for per-account gateway selection")
	}
	if !strings.Contains(inboundSIP, "exten => *100,1,NoOp(Simson: explicit HAOS card bypass") {
		t.Fatal("*100 must provide an explicit HAOS-card bypass for phones with a live advanced route")
	}
}

func TestSupervisionDialplanIsExactAuthenticatedAndAccountScoped(t *testing.T) {
	root := t.TempDir()
	endpoints := []SIPEndpointDef{
		{
			Extension: "1026", AccountID: "site-a", Enabled: true,
			SupervisionConfig: `{"enabled":true,"listen":true,"listen_key":"*81","whisper":true,"whisper_key":"*82","barge":true,"barge_key":"*83","targets":["1028","2020"]}`,
		},
		{Extension: "1028", AccountID: "site-a", Enabled: true},
		{Extension: "2020", AccountID: "site-b", Enabled: true},
	}
	if err := writeDialplanConf(root, "from-simson-sip", "from-simson-node", "from-simson-out", "7009", nil, endpoints); err != nil {
		t.Fatal(err)
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	for _, want := range []string{
		"exten => *811028,1,NoOp(Simson authorized call supervision",
		"exten => 811028,1,NoOp(Simson authorized call supervision",
		"exten => *821028,1,NoOp(Simson authorized call supervision",
		"exten => 821028,1,NoOp(Simson authorized call supervision",
		"exten => *831028,1,NoOp(Simson authorized call supervision",
		"exten => 831028,1,NoOp(Simson authorized call supervision",
		`Set(SIMSON_SUPERVISOR=${SIMSON_ENDPOINT_ID})`,
		`Set(SIMSON_SUPERVISOR=${CHANNEL(pjsip,endpoint)})`,
		`Set(SIMSON_CHANNEL_ENDPOINT=${CUT(SIMSON_CHANNEL_RESOURCE,-,1)})`,
		`GotoIf($["${SIMSON_SUPERVISOR}" = "1026"]?supervise-0)`,
		"ChanSpy(PJSIP/1028-,qbE)",
		"ChanSpy(PJSIP/1028-,qbwE)",
		"ChanSpy(PJSIP/1028-,qbBE)",
		"exten => 1028,1,NoOp(Simson direct SIP endpoint",
	} {
		if !strings.Contains(dialplan, want) {
			t.Fatalf("generated supervision dialplan missing %q:\n%s", want, dialplan)
		}
	}
	if strings.Contains(dialplan, "*812020") || strings.Contains(dialplan, "ChanSpy(PJSIP/2020-") {
		t.Fatalf("cross-account supervision target leaked into dialplan:\n%s", dialplan)
	}
	if strings.Contains(dialplan, "812020") {
		t.Fatalf("cross-account supervision target leaked into compatibility aliases:\n%s", dialplan)
	}
	if !strings.Contains(section(dialplan, "exten => *811028", "exten => *821028"), "Hangup(21)") {
		t.Fatal("unauthorized supervisor calls must be rejected")
	}
	if !strings.Contains(section(dialplan, "exten => 811028", "exten => 821028"), "Hangup(21)") {
		t.Fatal("digits-only compatibility aliases must retain endpoint authorization")
	}
}

func TestPJSIPEndpointCarriesServerAssignedAuthorizationIdentity(t *testing.T) {
	root := t.TempDir()
	endpoints := []SIPEndpointDef{{
		Extension: "1027", Username: "supervisor-auth", Password: "test-secret", AccountID: "site-a", Enabled: true,
	}}
	if err := writePJSIPConf(root, SetupConfig{SIPDomain: "simson-vps.vipsy.in"}, endpoints); err != nil {
		t.Fatal(err)
	}
	pjsip := readTestFile(t, filepath.Join(root, "pjsip.d", "simson.conf"))
	endpoint := section(pjsip, "[1027](simson-ep-tpl)", "[1027-auth]")
	if !strings.Contains(endpoint, "set_var=SIMSON_ENDPOINT_ID=1027") {
		t.Fatalf("endpoint must carry its server-assigned supervision identity:\n%s", endpoint)
	}
}

func TestGatewayEndpointsExpireStaleMediaLegs(t *testing.T) {
	root := t.TempDir()
	endpoints := []SIPEndpointDef{
		{Extension: "7014", Username: "7014", Password: "test-secret", Enabled: true},
		{Extension: "1027", Username: "1027", Password: "test-secret", Enabled: true},
	}
	if err := writePJSIPConf(root, SetupConfig{
		SIPDomain:               "simson-vps.vipsy.in",
		NoAuthInboundExtensions: []string{"7014"},
	}, endpoints); err != nil {
		t.Fatal(err)
	}

	pjsip := readTestFile(t, filepath.Join(root, "pjsip.d", "simson.conf"))
	gateway := section(pjsip, "[7014](simson-ep-tpl)", "[7014-auth]")
	if !strings.Contains(gateway, "rtp_timeout=120") || !strings.Contains(gateway, "rtp_timeout_hold=300") {
		t.Fatalf("gateway endpoint must expire stale media legs:\n%s", gateway)
	}
	deskPhone := section(pjsip, "[1027](simson-ep-tpl)", "[1027-auth]")
	if strings.Contains(deskPhone, "rtp_timeout=120") || strings.Contains(deskPhone, "rtp_timeout_hold=300") {
		t.Fatalf("stale gateway watchdog must not alter desk-phone media policy:\n%s", deskPhone)
	}
}

func TestConfBridgeDoesNotStackJitterOrInjectHoldAudio(t *testing.T) {
	root := t.TempDir()
	if err := writeConfBridgeConf(root); err != nil {
		t.Fatal(err)
	}

	conf := readTestFile(t, filepath.Join(root, "confbridge.conf.d", "simson.conf"))
	user := section(conf, "[simson_user]", "\n[nonexistent]")
	if strings.Contains(user, "jitterbuffer=yes") {
		t.Fatalf("ConfBridge must not stack a second jitter buffer on dialplan-buffered channels:\n%s", user)
	}
	if !strings.Contains(user, "music_on_hold_when_empty=no") {
		t.Fatalf("ConfBridge must not leak hold/ringback audio while a participant is alone:\n%s", user)
	}
	waiting := section(conf, "[simson_waiting_user]", "\n[nonexistent]")
	if !strings.Contains(waiting, "music_on_hold_when_empty=yes") || !strings.Contains(waiting, "music_on_hold_class=default") {
		t.Fatalf("advanced-route callers must hear waiting audio while phones ring:\n%s", waiting)
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
	endpoints := []SIPEndpointDef{
		{Extension: "7013", Username: "7013", GatewayIVREnabled: true, GatewayIVRSound: "custom/site_7013_welcome", Enabled: true},
		{Extension: "7014", Username: "7014", GatewayIVREnabled: false, Enabled: true},
	}
	cfg.NoAuthInboundExtensions = append(cfg.NoAuthInboundExtensions, "7014")
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, "7009", cfg.NoAuthInboundExtensions, endpoints); err != nil {
		t.Fatal(err)
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	announcement := section(dialplan, "[simson-gateway-announcement]", "[simson-auto-answer]")
	for _, want := range []string{
		"Progress()",
		"TryExec(Playback(${ARG1},noanswer))",
		"TryExec(Playback(queue-thankyou&one-moment-please&pls-hold-while-try,noanswer))",
		"Return()",
	} {
		if !strings.Contains(announcement, want) {
			t.Fatalf("gateway welcome announcement missing %q:\n%s", want, announcement)
		}
	}
	if strings.Contains(announcement, "Answer()") {
		t.Fatalf("gateway welcome announcement must not force-answer before routing:\n%s", announcement)
	}

	inboundSIP := section(dialplan, "\n[from-simson-sip]\n", "\n[from-simson-node]\n")
	if strings.Contains(inboundSIP, "simson-gateway-announcement") {
		t.Fatalf("authenticated catch-all routes should not play a global gateway announcement:\n%s", inboundSIP)
	}

	anonymous := section(dialplan, "\n[from-simson-anonymous]\n", "\n[from-simson-sip-outbound]")
	if !strings.Contains(anonymous, "exten => 7013,1,NoOp(Simson anonymous gateway call") ||
		!strings.Contains(anonymous, "Gosub(simson-gateway-announcement,s,1(custom/site_7013_welcome))") {
		t.Fatalf("no-auth gateway ingress with IVR enabled should play its configured announcement:\n%s", anonymous)
	}
	if !strings.Contains(anonymous, "exten => 7014,1,NoOp(Simson anonymous gateway call") {
		t.Fatalf("second no-auth gateway missing:\n%s", anonymous)
	}
	if strings.Contains(section(anonymous, "exten => 7014,1", "\n[from-simson-sip-outbound]"), "simson-gateway-announcement") {
		t.Fatalf("gateway without IVR enabled should not play an announcement:\n%s", anonymous)
	}
	anonRouteIdx := strings.Index(anonymous, "UserEvent(SimsonRoute")
	anonAnnouncementIdx := strings.Index(anonymous, "Gosub(simson-gateway-announcement,s,1(custom/site_7013_welcome))")
	if anonRouteIdx < 0 || anonAnnouncementIdx < 0 || anonRouteIdx > anonAnnouncementIdx {
		t.Fatalf("no-auth gateway ingress must start routing before playing the announcement:\n%s", anonymous)
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
	if !strings.Contains(target, "b(simson-extension-predial^s^1(${SIMSON_CALL_ID}^${SIMSON_AUTO_ANSWER_MODE}))") {
		t.Fatal("direct SIP route should apply called-leg jitter and auto-answer headers in one pre-dial handler")
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

func TestReceivingPhoneAnnouncementIsCalledPartyOnly(t *testing.T) {
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
			ID:                  "target",
			Extension:           "1603",
			Username:            "1603",
			Password:            "secret",
			AnswerAnnouncement:  "custom/call_for_amit",
			PreRingAnnouncement: "custom/please_wait",
			CallDurationRules:   `{"1025":15}`,
			Enabled:             true,
		},
	}
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, "7009", nil, endpoints); err != nil {
		t.Fatal(err)
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	direct := section(dialplan, "exten => 1603,1,NoOp(Simson direct SIP endpoint", "exten => _+X.")
	if !strings.Contains(direct, "A(custom/call_for_amit)") {
		t.Fatal("direct SIP route must play the target endpoint announcement")
	}
	if strings.Contains(direct, "A(custom/call_for_amit:") {
		t.Fatal("announcement must not define a caller-side sound")
	}
	preRingIdx := strings.Index(direct, "Playback(custom/please_wait,noanswer)")
	dialIdx := strings.Index(direct, "Dial(PJSIP/${EXTEN}")
	if preRingIdx < 0 || dialIdx < 0 || preRingIdx > dialIdx {
		t.Fatalf("caller pre-ring prompt must finish before the target starts ringing:\n%s", direct)
	}
	for _, want := range []string{
		`"${SIMSON_CALLER_ENDPOINT}" = "1025"`,
		`Set(SIMSON_ROUTE_LIMIT_MS=15000)`,
		`L(${SIMSON_ROUTE_LIMIT_MS})`,
	} {
		if !strings.Contains(direct, want) {
			t.Fatalf("exact connected-call limit missing %q:\n%s", want, direct)
		}
	}

	nodeRoute := section(dialplan, "[from-simson-extension]", "[from-simson-out]")
	if !strings.Contains(nodeRoute, "exten => 1603,1,NoOp(Simson call policy SIP endpoint") ||
		!strings.Contains(nodeRoute, "A(custom/call_for_amit)") ||
		!strings.Contains(nodeRoute, "Playback(custom/please_wait,noanswer)") ||
		!strings.Contains(nodeRoute, "L(${SIMSON_ROUTE_LIMIT_MS})") {
		t.Fatal("node/VPS-originated route must preserve prompts and exact duration policy")
	}
	callerRoute := section(dialplan, "exten => 1025,1,NoOp(Simson direct SIP endpoint", "exten => 1603,1,NoOp")
	if strings.Contains(callerRoute, "please_wait") || strings.Contains(callerRoute, "SIMSON_ROUTE_LIMIT_MS") {
		t.Fatal("target call policy leaked onto an unrelated SIP endpoint")
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
		`Playback(${SIMSON_PRE_RING_ANNOUNCEMENT})`,
		`L(${SIMSON_MAX_CONNECTED_MS})`,
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

func TestAdvancedIngressEndpointUsesRouteEventInsteadOfDirectDial(t *testing.T) {
	endpoints := []SIPEndpointDef{
		{ID: "direct", Extension: "1027", Username: "1027", Password: "secret", Enabled: true},
		{ID: "routed", Extension: "1040", Username: "1040", Password: "secret", Enabled: true, AdvancedIngress: true},
	}
	dialplan := buildDirectEndpointDialplan(endpoints)
	if !strings.Contains(dialplan, "exten => 1027,1,NoOp(Simson direct SIP endpoint") {
		t.Fatal("ordinary SIP endpoint lost its direct dial route")
	}
	if strings.Contains(dialplan, "exten => 1040,1,NoOp(Simson direct SIP endpoint") {
		t.Fatal("advanced-ingress endpoint must reach the catch-all SimsonRoute handler")
	}
	advanced := buildAdvancedIngressDialplan(endpoints)
	for _, want := range []string{
		"exten => 1040,1,NoOp(Simson advanced landing call",
		"UserEvent(SimsonRoute,Extension: ${EXTEN}",
		"ConfBridge(${SIMSON_BRIDGE_ID},simson_bridge,simson_waiting_user)",
	} {
		if !strings.Contains(advanced, want) {
			t.Fatalf("advanced landing dialplan missing %q:\n%s", want, advanced)
		}
	}
	if strings.Contains(advanced, "exten => 1027,") {
		t.Fatalf("ordinary endpoint was incorrectly emitted as advanced ingress:\n%s", advanced)
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

func TestAccountFeatureCodesAreGeneratedAndAccountScoped(t *testing.T) {
	root := t.TempDir()
	endpoints := []SIPEndpointDef{
		{Extension: "1027", Username: "site-a-1027", AccountID: "site-a", Enabled: true, AccountFeaturesEnabled: true, AccountTransferCode: "*84", AccountConferenceCode: "*85"},
		{Extension: "1028", Username: "site-a-1028", AccountID: "site-a", Enabled: true, AccountFeaturesEnabled: true, AccountTransferCode: "*84", AccountConferenceCode: "*85"},
		{Extension: "7009", Username: "site-a-7009", AccountID: "site-a", Enabled: true, DefaultOutbound: true, AccountFeaturesEnabled: true, AccountTransferCode: "*84", AccountConferenceCode: "*85"},
		{Extension: "2020", Username: "site-b-2020", AccountID: "site-b", Enabled: true, AccountFeaturesEnabled: true, AccountTransferCode: "*74", AccountConferenceCode: "*85"},
		{Extension: "7013", Username: "site-b-7013", AccountID: "site-b", Enabled: true, DefaultOutbound: true, AccountFeaturesEnabled: true, AccountTransferCode: "*74", AccountConferenceCode: "*85"},
	}
	if err := writeDialplanConf(root, "from-simson-sip", "from-simson-node", "from-simson-out", "7009", nil, endpoints); err != nil {
		t.Fatal(err)
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	for _, want := range []string{
		"Set(__SIMSON_BLINDXFER_CODE=*84)",
		"Set(FEATUREMAP(blindxfer)=*84)",
		"Set(__TRANSFER_CONTEXT=simson-transfer-site-a)",
		"Set(TRANSFER_CONTEXT=simson-transfer-site-a)",
		"Set(SIMSON_DIAL_OPTIONS=Ttb(simson-extension-predial",
		"exten => *851028,1,NoOp(Simson site conference launch",
		`"${CHANNEL(pjsip,endpoint)}" = "site-a-1027"`,
		"exten => *852020,1,NoOp(Simson site conference launch",
		"exten => _*85X.,1,NoOp(Simson account-authorized outside conference",
		"Dial(PJSIP/${SIMSON_CONF_NUMBER}@7009,60,G(simson-account-conference",
		"Dial(PJSIP/${SIMSON_CONF_NUMBER}@7013,60,G(simson-account-conference",
		"[simson-account-conference]",
		"[simson-transfer-site-a]",
		"exten => 1028,1,NoOp(Simson same-site blind transfer to 1028)",
		"Set(SIMSON_TRUNK=7009)",
		"Goto(from-simson-out,${SIMSON_XFER_NUMBER},1)",
	} {
		if !strings.Contains(dialplan, want) {
			t.Fatalf("account feature dialplan missing %q:\n%s", want, dialplan)
		}
	}
	if strings.Count(dialplan, "exten => _*85X.,1,") != 1 {
		t.Fatalf("shared conference prefix must emit one account-authorized outside pattern:\n%s", dialplan)
	}
	siteAConference := section(dialplan, "exten => *851028", "exten => *852020")
	if strings.Contains(siteAConference, "site-b-2020") || strings.Contains(siteAConference, "PJSIP/2020") {
		t.Fatalf("site-b endpoint leaked into site-a conference authorization:\n%s", siteAConference)
	}
	siteATransfer := section(dialplan, "[simson-transfer-site-a]", "[simson-transfer-site-b]")
	if !strings.Contains(siteATransfer, "Set(SIMSON_TRUNK=7009)") {
		t.Fatalf("site-a outside transfer did not use its default gateway:\n%s", siteATransfer)
	}
	if strings.Contains(siteATransfer, "2020") || strings.Contains(siteATransfer, "SIMSON_TRUNK=7013") {
		t.Fatalf("site-b endpoint or gateway leaked into site-a transfer context:\n%s", siteATransfer)
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

func TestDirectSIPConferenceBargeDialplan(t *testing.T) {
	root := t.TempDir()
	if err := writeDialplanConf(root, "from-simson-sip", "from-simson-node", "from-simson-out", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	for _, want := range []string{
		"[simson-direct-conference]",
		"ChanSpy(${SIMSON_SPY_CHANNEL},qBE)",
		"same  => n(invalid),Hangup(21)",
	} {
		if !strings.Contains(dialplan, want) {
			t.Fatalf("generated direct conference dialplan missing %q:\n%s", want, dialplan)
		}
	}
}

func TestOutboundTrunkDialplanAppliesOptionalConnectedCallLimit(t *testing.T) {
	root := t.TempDir()
	if err := writeDialplanConf(root, "from-simson-sip", "from-simson-node", "from-simson-out", "7009", nil, nil); err != nil {
		t.Fatal(err)
	}

	dialplan := readTestFile(t, filepath.Join(root, "extensions.d", "simson.conf"))
	outbound := section(dialplan, "[from-simson-out]", "[simson-outbound-postanswer]")
	for _, want := range []string{
		`GotoIf($["${SIMSON_POST_ANSWER_DTMF}" = ""]?dial-limit)`,
		`GotoIf($["${SIMSON_MAX_CONNECTED_MS}" = ""]?dial)`,
		`Set(SIMSON_DIAL_OPTIONS=${SIMSON_DIAL_OPTIONS}L(${SIMSON_MAX_CONNECTED_MS}))`,
	} {
		if !strings.Contains(outbound, want) {
			t.Fatalf("outbound trunk dialplan missing %q:\n%s", want, outbound)
		}
	}
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
