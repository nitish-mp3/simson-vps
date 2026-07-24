package asterisk

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nitish-mp3/simson-vps/logging"
)

// ---- public types -----------------------------------------------------------

// SetupConfig holds parameters for auto-configuring Asterisk on the VPS.
type SetupConfig struct {
	AmiUser                 string
	AmiSecret               string
	SIPDomain               string   // PJSIP transport domain / hostname seen by phones
	ExternalIP              string   // Public IP for RTP NAT traversal (empty → omit external_media_address)
	InContext               string   // dialplan context for incoming SIP calls ("from-simson-sip")
	NodeContext             string   // dialplan context for node-callback channels ("from-simson-node")
	OutContext              string   // dialplan context for configured outbound trunk/landline calls
	DefaultPSTNTrunk        string   // registered gateway endpoint for SIP-phone outside dialing
	TrustedGatewayIPs       []string // trusted SIP gateway public IPs for inbound INVITEs that cannot digest-auth
	NoAuthInboundExtensions []string // gateway extensions that cannot digest-auth inbound INVITEs
	// Shared SIP-over-WebSocket endpoint for browser SIP.js clients.
	// Empty Username disables the webrtc-pool endpoint.
	WebRTCUser string
	WebRTCPass string
}

// SIPEndpointDef is a minimal view of a SIP endpoint used when writing pjsip.conf.
// It mirrors store.SIPEndpoint but avoids an import cycle.
type SIPEndpointDef struct {
	ID           string
	AccountID    string
	Extension    string
	Username     string
	Password     string
	RouteTo      string
	VideoEnabled bool
	AutoAnswer   bool
	// AutoAnswerCallers is a comma-separated allowlist. Empty means any caller.
	AutoAnswerCallers string
	AutoSpeaker       bool
	// AutoSpeakerCallers optionally narrows speaker/intercom mode to a separate
	// caller allowlist. Empty reuses AutoAnswerCallers for backward compatibility.
	AutoSpeakerCallers string
	// CallbackBridge lets Simson call the original caller back first, then bridge
	// to this endpoint. This is the only reliable caller-side auto speaker path.
	CallbackBridge bool
	// CallbackBridgeCallers is the allowlist for callback bridge source phones.
	CallbackBridgeCallers     string
	CallbackCallerAutoAnswer  bool
	CallbackCallerAutoSpeaker bool
	GatewayIVREnabled         bool
	GatewayIVRSound           string
	// AnswerAnnouncement is played to the receiving phone after answer and
	// before bridging. It is never played to the caller.
	AnswerAnnouncement string
	// PreRingAnnouncement is played to the caller before this endpoint starts
	// ringing. It is intentionally separate from AnswerAnnouncement.
	PreRingAnnouncement string
	// CallDurationRules maps exact source SIP extensions to the maximum
	// connected-call duration for this target, encoded as validated JSON.
	CallDurationRules string
	// SupervisionConfig contains validated account-scoped feature-code
	// permissions for this authenticated endpoint.
	SupervisionConfig string
	// Account-scoped feature codes copied onto every endpoint definition during
	// config generation. They are never shared across customer accounts.
	AccountTransferCode    string
	AccountConferenceCode  string
	AccountFeaturesEnabled bool
	// AdvancedIngress keeps this exact extension out of the direct Dial path so
	// its enabled per-line route can be evaluated by the Simson control plane.
	AdvancedIngress bool
	// DefaultOutbound marks this endpoint as its account's selected gateway.
	// It is used only for account-authorized outside-number feature calls.
	DefaultOutbound bool
	Enabled         bool
}

// Setup writes all Asterisk config files needed by the Simson VPS and reloads
// the relevant Asterisk modules. It is idempotent — safe to call on every start.
func Setup(cfg SetupConfig, endpoints []SIPEndpointDef, log *logging.Logger) error {
	root := findAsteriskRoot()
	if root == "" {
		return fmt.Errorf(
			"asterisk config root not found (tried /etc/asterisk, /usr/local/etc/asterisk). " +
				"Install Asterisk first: sudo apt install asterisk",
		)
	}

	if err := writeManagerConf(root, cfg.AmiUser, cfg.AmiSecret); err != nil {
		return fmt.Errorf("manager.conf: %w", err)
	}
	if err := writePJSIPConf(root, cfg, endpoints); err != nil {
		return fmt.Errorf("pjsip.conf: %w", err)
	}
	if err := writeHTTPConf(root); err != nil {
		return fmt.Errorf("http.conf: %w", err)
	}
	if err := writeRTPConf(root, cfg.ExternalIP, cfg.SIPDomain); err != nil {
		return fmt.Errorf("rtp.conf: %w", err)
	}
	if err := writeConfBridgeConf(root); err != nil {
		return fmt.Errorf("confbridge.conf: %w", err)
	}
	if err := writeDialplanConf(root, cfg.InContext, cfg.NodeContext, cfg.OutContext, cfg.DefaultPSTNTrunk, cfg.NoAuthInboundExtensions, endpoints); err != nil {
		return fmt.Errorf("extensions.conf: %w", err)
	}

	log.Info("asterisk config written", map[string]any{"root": root})

	if err := reloadModules(log); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return nil
}

// ---- internal ---------------------------------------------------------------

var asteriskRoots = []string{
	"/etc/asterisk",
	"/usr/local/etc/asterisk",
}

func findAsteriskRoot() string {
	for _, p := range asteriskRoots {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

// ensureInclude appends a #include directive to confFile if not already present.
func ensureInclude(confFile, glob string) error {
	data, _ := os.ReadFile(confFile) // file may not exist — ignore err
	content := string(data)
	normGlob := strings.ReplaceAll(glob, "\\", "/")
	dirPattern := filepath.Base(filepath.Dir(normGlob)) + "/*.conf"
	line := "#include " + glob
	if strings.Contains(content, line) || strings.Contains(content, normGlob) || strings.Contains(content, dirPattern) {
		return nil
	}
	f, err := os.OpenFile(confFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "\n; Added by Simson VPS server\n%s\n", line)
	return err
}

func ensureSimsonIncludeBase(root, confFile, snippetDir string) error {
	confPath := filepath.Join(root, confFile)
	includeGlob := snippetDir + "/*.conf"
	data, _ := os.ReadFile(confPath)
	content := string(data)
	if isStockAsteriskSampleConfig(confFile, content) {
		backupPath := confPath + ".simson-sample.bak"
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, data, 0644); err != nil {
				return err
			}
		}
		minimal := fmt.Sprintf(
			`; Simson-managed minimal Asterisk base config.
; The stock sample config was backed up to %s.
; Real Simson configuration lives in the snippet directory below.
#include %s
`,
			filepath.Base(backupPath),
			includeGlob,
		)
		return os.WriteFile(confPath, []byte(minimal), 0644)
	}
	return ensureInclude(confPath, includeGlob)
}

func isStockAsteriskSampleConfig(confFile, content string) bool {
	switch confFile {
	case "pjsip.conf":
		return strings.Contains(content, "[1001]") &&
			strings.Contains(content, "context=default") &&
			strings.Contains(content, "username=1001") &&
			strings.Contains(content, "password=1234") &&
			strings.Contains(content, "webrtc=yes")
	case "extensions.conf":
		return strings.Contains(content, "[default]") &&
			strings.Contains(content, "exten => 1001,1,Answer()") &&
			strings.Contains(content, "Playback(hello-world)")
	default:
		return false
	}
}

// detectSnippetDirName picks the snippet dir already included by a base conf.
// Falls back to fallbackDir when no include is present.
func detectSnippetDirName(root, confFile string, candidates []string, fallbackDir string) string {
	data, _ := os.ReadFile(filepath.Join(root, confFile))
	content := strings.ReplaceAll(string(data), "\"", "")
	for _, name := range candidates {
		pattern := name + "/*.conf"
		if strings.Contains(content, pattern) || strings.Contains(content, "/"+pattern) {
			return name
		}
	}
	return fallbackDir
}

// ---- manager.conf -----------------------------------------------------------

func writeManagerConf(root, amiUser, amiSecret string) error {
	dirName := detectSnippetDirName(root, "manager.conf", []string{"manager.d", "manager.conf.d"}, "manager.d")
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := ensureInclude(
		filepath.Join(root, "manager.conf"),
		dirName+"/*.conf",
	); err != nil {
		return err
	}

	content := fmt.Sprintf(
		`; Auto-generated by Simson VPS server — do not edit manually.
; Re-generated on every server start when asterisk.auto_configure = true.
[general]
enabled = yes
port = 5038
bindaddr = 127.0.0.1

[%s]
secret = %s
deny = 0.0.0.0/0.0.0.0
permit = 127.0.0.1/255.255.255.255
read = all
write = all
writetimeout = 5000
`, amiUser, amiSecret)

	dest := filepath.Join(dir, "simson.conf")
	return os.WriteFile(dest, []byte(content), 0640)
}

// ---- pjsip.conf -------------------------------------------------------------

func writePJSIPConf(root string, cfg SetupConfig, endpoints []SIPEndpointDef) error {
	dirName := detectSnippetDirName(root, "pjsip.conf", []string{"pjsip.d", "pjsip.conf.d"}, "pjsip.d")
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := ensureSimsonIncludeBase(root, "pjsip.conf", dirName); err != nil {
		return err
	}

	var sb strings.Builder
	sb.WriteString("; Auto-generated by Simson VPS server — do not edit manually.\n\n")
	externalIP := strings.TrimSpace(cfg.ExternalIP)
	if externalIP == "" {
		externalIP = resolveExternalIPFromDomain(cfg.SIPDomain)
	}

	// ── UDP transport ──────────────────────────────────────────────────────────
	// Used by IP phones (desk phones, softphones) for SIP signalling.
	sb.WriteString("[simson-udp]\ntype=transport\nprotocol=udp\nbind=0.0.0.0:5060\n")
	if cfg.SIPDomain != "" {
		sb.WriteString("domain=" + cfg.SIPDomain + "\n")
	}
	// External IP lets Asterisk advertise the correct public address in SDP,
	// preventing the "audio not passing" problem caused by RFC1918 in SDP/RTP.
	appendTransportNATConfig(&sb, externalIP)
	sb.WriteString("\n")

	// ── TCP transport ──────────────────────────────────────────────────────────
	// Some phones / ISPs prefer or require TCP for SIP signalling.
	sb.WriteString("[simson-tcp]\ntype=transport\nprotocol=tcp\nbind=0.0.0.0:5060\n")
	if cfg.SIPDomain != "" {
		sb.WriteString("domain=" + cfg.SIPDomain + "\n")
	}
	appendTransportNATConfig(&sb, externalIP)
	sb.WriteString("\n")

	// ── Plain WebSocket transport (browser SIP.js / Simson card) ─────────────
	// TLS is handled upstream by Caddy which proxies /sip/ws → localhost:8088.
	// We intentionally omit a native WSS transport — the self-signed cert
	// Asterisk would need isn't available and browsers would reject it anyway.
	//
	// The listening port belongs to Asterisk's HTTP server (http.conf), not the
	// PJSIP websocket transport. Binding both to :8088 prevents SIP-over-WS from
	// coming up reliably, so keep the transport bind address portless.
	sb.WriteString("[simson-ws]\ntype=transport\nprotocol=ws\nbind=0.0.0.0\n")
	if cfg.SIPDomain != "" {
		sb.WriteString("domain=" + cfg.SIPDomain + "\n")
	}
	appendTransportNATConfig(&sb, externalIP)
	sb.WriteString("\n")

	// ── Global settings ──────────────────────────────────────────────────────
	trustedGatewayIPs := normalizeIPList(cfg.TrustedGatewayIPs)
	noAuthInbound := stringSet(cfg.NoAuthInboundExtensions)
	enableAnonymousIngress := len(noAuthInbound) > 0

	// Prefer username matching first so registered phones authenticate normally.
	// A site often has gateways and desk phones behind the same public NAT IP.
	// Broad IP identification would classify phone REGISTERs as the gateway
	// endpoint and prevent normal registration, so no-auth gateway ingress uses
	// the locked-down anonymous dialplan instead of an IP identify rule.
	endpointOrder := "username"
	if len(trustedGatewayIPs) > 0 && !enableAnonymousIngress {
		endpointOrder += ",ip"
	}
	if enableAnonymousIngress {
		endpointOrder += ",anonymous"
	}
	sb.WriteString("[global]\ntype=global\nmax_initial_qualify_time=60\nkeep_alive_interval=25\nendpoint_identifier_order=" + endpointOrder + "\n\n")

	// ── Endpoint template (shared settings for all Simson phones) ─────────────
	sipContext := cfg.InContext
	if sipContext == "" {
		sipContext = "from-simson-sip"
	}
	sb.WriteString(
		"[simson-ep-tpl](!)\ntype=endpoint\n" +
			"context=" + sipContext + "\n" +
			"disallow=all\n" +
			"allow=ulaw\nallow=alaw\n" +
			"direct_media=no\n" +
			"rtp_symmetric=yes\n" +
			"rtp_keepalive=2\n" +
			"rtp_timeout=0\n" +
			"rtp_timeout_hold=0\n" +
			"force_rport=yes\n" +
			"rewrite_contact=yes\n" +
			"identify_by=auth_username,username\n" +
			"ice_support=no\n" +
			"media_encryption=no\n" +
			"dtmf_mode=rfc4733\n" +
			"allow_subscribe=yes\n" +
			"subscribe_context=simson-blf\n" +
			"notify_early_inuse_ringing=yes\n" +
			"timers=no\n" +
			"100rel=no\n\n",
	)
	sb.WriteString("[simson-auth-tpl](!)\ntype=auth\nauth_type=userpass\n\n")
	sb.WriteString("[simson-aor-tpl](!)\ntype=aor\nmax_contacts=1\nremove_existing=yes\nqualify_frequency=30\n\n")
	sb.WriteString(
		"[simson-gateway-in-tpl](!)\ntype=endpoint\n" +
			"transport=simson-udp\n" +
			"context=" + sipContext + "\n" +
			"disallow=all\n" +
			"allow=ulaw\nallow=alaw\n" +
			"direct_media=no\n" +
			"rtp_symmetric=yes\n" +
			"rtp_keepalive=2\n" +
			"rtp_timeout=0\n" +
			"rtp_timeout_hold=0\n" +
			"force_rport=yes\n" +
			"rewrite_contact=yes\n" +
			"identify_by=ip\n" +
			"ice_support=no\n" +
			"media_encryption=no\n" +
			"dtmf_mode=rfc4733\n\n",
	)
	if enableAnonymousIngress {
		sb.WriteString(
			"[anonymous]\ntype=endpoint\n" +
				"transport=simson-udp\n" +
				"context=from-simson-anonymous\n" +
				"disallow=all\n" +
				"allow=ulaw\nallow=alaw\n" +
				"direct_media=no\n" +
				"rtp_symmetric=yes\n" +
				"rtp_keepalive=2\n" +
				"rtp_timeout=0\n" +
				"rtp_timeout_hold=0\n" +
				"force_rport=yes\n" +
				"rewrite_contact=yes\n" +
				"ice_support=no\n" +
				"media_encryption=no\n" +
				"dtmf_mode=rfc4733\n\n",
		)
	}
	sb.WriteString(
		"[simson-webrtc-ep-tpl](!)\ntype=endpoint\n" +
			"transport=simson-ws\n" +
			"context=from-simson-node\n" +
			"disallow=all\n" +
			"allow=ulaw\nallow=alaw\n" +
			"direct_media=no\n" +
			"rtp_symmetric=yes\n" +
			"rtp_keepalive=2\n" +
			"rtp_timeout=0\n" +
			"rtp_timeout_hold=0\n" +
			"force_rport=yes\n" +
			"rewrite_contact=yes\n" +
			"identify_by=auth_username,username\n" +
			"ice_support=yes\n" +
			"webrtc=yes\n" +
			"use_avpf=yes\n" +
			"rtcp_mux=yes\n" +
			"media_use_received_transport=yes\n" +
			"media_encryption=dtls\n" +
			"dtls_auto_generate_cert=yes\n" +
			"dtls_setup=actpass\n" +
			"dtmf_mode=rfc4733\n\n",
	)

	// ── Shared WebRTC pool endpoint (for browser SIP.js clients) ─────────────
	// All browser clients use the same credentials; individual routing is done
	// via the ConfBridge extension, not the SIP identity.
	if cfg.WebRTCUser != "" && cfg.WebRTCPass != "" {
		sb.WriteString(
			"[" + cfg.WebRTCUser + "](simson-webrtc-ep-tpl)\n" +
				"auth=" + cfg.WebRTCUser + "-auth\n" +
				"aors=" + cfg.WebRTCUser + "\n\n",
		)
		fmt.Fprintf(&sb, "[%s-auth](simson-auth-tpl)\nusername=%s\npassword=%s\n\n",
			cfg.WebRTCUser, cfg.WebRTCUser, cfg.WebRTCPass)
		// AOR must NOT inherit from template — explicit settings override.
		// Use type=aor directly without (template) so template values don't override.
		fmt.Fprintf(&sb, "[%s]\ntype=aor\nmax_contacts=50\nremove_existing=no\nqualify_frequency=30\n\n", cfg.WebRTCUser)
	}

	// ── Per-endpoint entries (registered SIP phones / devices) ────────────────
	//
	// Standard PJSIP pattern: the AoR name matches the SIP auth username so that
	// REGISTER (To: sip:<username>@domain) maps to the correct AoR.  Endpoint
	// and AoR may share the same section name — PJSIP stores them in separate
	// sorcery containers keyed by type.
	for _, ep := range endpoints {
		if !ep.Enabled {
			continue
		}
		endpointID := sanitizeID(ep.Extension)
		if endpointID == "" {
			endpointID = sanitizeID(ep.ID)
		}
		if endpointID == "" {
			continue
		}

		aorName := sanitizeID(ep.Username)
		if aorName == "" {
			aorName = endpointID
		}

		fmt.Fprintf(&sb, "[%s](simson-ep-tpl)\nauth=%s-auth\noutbound_auth=%s-auth\naors=%s\nset_var=SIMSON_ENDPOINT_ID=%s\n", endpointID, endpointID, endpointID, aorName, endpointID)
		if ep.VideoEnabled {
			sb.WriteString("allow=h264\n")
		}
		if _, ok := noAuthInbound[endpointID]; ok {
			sb.WriteString(
				"; Synway/GSM gateway compatibility: avoid dynamic RTP payloads\n" +
					"; and SIP extensions that this gateway answers inconsistently.\n" +
					"dtmf_mode=inband\n" +
					"preferred_codec_only=yes\n" +
					"timers=no\n" +
					"100rel=no\n",
			)
		}
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "[%s-auth](simson-auth-tpl)\nusername=%s\npassword=%s\n\n", endpointID, ep.Username, ep.Password)
		fmt.Fprintf(&sb, "[%s](simson-aor-tpl)\n\n", aorName)
	}

	if len(trustedGatewayIPs) > 0 && !enableAnonymousIngress {
		aors := gatewayAORList(endpoints)
		if aors != "" {
			sb.WriteString("[simson-trusted-gateway-in](simson-gateway-in-tpl)\n")
			sb.WriteString("aors=" + aors + "\n\n")
			sb.WriteString("[simson-trusted-gateway-in-identify]\ntype=identify\nendpoint=simson-trusted-gateway-in\n")
			for _, ip := range trustedGatewayIPs {
				sb.WriteString("match=" + ip + "\n")
			}
			sb.WriteString("\n")
		}
	}

	return os.WriteFile(filepath.Join(dir, "simson.conf"), []byte(sb.String()), 0640)
}

// ---- extensions.conf --------------------------------------------------------

func writeHTTPConf(root string) error {
	dirName := detectSnippetDirName(root, "http.conf", []string{"http.conf.d", "http.d"}, "http.conf.d")
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := ensureInclude(
		filepath.Join(root, "http.conf"),
		dirName+"/*.conf",
	); err != nil {
		return err
	}

	content := `; Auto-generated by Simson VPS server — do not edit manually.
;
; Asterisk exposes SIP-over-WebSocket at ws://127.0.0.1:8088/ws.
; Caddy terminates TLS and proxies wss://<domain>/sip/ws to this listener.
[general]
enabled=yes
bindaddr=127.0.0.1
bindport=8088
`

	return os.WriteFile(filepath.Join(dir, "simson.conf"), []byte(content), 0640)
}

// ---- confbridge.conf --------------------------------------------------------

func writeConfBridgeConf(root string) error {
	dirName := detectSnippetDirName(root, "confbridge.conf", []string{"confbridge.conf.d", "confbridge.d"}, "confbridge.conf.d")
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := ensureInclude(
		filepath.Join(root, "confbridge.conf"),
		dirName+"/*.conf",
	); err != nil {
		return err
	}

	content := `; Auto-generated by Simson VPS server — do not edit manually.

; Bridge profile — shared settings for all Simson ConfBridge rooms.
[simson_bridge]
type=bridge
max_members=10
record_conference=no
video_mode=none
internal_sample_rate=8000
mixing_interval=20

; User profile — applied to every participant in a Simson ConfBridge.
; RTP NAT bindings are maintained by the endpoint-level rtp_keepalive setting.
; Do not add another jitter buffer here: every real media channel receives one
; adaptive buffer in the dialplan. Do not inject hold music while a participant
; is alone because it can leak ringback/hold audio across bridge transitions.
[simson_user]
type=user
quiet=yes
announce_join_leave=no
announce_only_user=no
wait_marked=no
end_marked=no
music_on_hold_when_empty=no

; Advanced-route ingress profile. The caller has already reached the PBX, so
; provide audible waiting audio while the landing phone and later stages ring.
; Ordinary direct calls continue to use simson_user and never receive this MOH.
[simson_waiting_user]
type=user
quiet=yes
announce_join_leave=no
announce_only_user=no
wait_marked=no
end_marked=no
music_on_hold_when_empty=yes
music_on_hold_class=default
`

	return os.WriteFile(filepath.Join(dir, "simson.conf"), []byte(content), 0640)
}

// ---- rtp.conf ---------------------------------------------------------------

// writeRTPConf writes rtp.conf with correct ICE host-candidate mapping so
// Asterisk advertises its public IP (externalIP) in WebRTC ICE candidates
// instead of the private RFC-1918 interface address, which is unreachable
// from browsers on external networks.
func writeRTPConf(root, externalIP, sipDomain string) error {
	ip := strings.TrimSpace(externalIP)
	if ip == "" {
		ip = resolveExternalIPFromDomain(sipDomain)
	}
	if ip == "" {
		return nil // cannot determine external IP — leave rtp.conf untouched
	}

	// Determine the private IP of the primary network interface so we can
	// build the ice_host_candidates override.
	privateIP := localIPForICE()

	var sb strings.Builder
	sb.WriteString("; Auto-generated by Simson VPS server — do not edit manually.\n")
	sb.WriteString("[general]\n")
	sb.WriteString("rtpstart=10000\n")
	sb.WriteString("rtpend=20000\n")
	sb.WriteString("icesupport=true\n")
	sb.WriteString("stunaddr=stun.l.google.com:19302\n")
	sb.WriteString("\n")
	if privateIP != "" && privateIP != ip {
		// Map the private interface address to the public IP so Asterisk
		// includes the public IP in WebRTC ICE candidates.  Without this,
		// Asterisk would only advertise the 10.x.x.x address which is
		// unreachable from browsers on external networks.
		sb.WriteString("[ice_host_candidates]\n")
		fmt.Fprintf(&sb, "%s => %s\n", privateIP, ip)
	}

	return os.WriteFile(filepath.Join(root, "rtp.conf"), []byte(sb.String()), 0640)
}

// localIPForICE returns the primary private IPv4 address of the machine
// (the one used for outbound connections). Falls back to empty string on error.
func localIPForICE() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
}

// ---- extensions.conf --------------------------------------------------------

func writeDialplanConf(root, inCtx, nodeCtx, outCtx, defaultPSTNTrunk string, noAuthInboundExtensions []string, endpoints []SIPEndpointDef) error {
	dirName := detectSnippetDirName(root, "extensions.conf", []string{"extensions.d", "extensions.conf.d"}, "extensions.d")
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := ensureSimsonIncludeBase(root, "extensions.conf", dirName); err != nil {
		return err
	}

	// Safety fallbacks
	if inCtx == "" {
		inCtx = "from-simson-sip"
	}
	if nodeCtx == "" {
		nodeCtx = "from-simson-node"
	}
	if outCtx == "" {
		outCtx = "from-simson-out"
	}

	supervisionRoutes := buildSupervisionDialplan(endpoints)
	advancedIngressRoutes := buildAdvancedIngressDialplan(endpoints)
	directEndpointRoutes := buildDirectEndpointDialplan(endpoints)
	autoAnswerExtensionRoutes := buildAutoAnswerExtensionDialplan(endpoints)
	accountTransferRoutes := buildAccountTransferDialplan(endpoints)
	anonymousRoutes := buildAnonymousInboundDialplan(noAuthInboundExtensions, endpoints)
	blfHints := buildBLFHintDialplan(endpoints)

	content := fmt.Sprintf(
		`; Auto-generated by Simson VPS server — do not edit manually.
;
; Architecture:
;   [%s]  — IP phones call numbers here → Asterisk fires UserEvent:SimsonRoute
;              → Go VPS server routes to the correct Simson WebSocket node
;              → audio is held in a ConfBridge room until the node's SIP UA joins
;   [%s] — Simson nodes join the ConfBridge room (extension = bridge ID)
;              e.g. PJSIP/node-my-pi dials bridge-<uniqueid> here
;   [%s]  — Simson-originated PSTN/landline calls through SIMSON_TRUNK
;
[%s]
; Direct registered SIP endpoint routes.
; If a SIP endpoint has no RouteTo node, it behaves like a normal PBX extension:
; a registered phone dialing it should ring that phone directly. Endpoints with
; RouteTo set are ingress/routing endpoints and continue through SimsonRoute.
%s%s
; Explicit HAOS-card bypass. A live advanced route may use 100 as its
; source-phone trigger; *100 always skips that plan and rings the HAOS card.
exten => *100,1,NoOp(Simson: explicit HAOS card bypass from ${CALLERID(num)})
 same  => n,Set(SIMSON_BRIDGE_ID=bridge-${UNIQUEID})
 same  => n,Set(JITTERBUFFER(adaptive)=default)
 same  => n,UserEvent(SimsonRoute,Extension: ${EXTEN},Caller: ${CALLERID(num)},CallerEndpoint: ${CHANNEL(pjsip,endpoint)},UniqueID: ${UNIQUEID},Bridge: ${SIMSON_BRIDGE_ID},Channel: ${CHANNEL})
 same  => n,ConfBridge(${SIMSON_BRIDGE_ID},simson_bridge,simson_user)
 same  => n,Hangup()

; SIP-phone outside dialing is intentionally routed through the catch-all
; SimsonRoute event below. The VPS then chooses an enabled gateway trunk scoped
; to the caller's account/site instead of hardwiring a global default trunk.
; Catch-all: route every incoming SIP call to the Simson control plane.
exten => _+X.,1,NoOp(Simson: incoming E.164 SIP call to ${EXTEN} from ${CALLERID(num)})
 same  => n,Set(SIMSON_BRIDGE_ID=bridge-${UNIQUEID})
 same  => n,Set(JITTERBUFFER(adaptive)=default)
 same  => n,UserEvent(SimsonRoute,Extension: ${EXTEN},Caller: ${CALLERID(num)},CallerEndpoint: ${CHANNEL(pjsip,endpoint)},UniqueID: ${UNIQUEID},Bridge: ${SIMSON_BRIDGE_ID},Channel: ${CHANNEL})
 same  => n,ConfBridge(${SIMSON_BRIDGE_ID},simson_bridge,simson_user)
 same  => n,Hangup()

exten => _X.,1,NoOp(Simson: incoming call to ${EXTEN} from ${CALLERID(num)})
 same  => n,Set(SIMSON_BRIDGE_ID=bridge-${UNIQUEID})
 same  => n,Set(JITTERBUFFER(adaptive)=default)
 same  => n,UserEvent(SimsonRoute,Extension: ${EXTEN},Caller: ${CALLERID(num)},CallerEndpoint: ${CHANNEL(pjsip,endpoint)},UniqueID: ${UNIQUEID},Bridge: ${SIMSON_BRIDGE_ID},Channel: ${CHANNEL})
 same  => n,ConfBridge(${SIMSON_BRIDGE_ID},simson_bridge,simson_user)
 same  => n,Hangup()

; Voicemail / no answer fallback.
exten => i,1,Hangup(21)
exten => t,1,Hangup(16)

[%s]
; Simson node SIP UA dials the bridge ID as the extension to join the audio path.
exten => _bridge-.,1,NoOp(Simson node joining bridge ${EXTEN})
 same  => n,Answer()
 same  => n,Set(JITTERBUFFER(adaptive)=default)
 same  => n,ConfBridge(${EXTEN},simson_bridge,simson_user)
 same  => n,Hangup()

; extension "s" — for Originate from VPS (answer + wait to be bridged)
exten => s,1,NoOp(Simson originate leg)
 same  => n,Answer()
 same  => n,Set(JITTERBUFFER(adaptive)=default)
 same  => n,Wait(${SIMSON_WAIT_TIMEOUT:=120})
 same  => n,Hangup()

[from-simson-extension]
; VPS-originated calls/transfers to onsite SIP phones.
; The Local channel answers only when the SIP phone answers, then AMI places
; that Local leg into the requested Simson ConfBridge room.
%s
exten => _X.,1,NoOp(Simson dial SIP endpoint ${EXTEN})
 same  => n,Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=120},rTb(simson-outbound-mark^s^1(${SIMSON_CALL_ID})))
 same  => n,Hangup()

[from-simson-door]
; Face-recognition webhook callback: call the outdoor SIP station first. The
; station must auto-answer callback calls so its camera media becomes the first
; bridge leg. Once answered, ring the configured indoor SIP phone directly.
; This is intentionally a plain Dial bridge rather than ConfBridge so H.264
; video can negotiate end-to-end between compatible SIP devices.
exten => _X.,1,NoOp(Simson door camera bridge to SIP endpoint ${EXTEN})
 same  => n,Set(__SIMSON_CALL_ID=${SIMSON_CALL_ID})
 ; Do not force local ringback here. Door stations and video monitors may use
 ; SIP early media / video preview; the "r" Dial option suppresses that path.
 same  => n,Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},T)
 same  => n,Hangup()

[from-simson-callback-source]
; Caller-side intercom bridge: Simson calls the original caller phone back as
; a fresh called leg. This is the reliable way to request caller-side
; auto-answer/speaker, because SIP cannot force speaker on an already-originated
; caller handset.
exten => _X.,1,NoOp(Simson callback bridge source ${EXTEN})
 same  => n,Set(__SIMSON_CALL_ID=${SIMSON_CALL_ID})
 same  => n,Set(SIMSON_DIAL_OPTIONS=T)
 same  => n,GotoIf($["${SIMSON_SOURCE_AUTO_MODE}" = ""]?dial)
 same  => n,Set(SIMSON_DIAL_OPTIONS=Tb(simson-auto-answer^s^1(${SIMSON_SOURCE_AUTO_MODE})))
 same  => n(dial),Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},${SIMSON_DIAL_OPTIONS})
 same  => n,Hangup()

[from-simson-callback-target]
; After the caller callback leg answers, ring the requested target phone in a
; plain SIP bridge so normal audio/video negotiation stays native.
exten => _X.,1,NoOp(Simson callback bridge target ${EXTEN})
 same  => n,Set(__SIMSON_CALL_ID=${SIMSON_CALL_ID})
 same  => n,GotoIf($["${SIMSON_TARGET_LEG_CALLER_NUM}" = ""]?caller-ready)
 same  => n,Set(CALLERID(num)=${SIMSON_TARGET_LEG_CALLER_NUM})
 same  => n,GotoIf($["${SIMSON_TARGET_LEG_CALLER_NAME}" = ""]?caller-ready)
 same  => n,Set(CALLERID(name)=${SIMSON_TARGET_LEG_CALLER_NAME})
 same  => n(caller-ready),ExecIf($["${SIMSON_PRE_RING_ANNOUNCEMENT}" != ""]?Playback(${SIMSON_PRE_RING_ANNOUNCEMENT}))
 same  => n,Set(SIMSON_DIAL_OPTIONS=T)
 same  => n,GotoIf($["${SIMSON_TARGET_AUTO_MODE}" = ""]?dial)
 same  => n,Set(SIMSON_DIAL_OPTIONS=Tb(simson-auto-answer^s^1(${SIMSON_TARGET_AUTO_MODE})))
 same  => n,NoOp(Simson callback target caller ${CALLERID(all)})
 same  => n(dial),ExecIf($[${SIMSON_MAX_CONNECTED_MS} > 0]?Set(SIMSON_DIAL_OPTIONS=${SIMSON_DIAL_OPTIONS}L(${SIMSON_MAX_CONNECTED_MS})))
 same  => n,Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},${SIMSON_DIAL_OPTIONS})
 same  => n,Hangup()

[from-simson-callback-target-first]
; Speaker callback bridge variant: answer the target first, then let that
; answered SIP leg call the original source phone back with intercom headers.
exten => _X.,1,NoOp(Simson callback bridge target-first ${EXTEN})
 same  => n,Set(__SIMSON_CALL_ID=${SIMSON_CALL_ID})
 same  => n,GotoIf($["${SIMSON_TARGET_LEG_CALLER_NUM}" = ""]?caller-ready)
 same  => n,Set(CALLERID(num)=${SIMSON_TARGET_LEG_CALLER_NUM})
 same  => n,GotoIf($["${SIMSON_TARGET_LEG_CALLER_NAME}" = ""]?caller-ready)
 same  => n,Set(CALLERID(name)=${SIMSON_TARGET_LEG_CALLER_NAME})
 same  => n(caller-ready),Set(SIMSON_DIAL_OPTIONS=T)
 same  => n,GotoIf($["${SIMSON_TARGET_AUTO_MODE}" = ""]?dial)
 same  => n,Set(SIMSON_DIAL_OPTIONS=Tb(simson-auto-answer^s^1(${SIMSON_TARGET_AUTO_MODE})))
 same  => n(dial),Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},${SIMSON_DIAL_OPTIONS})
 same  => n,Hangup()

[from-simson-callback-source-after-target]
; After the target leg answers, ring the original caller as the called leg.
; This matches the normal SIP-to-SIP intercom flow more closely for phones that
; ignore speaker hints on the first AMI-originated callback leg.
exten => _X.,1,NoOp(Simson callback bridge source after target ${EXTEN})
 same  => n,Set(__SIMSON_CALL_ID=${SIMSON_CALL_ID})
 same  => n,GotoIf($["${SIMSON_SOURCE_LEG_CALLER_ID}" = ""]?caller-ready)
 same  => n,Set(CALLERID(all)=${SIMSON_SOURCE_LEG_CALLER_ID})
 same  => n(caller-ready),Set(SIMSON_DIAL_OPTIONS=T)
 same  => n,GotoIf($["${SIMSON_SOURCE_AUTO_MODE}" = ""]?dial)
 same  => n,Set(SIMSON_DIAL_OPTIONS=Tb(simson-auto-answer^s^1(${SIMSON_SOURCE_AUTO_MODE})))
 same  => n(dial),Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=30},${SIMSON_DIAL_OPTIONS})
 same  => n,Hangup()

[%s]
; Configured outbound landline/PSTN targets.
; The VPS originates Local/<number>@%s and passes SIMSON_TRUNK.
exten => _X.,1,NoOp(Simson outbound trunk call ${EXTEN} via ${SIMSON_TRUNK})
 same  => n,GotoIf($["${SIMSON_TRUNK}" = ""]?missing-trunk,1)
 same  => n,Set(JITTERBUFFER(adaptive)=default)
 same  => n,Set(SIMSON_DIAL_TARGET=${EXTEN}${SIMSON_DIAL_SUFFIX})
 same  => n,Set(SIMSON_DIAL_OPTIONS=rTb(simson-outbound-mark^s^1(${SIMSON_CALL_ID})))
 same  => n,GotoIf($["${SIMSON_POST_ANSWER_DTMF}" = ""]?dial)
 same  => n,Set(SIMSON_DIAL_OPTIONS=${SIMSON_DIAL_OPTIONS}U(simson-outbound-postanswer^${SIMSON_POST_ANSWER_DTMF}))
 same  => n(dial),Dial(PJSIP/${SIMSON_DIAL_TARGET}@${SIMSON_TRUNK},${SIMSON_WAIT_TIMEOUT:=120},${SIMSON_DIAL_OPTIONS})
 same  => n,Hangup()

exten => missing-trunk,1,NoOp(Simson outbound trunk call missing SIMSON_TRUNK)
 same  => n,Congestion(5)
 same  => n,Hangup(21)

[simson-outbound-postanswer]
exten => s,1,NoOp(Simson outbound gateway post-answer DTMF ${ARG1})
 same  => n,GotoIf($["${ARG1}" = ""]?done)
 same  => n,Wait(0.2)
 same  => n,SendDTMF(${ARG1})
 same  => n(done),Return()

[simson-gateway-announcement]
exten => s,1,NoOp(Simson inbound gateway welcome announcement ${ARG1})
 same  => n,GotoIf($["${ARG1}" = ""]?builtin)
 same  => n,Progress()
 same  => n,TryExec(Playback(${ARG1},noanswer))
 same  => n,Return()
 same  => n(builtin),Progress()
 same  => n,TryExec(Playback(queue-thankyou&one-moment-please&pls-hold-while-try,noanswer))
 same  => n,Return()

[simson-auto-answer]
exten => s,1,NoOp(Add Simson SIP auto-answer headers mode=${ARG1})
 ; Different SIP phones listen for different auto-answer/intercom hints. Keep
 ; this as a conservative superset on the called leg only.
 same  => n,GotoIf($["${ARG1}" = "speaker"]?speaker)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=<http://www.notused.com>\;info=alert-autoanswer)
 same  => n,Set(PJSIP_HEADER(add,Call-Info)=<sip:simson>\;answer-after=0)
 same  => n,Set(PJSIP_HEADER(add,Answer-Mode)=Auto)
 same  => n,Set(PJSIP_HEADER(add,Priv-Answer-Mode)=Auto)
 same  => n,Set(PJSIP_HEADER(add,P-Auto-Answer)=normal)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=Auto Answer)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=answer-after=0)
 same  => n,Goto(done)
 same  => n(speaker),Set(PJSIP_HEADER(add,Alert-Info)=<http://www.notused.com>\;info=alert-autoanswer)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=Auto Answer)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=answer-after=0)
 same  => n,Set(PJSIP_HEADER(add,Call-Info)=answer-after=0)
 same  => n,Set(PJSIP_HEADER(add,P-Auto-Answer)=normal)
 same  => n,Set(PJSIP_HEADER(add,Answer-After)=0)
 same  => n,Set(PJSIP_HEADER(add,Auto-Answer)=true)
 same  => n,Set(PJSIP_HEADER(add,Answer-Mode)=Auto)
 same  => n,Set(PJSIP_HEADER(add,Priv-Answer-Mode)=Auto)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=<http://www.notused.com>\;info=intercom)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=info=intercom)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=Intercom)
 same  => n,Set(PJSIP_HEADER(add,Alert-Info)=intercom)
 same  => n,Set(PJSIP_HEADER(add,Call-Info)=<sip:simson>\;answer-after=0\;intercom=true)
 same  => n,Set(PJSIP_HEADER(add,P-Auto-Answer)=intercom)
 same  => n(done),Return()

[simson-extension-predial]
exten => s,1,NoOp(Mark Simson extension leg and optionally add auto-answer headers)
 same  => n,Gosub(simson-outbound-mark^s^1(${ARG1}))
 same  => n,ExecIf($["${SIMSON_BLINDXFER_CODE}" != ""]?Set(FEATUREMAP(blindxfer)=${SIMSON_BLINDXFER_CODE}))
 same  => n,GotoIf($["${ARG2}" = ""]?done)
 same  => n,Gosub(simson-auto-answer^s^1(${ARG2}))
 same  => n(done),Return()

[simson-account-conference]
; G() sends the dialing channel to priority 1 and the answered channel to
; priority 2. Both then enter the same room at priority 2.
exten => _feature-.,1,NoOp(Simson account conference ${EXTEN})
 same  => n,ConfBridge(${EXTEN},simson_bridge,simson_user)
 same  => n,Hangup()

[simson-direct-conference]
; The invited handset joins an already active basic SIP bridge through
; ChanSpy barge mode. q suppresses announcements and E exits with the source.
exten => s,1,NoOp(Simson direct SIP conference into ${SIMSON_SPY_CHANNEL})
 same  => n,GotoIf($["${SIMSON_SPY_CHANNEL}" = ""]?invalid)
 same  => n,ChanSpy(${SIMSON_SPY_CHANNEL},qBE)
 same  => n,Hangup()
 same  => n(invalid),Hangup(21)

[simson-direct-supervision]
; Invited active-call participant. Listen is silent, whisper talks only to the
; inviting channel, and barge joins both directions. E exits with the source.
exten => s,1,NoOp(Simson direct supervision ${SIMSON_SPY_MODE} into ${SIMSON_SPY_CHANNEL})
 same  => n,GotoIf($["${SIMSON_SPY_CHANNEL}" = ""]?invalid)
 same  => n,GotoIf($["${SIMSON_SPY_MODE}" = "listen"]?listen)
 same  => n,GotoIf($["${SIMSON_SPY_MODE}" = "whisper"]?whisper)
 same  => n,GotoIf($["${SIMSON_SPY_MODE}" = "barge"]?barge)
 same  => n(invalid),Hangup(21)
 same  => n(listen),ChanSpy(${SIMSON_SPY_CHANNEL},qE)
 same  => n,Hangup()
 same  => n(whisper),ChanSpy(${SIMSON_SPY_CHANNEL},qwE)
 same  => n,Hangup()
 same  => n(barge),ChanSpy(${SIMSON_SPY_CHANNEL},qBE)
 same  => n,Hangup()

[simson-direct-observer-answer]
; Called-channel U() hook used only for live-state observation. It does not
; answer early, alter media, or move either endpoint out of the native bridge.
exten => s,1,UserEvent(SimsonDirectCall,Phase: active,CallID: ${ARG1},AccountID: ${ARG4},Source: ${ARG2},Target: ${ARG3},Channel: ${CHANNEL})
 same  => n,Return()

[simson-outbound-mark]
exten => s,1,NoOp(Mark Simson outbound child channel ${ARG1})
 same  => n,Set(SIMSON_CALL_ID=${ARG1})
 same  => n,Set(JITTERBUFFER(adaptive)=default)
 same  => n,Return()

[from-simson-anonymous]
; Locked-down ingress for gateways that cannot digest-auth inbound INVITEs.
; Only explicitly configured extensions are accepted here.
%s
exten => _X.,1,Hangup(21)
exten => i,1,Hangup(21)
exten => t,1,Hangup(16)

[simson-blf]
; BLF/presence hints for desk phones that subscribe to extension state.
%s
%s
`, inCtx, nodeCtx, outCtx, inCtx, supervisionRoutes, advancedIngressRoutes+directEndpointRoutes, nodeCtx, autoAnswerExtensionRoutes, outCtx, outCtx, anonymousRoutes, blfHints, accountTransferRoutes)

	return os.WriteFile(filepath.Join(dir, "simson.conf"), []byte(content), 0640)
}

// ---- module reload ----------------------------------------------------------

func reloadModules(log *logging.Logger) error {
	cmds := []string{
		"manager reload",
		"pjsip reload",
		"dialplan reload",
		"module reload app_confbridge.so",
		"module reload res_http_websocket.so",
		"module reload res_pjsip_transport_websocket.so",
	}
	anyFailed := false
	for _, cmd := range cmds {
		out, err := exec.Command("asterisk", "-rx", cmd).CombinedOutput()
		if err != nil {
			// Non-fatal: CLI socket may be unavailable when the service runs
			// sandboxed. The server will reload via AMI once connected.
			log.Debug("asterisk cli reload skipped (will reload via AMI)",
				map[string]any{"cmd": cmd, "err": err.Error()})
			anyFailed = true
			continue
		}
		log.Debug("asterisk reload", map[string]any{"cmd": cmd, "output": strings.TrimSpace(string(out))})
	}
	if anyFailed {
		log.Info("asterisk configs written; CLI reload unavailable, will reload via AMI", nil)
	}
	return nil
}

func appendTransportNATConfig(sb *strings.Builder, externalIP string) {
	ip := strings.TrimSpace(externalIP)
	if ip == "" {
		return
	}
	sb.WriteString("external_media_address=" + ip + "\n")
	sb.WriteString("external_signaling_address=" + ip + "\n")
	sb.WriteString("local_net=127.0.0.0/8\nlocal_net=10.0.0.0/8\nlocal_net=172.16.0.0/12\nlocal_net=192.168.0.0/16\n")
}

func resolveExternalIPFromDomain(domain string) string {
	host := strings.TrimSpace(domain)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ""
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && !v4.IsPrivate() {
			return v4.String()
		}
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

func normalizeIPList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		ip := strings.TrimSpace(value)
		if ip == "" {
			continue
		}
		if parsed := net.ParseIP(ip); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				ip = v4.String()
			} else {
				ip = parsed.String()
			}
		}
		if strings.Contains(ip, "/") {
			ip = strings.TrimSpace(ip)
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func gatewayAORList(endpoints []SIPEndpointDef) string {
	seen := map[string]struct{}{}
	aors := []string{}
	for _, ep := range endpoints {
		if !ep.Enabled {
			continue
		}
		aor := sanitizeID(ep.Username)
		if aor == "" {
			aor = sanitizeID(ep.Extension)
		}
		if aor == "" {
			aor = sanitizeID(ep.ID)
		}
		if aor == "" {
			continue
		}
		if _, ok := seen[aor]; ok {
			continue
		}
		seen[aor] = struct{}{}
		aors = append(aors, aor)
	}
	return strings.Join(aors, ",")
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = sanitizeID(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		out[value] = struct{}{}
	}
	return out
}

func buildAnonymousInboundDialplan(extensions []string, endpoints []SIPEndpointDef) string {
	ivrByExt := map[string]string{}
	advancedIngress := map[string]bool{}
	for _, ep := range endpoints {
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if ext == "" {
			continue
		}
		advancedIngress[ext] = ep.AdvancedIngress
		if ep.GatewayIVREnabled {
			ivrByExt[ext] = sanitizeSoundName(ep.GatewayIVRSound)
		}
	}
	seen := map[string]struct{}{}
	var sb strings.Builder
	for _, ext := range extensions {
		ext = sanitizeID(strings.TrimSpace(ext))
		if ext == "" {
			continue
		}
		if _, ok := seen[ext]; ok {
			continue
		}
		seen[ext] = struct{}{}
		fmt.Fprintf(&sb, "exten => %s,1,NoOp(Simson anonymous gateway call to ${EXTEN} from ${CALLERID(num)})\n", ext)
		sb.WriteString(" same  => n,Set(SIMSON_BRIDGE_ID=bridge-${UNIQUEID})\n")
		sb.WriteString(" same  => n,UserEvent(SimsonRoute,Extension: ${EXTEN},Caller: ${CALLERID(num)},CallerEndpoint: ${CHANNEL(pjsip,endpoint)},GatewaySource: ${EXTEN},UniqueID: ${UNIQUEID},Bridge: ${SIMSON_BRIDGE_ID},Channel: ${CHANNEL})\n")
		if sound, ok := ivrByExt[ext]; ok {
			fmt.Fprintf(&sb, " same  => n,Gosub(simson-gateway-announcement,s,1(%s))\n", sound)
		}
		profile := "simson_user"
		if advancedIngress[ext] {
			profile = "simson_waiting_user"
		}
		fmt.Fprintf(&sb, " same  => n,ConfBridge(${SIMSON_BRIDGE_ID},simson_bridge,%s)\n", profile)
		sb.WriteString(" same  => n,Hangup()\n")
	}
	return sb.String()
}

// buildAdvancedIngressDialplan emits exact routes before the generic catch-all.
// These channels use an audible waiting profile while the server executes the
// configured landing/fallback plan. Keeping this exact and account-generated
// avoids changing media behavior for every other SIP call.
func buildAdvancedIngressDialplan(endpoints []SIPEndpointDef) string {
	seen := map[string]struct{}{}
	var sb strings.Builder
	for _, ep := range endpoints {
		if !ep.Enabled || !ep.AdvancedIngress {
			continue
		}
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if ext == "" || isReservedGatewayExtension(ext) {
			continue
		}
		if _, ok := seen[ext]; ok {
			continue
		}
		seen[ext] = struct{}{}
		fmt.Fprintf(&sb, "exten => %s,1,NoOp(Simson advanced landing call ${CALLERID(num)} -> ${EXTEN})\n", ext)
		sb.WriteString(" same  => n,Set(SIMSON_BRIDGE_ID=bridge-${UNIQUEID})\n")
		sb.WriteString(" same  => n,Set(JITTERBUFFER(adaptive)=default)\n")
		sb.WriteString(" same  => n,UserEvent(SimsonRoute,Extension: ${EXTEN},Caller: ${CALLERID(num)},CallerEndpoint: ${CHANNEL(pjsip,endpoint)},UniqueID: ${UNIQUEID},Bridge: ${SIMSON_BRIDGE_ID},Channel: ${CHANNEL})\n")
		sb.WriteString(" same  => n,ConfBridge(${SIMSON_BRIDGE_ID},simson_bridge,simson_waiting_user)\n")
		sb.WriteString(" same  => n,Hangup()\n")
	}
	return sb.String()
}

func sanitizeSoundName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var sb strings.Builder
	for _, r := range value {
		if r == '/' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func buildSIPPhoneOutboundDialplan(defaultTrunk string) string {
	trunk := sanitizeID(defaultTrunk)
	if trunk == "" {
		return "; No default PSTN trunk configured.\n"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "exten => _+%s91XXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk, trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN:%d}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", len(trunk)+3, trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	fmt.Fprintf(&sb, "exten => _+%sXXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk, trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN:%d}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", len(trunk)+1, trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	fmt.Fprintf(&sb, "exten => _%s91XXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk, trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN:%d}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", len(trunk)+2, trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	fmt.Fprintf(&sb, "exten => _%sXXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk, trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN:%d}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", len(trunk), trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	fmt.Fprintf(&sb, "exten => _+91XXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN:3}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	fmt.Fprintf(&sb, "exten => _+XXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN:1}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	fmt.Fprintf(&sb, "exten => _91XXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN:2}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	fmt.Fprintf(&sb, "exten => _0XXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN:1}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	fmt.Fprintf(&sb, "exten => _XXXXXXXXXX,1,NoOp(SIP phone outside call ${CALLERID(num)} -> ${EXTEN} via %s)\n", trunk)
	fmt.Fprintf(&sb, " same  => n,Dial(PJSIP/${EXTEN}@%s,${SIMSON_WAIT_TIMEOUT:=120},rT)\n", trunk)
	sb.WriteString(" same  => n,Hangup()\n")
	return sb.String()
}

func buildDirectEndpointDialplan(endpoints []SIPEndpointDef) string {
	seen := map[string]struct{}{}
	autoAnswer := map[string]SIPEndpointDef{}
	for _, ep := range endpoints {
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if ext != "" && ep.AutoAnswer {
			autoAnswer[ext] = ep
		}
	}
	var sb strings.Builder
	for _, ep := range endpoints {
		if !ep.Enabled || strings.TrimSpace(ep.RouteTo) != "" || ep.AdvancedIngress {
			continue
		}
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if ext == "" {
			continue
		}
		if isReservedGatewayExtension(ext) {
			continue
		}
		if _, ok := seen[ext]; ok {
			continue
		}
		seen[ext] = struct{}{}
		fmt.Fprintf(&sb, "exten => %s,1,NoOp(Simson direct SIP endpoint ${CALLERID(num)} -> ${EXTEN})\n", ext)
		sb.WriteString(" same  => n,Set(SIMSON_CALL_ID=direct-${UNIQUEID})\n")
		sb.WriteString(" same  => n,Set(__SIMSON_CALL_ID=${SIMSON_CALL_ID})\n")
		fmt.Fprintf(&sb, " same  => n,UserEvent(SimsonDirectCall,Phase: ringing,CallID: ${SIMSON_CALL_ID},AccountID: %s,Source: ${CALLERID(num)},Target: ${EXTEN},Channel: ${CHANNEL})\n", sanitizeID(ep.AccountID))
		sb.WriteString(" same  => n,Set(JITTERBUFFER(adaptive)=default)\n")
		appendAccountTransferChannelVars(&sb, ep)
		appendCallerPreRingAnnouncement(&sb, ep.PreRingAnnouncement)
		targetAutoModePrepared := false
		if ep.CallbackBridge {
			if aa, ok := autoAnswer[ext]; ok {
				appendConditionalAutoAnswerMode(&sb, aa.AutoAnswerCallers, aa.AutoSpeaker, aa.AutoSpeakerCallers)
			} else {
				sb.WriteString(" same  => n,Set(SIMSON_AUTO_ANSWER_MODE=)\n")
			}
			targetAutoModePrepared = true
			appendConditionalCallbackBridge(&sb, ep.CallbackBridgeCallers, callbackSourceMode(ep), "${EXTEN}", false)
		}
		if aa, ok := autoAnswer[ext]; ok && !targetAutoModePrepared {
			appendConditionalAutoAnswerMode(&sb, aa.AutoAnswerCallers, aa.AutoSpeaker, aa.AutoSpeakerCallers)
		}
		// Apply one adaptive buffer to the called RTP leg too. The inbound
		// caller received its buffer above, so each direction is protected
		// without stacking a second ConfBridge jitter buffer.
		sb.WriteString(" same  => n,Set(SIMSON_DIAL_OPTIONS=Ttb(simson-extension-predial^s^1(${SIMSON_CALL_ID}^)))\n")
		sb.WriteString(" same  => n,GotoIf($[\"${SIMSON_AUTO_ANSWER_MODE}\" = \"\"]?simson-dial)\n")
		sb.WriteString(" same  => n,Set(SIMSON_DIAL_OPTIONS=Ttb(simson-extension-predial^s^1(${SIMSON_CALL_ID}^${SIMSON_AUTO_ANSWER_MODE})))\n")
		appendCalledPartyAnnouncement(&sb, ep.AnswerAnnouncement)
		appendCallDurationRules(&sb, ep.CallDurationRules)
		fmt.Fprintf(&sb, " same  => n,Set(SIMSON_DIAL_OPTIONS=${SIMSON_DIAL_OPTIONS}U(simson-direct-observer-answer^${SIMSON_CALL_ID}^${CALLERID(num)}^${EXTEN}^%s))\n", sanitizeID(ep.AccountID))
		sb.WriteString(" same  => n,Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=60},${SIMSON_DIAL_OPTIONS})\n")
		fmt.Fprintf(&sb, " same  => n,UserEvent(SimsonDirectCall,Phase: ended,CallID: ${SIMSON_CALL_ID},AccountID: %s,Source: ${CALLERID(num)},Target: ${EXTEN},Channel: ${CHANNEL},DialStatus: ${DIALSTATUS})\n", sanitizeID(ep.AccountID))
		sb.WriteString(" same  => n,Hangup()\n")
		if ep.CallbackBridge {
			fmt.Fprintf(&sb, "exten => *%s,1,NoOp(Simson callback feature code ${CALLERID(num)} -> %s)\n", ext, ext)
			if aa, ok := autoAnswer[ext]; ok {
				appendConditionalAutoAnswerMode(&sb, aa.AutoAnswerCallers, aa.AutoSpeaker, aa.AutoSpeakerCallers)
			} else {
				sb.WriteString(" same  => n,Set(SIMSON_AUTO_ANSWER_MODE=)\n")
			}
			appendConditionalCallbackBridge(&sb, ep.CallbackBridgeCallers, callbackSourceMode(ep), ext, true)
			sb.WriteString(" same  => n,Hangup(21)\n")
		}
	}
	appendAccountConferenceRoutes(&sb, endpoints)
	return sb.String()
}

func normalizeAccountDialCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "*") {
		value = "*" + value
	}
	for _, r := range strings.TrimPrefix(value, "*") {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return value
}

func accountTransferContextName(accountID string) string {
	accountID = sanitizeID(strings.TrimSpace(accountID))
	if accountID == "" {
		return ""
	}
	return "simson-transfer-" + accountID
}

func appendAccountTransferChannelVars(sb *strings.Builder, ep SIPEndpointDef) {
	code := normalizeAccountDialCode(ep.AccountTransferCode)
	context := accountTransferContextName(ep.AccountID)
	if !ep.AccountFeaturesEnabled || code == "" || context == "" {
		sb.WriteString(" same  => n,Set(__SIMSON_BLINDXFER_CODE=)\n")
		sb.WriteString(" same  => n,Set(__TRANSFER_CONTEXT=)\n")
		return
	}
	fmt.Fprintf(sb, " same  => n,Set(__SIMSON_BLINDXFER_CODE=%s)\n", code)
	fmt.Fprintf(sb, " same  => n,Set(FEATUREMAP(blindxfer)=%s)\n", code)
	fmt.Fprintf(sb, " same  => n,Set(__TRANSFER_CONTEXT=%s)\n", context)
	fmt.Fprintf(sb, " same  => n,Set(TRANSFER_CONTEXT=%s)\n", context)
}

// buildAccountTransferDialplan confines blind-transfer destinations to the
// authenticated endpoint's account. Exact same-site SIP extensions are routed
// through the normal endpoint policy, while outside numbers can leave only via
// that account's explicitly selected default outbound gateway.
func buildAccountTransferDialplan(endpoints []SIPEndpointDef) string {
	type transferAccount struct {
		members map[string]struct{}
		trunk   string
		enabled bool
	}
	accounts := map[string]*transferAccount{}
	for _, ep := range endpoints {
		if !ep.Enabled || strings.TrimSpace(ep.AccountID) == "" {
			continue
		}
		accountID := strings.TrimSpace(ep.AccountID)
		account := accounts[accountID]
		if account == nil {
			account = &transferAccount{members: map[string]struct{}{}}
			accounts[accountID] = account
		}
		if ep.AccountFeaturesEnabled && normalizeAccountDialCode(ep.AccountTransferCode) != "" {
			account.enabled = true
		}
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if ext == "" {
			continue
		}
		if ep.DefaultOutbound && isReservedGatewayExtension(ext) {
			account.trunk = ext
		}
		if !isReservedGatewayExtension(ext) {
			account.members[ext] = struct{}{}
		}
	}

	accountIDs := make([]string, 0, len(accounts))
	for accountID, account := range accounts {
		if account.enabled && accountTransferContextName(accountID) != "" {
			accountIDs = append(accountIDs, accountID)
		}
	}
	sort.Strings(accountIDs)

	var sb strings.Builder
	for _, accountID := range accountIDs {
		account := accounts[accountID]
		context := accountTransferContextName(accountID)
		fmt.Fprintf(&sb, "\n[%s]\n", context)
		fmt.Fprintf(&sb, "; Account-scoped blind-transfer destinations for %s.\n", sanitizeID(accountID))
		members := make([]string, 0, len(account.members))
		for ext := range account.members {
			members = append(members, ext)
		}
		sort.Strings(members)
		for _, ext := range members {
			fmt.Fprintf(&sb, "exten => %s,1,NoOp(Simson same-site blind transfer to %s)\n", ext, ext)
			fmt.Fprintf(&sb, " same  => n,Goto(from-simson-sip,%s,1)\n", ext)
		}
		if account.trunk != "" {
			for _, pattern := range []string{"_+X.", "_X."} {
				fmt.Fprintf(&sb, "exten => %s,1,NoOp(Simson account outside blind transfer ${EXTEN} via %s)\n", pattern, account.trunk)
				sb.WriteString(" same  => n,Set(SIMSON_XFER_NUMBER=${FILTER(0-9,${EXTEN})})\n")
				sb.WriteString(" same  => n,GotoIf($[${LEN(${SIMSON_XFER_NUMBER})} < 7]?invalid)\n")
				fmt.Fprintf(&sb, " same  => n,Set(SIMSON_TRUNK=%s)\n", account.trunk)
				sb.WriteString(" same  => n,Set(SIMSON_CALL_ID=transfer-${UNIQUEID})\n")
				sb.WriteString(" same  => n,Goto(from-simson-out,${SIMSON_XFER_NUMBER},1)\n")
				sb.WriteString(" same  => n(invalid),Hangup(28)\n")
			}
		}
		sb.WriteString("exten => i,1,Hangup(21)\n")
		sb.WriteString("exten => t,1,Hangup(16)\n")
	}
	return sb.String()
}

func appendAccountConferenceRoutes(sb *strings.Builder, endpoints []SIPEndpointDef) {
	type outsideConferenceRoute struct {
		accountID string
		code      string
		trunk     string
		authExpr  string
	}
	members := map[string][]SIPEndpointDef{}
	conferenceCode := map[string]string{}
	defaultGateway := map[string]string{}
	for _, ep := range endpoints {
		if !ep.Enabled || ep.AccountID == "" {
			continue
		}
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if isReservedGatewayExtension(ext) {
			if ep.DefaultOutbound {
				defaultGateway[ep.AccountID] = ext
			}
			continue
		}
		members[ep.AccountID] = append(members[ep.AccountID], ep)
		if ep.AccountFeaturesEnabled {
			conferenceCode[ep.AccountID] = normalizeAccountDialCode(ep.AccountConferenceCode)
		}
	}
	outsideRoutes := make([]outsideConferenceRoute, 0, len(members))
	accountIDs := make([]string, 0, len(members))
	for accountID := range members {
		accountIDs = append(accountIDs, accountID)
	}
	sort.Strings(accountIDs)
	for _, accountID := range accountIDs {
		accountMembers := members[accountID]
		code := conferenceCode[accountID]
		if code == "" {
			continue
		}
		allowed := make([]string, 0, len(accountMembers))
		for _, source := range accountMembers {
			endpointName := sanitizeID(strings.TrimSpace(source.Username))
			if endpointName != "" {
				allowed = append(allowed, fmt.Sprintf("\"${CHANNEL(pjsip,endpoint)}\" = \"%s\"", endpointName))
			}
		}
		if len(allowed) == 0 {
			continue
		}
		authExpr := strings.Join(allowed, " | ")
		for _, target := range accountMembers {
			targetExt := sanitizeID(strings.TrimSpace(target.Extension))
			if targetExt == "" {
				continue
			}
			fmt.Fprintf(sb, "exten => %s%s,1,NoOp(Simson site conference launch ${CALLERID(num)} -> %s)\n", code, targetExt, targetExt)
			fmt.Fprintf(sb, " same  => n,GotoIf($[%s]?authorized)\n", authExpr)
			sb.WriteString(" same  => n,Hangup(21)\n")
			sb.WriteString(" same  => n(authorized),Set(SIMSON_CONF_ROOM=feature-${UNIQUEID})\n")
			fmt.Fprintf(sb, " same  => n,Dial(PJSIP/%s,30,G(simson-account-conference^${SIMSON_CONF_ROOM}^1))\n", targetExt)
			sb.WriteString(" same  => n,Hangup()\n")
		}

		// Exact SIP-extension routes above win over this pattern. Longer values
		// are treated as outside numbers and may leave only through this
		// account's explicitly selected default gateway.
		trunk := defaultGateway[accountID]
		if trunk != "" {
			outsideRoutes = append(outsideRoutes, outsideConferenceRoute{
				accountID: accountID, code: code, trunk: trunk, authExpr: authExpr,
			})
		}
	}

	// Accounts normally share the same feature prefix. Emit one wildcard per
	// prefix and branch by the authenticated source endpoint; duplicate Asterisk
	// pattern priorities would otherwise overwrite one another.
	routesByCode := map[string][]outsideConferenceRoute{}
	for _, route := range outsideRoutes {
		routesByCode[route.code] = append(routesByCode[route.code], route)
	}
	codes := make([]string, 0, len(routesByCode))
	for code := range routesByCode {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		routes := routesByCode[code]
		fmt.Fprintf(sb, "exten => _%sX.,1,NoOp(Simson account-authorized outside conference ${CALLERID(num)} -> ${EXTEN})\n", code)
		for i, route := range routes {
			fmt.Fprintf(sb, " same  => n,GotoIf($[%s]?outside-account-%d)\n", route.authExpr, i)
		}
		sb.WriteString(" same  => n,Hangup(21)\n")
		for i, route := range routes {
			fmt.Fprintf(sb, " same  => n(outside-account-%d),Set(SIMSON_CONF_NUMBER=${EXTEN:%d})\n", i, len(code))
			sb.WriteString(" same  => n,ExecIf($[${LEN(${SIMSON_CONF_NUMBER})} < 7]?Hangup(28))\n")
			sb.WriteString(" same  => n,Set(SIMSON_CONF_ROOM=feature-${UNIQUEID})\n")
			fmt.Fprintf(sb, " same  => n,Dial(PJSIP/${SIMSON_CONF_NUMBER}@%s,60,G(simson-account-conference^${SIMSON_CONF_ROOM}^1))\n", route.trunk)
			sb.WriteString(" same  => n,Hangup()\n")
		}
	}
}

type supervisionConfig struct {
	Enabled    bool     `json:"enabled"`
	Listen     bool     `json:"listen"`
	ListenKey  string   `json:"listen_key"`
	Whisper    bool     `json:"whisper"`
	WhisperKey string   `json:"whisper_key"`
	Barge      bool     `json:"barge"`
	BargeKey   string   `json:"barge_key"`
	Targets    []string `json:"targets"`
}

type supervisionRule struct {
	Supervisor string
	Target     string
	Mode       string
	Options    string
}

func buildSupervisionDialplan(endpoints []SIPEndpointDef) string {
	known := map[string]map[string]struct{}{}
	for _, ep := range endpoints {
		if !ep.Enabled {
			continue
		}
		account := strings.TrimSpace(ep.AccountID)
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if account == "" || ext == "" || isReservedGatewayExtension(ext) {
			continue
		}
		if known[account] == nil {
			known[account] = map[string]struct{}{}
		}
		known[account][ext] = struct{}{}
	}

	rules := map[string][]supervisionRule{}
	for _, ep := range endpoints {
		if !ep.Enabled || strings.TrimSpace(ep.SupervisionConfig) == "" {
			continue
		}
		var cfg supervisionConfig
		if err := json.Unmarshal([]byte(ep.SupervisionConfig), &cfg); err != nil || !cfg.Enabled {
			continue
		}
		supervisor := sanitizeID(strings.TrimSpace(ep.Extension))
		account := strings.TrimSpace(ep.AccountID)
		if supervisor == "" || account == "" {
			continue
		}
		modes := []struct {
			enabled bool
			key     string
			name    string
			options string
		}{
			{cfg.Listen, cfg.ListenKey, "listen", "qbE"},
			{cfg.Whisper, cfg.WhisperKey, "whisper", "qbwE"},
			{cfg.Barge, cfg.BargeKey, "barge", "qbBE"},
		}
		for _, targetRaw := range cfg.Targets {
			target := sanitizeID(strings.TrimSpace(targetRaw))
			if target == "" || target == supervisor {
				continue
			}
			if _, ok := known[account][target]; !ok {
				continue
			}
			for _, mode := range modes {
				key := normalizeSupervisionDialKey(mode.key)
				if !mode.enabled || key == "" {
					continue
				}
				dialed := key + target
				rules[dialed] = append(rules[dialed], supervisionRule{
					Supervisor: supervisor,
					Target:     target,
					Mode:       mode.name,
					Options:    mode.options,
				})
			}
		}
	}
	if len(rules) == 0 {
		return "; Call supervision is disabled for all SIP endpoints.\n"
	}

	// Some handsets reserve star-prefixed strings for local feature handling and
	// never send them to Asterisk. Publish a digits-only compatibility alias for
	// every exact supervision code; it retains the same endpoint authentication
	// and per-account target allowlist as the configured star code.
	aliases := make(map[string][]supervisionRule, len(rules))
	for dialed, dialRules := range rules {
		alias := strings.TrimPrefix(dialed, "*")
		if alias == dialed || alias == "" {
			continue
		}
		if _, exists := rules[alias]; exists {
			continue
		}
		aliases[alias] = append([]supervisionRule(nil), dialRules...)
	}
	for dialed, dialRules := range aliases {
		rules[dialed] = dialRules
	}

	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("; Account-scoped call supervision. Authorization uses an endpoint variable\n")
	sb.WriteString("; assigned by Asterisk, never caller ID supplied by the SIP device.\n")
	for _, dialed := range keys {
		fmt.Fprintf(&sb, "exten => %s,1,NoOp(Simson authorized call supervision dialed %s)\n", dialed, dialed)
		sb.WriteString(" same  => n,Set(SIMSON_SUPERVISOR=${SIMSON_ENDPOINT_ID})\n")
		sb.WriteString(" same  => n,ExecIf($[\"${SIMSON_SUPERVISOR}\" = \"\"]?Set(SIMSON_SUPERVISOR=${CHANNEL(pjsip,endpoint)}))\n")
		sb.WriteString(" same  => n,Set(SIMSON_CHANNEL_NAME=${CHANNEL(name)})\n")
		sb.WriteString(" same  => n,Set(SIMSON_CHANNEL_RESOURCE=${CUT(SIMSON_CHANNEL_NAME,/,2)})\n")
		sb.WriteString(" same  => n,Set(SIMSON_CHANNEL_ENDPOINT=${CUT(SIMSON_CHANNEL_RESOURCE,-,1)})\n")
		sb.WriteString(" same  => n,ExecIf($[\"${SIMSON_SUPERVISOR}\" = \"\"]?Set(SIMSON_SUPERVISOR=${SIMSON_CHANNEL_ENDPOINT}))\n")
		sb.WriteString(" same  => n,NoOp(Simson supervision authenticated endpoint ${SIMSON_SUPERVISOR})\n")
		for i, rule := range rules[dialed] {
			fmt.Fprintf(&sb, " same  => n,GotoIf($[\"${SIMSON_SUPERVISOR}\" = \"%s\"]?supervise-%d)\n", rule.Supervisor, i)
		}
		sb.WriteString(" same  => n,Hangup(21)\n")
		for i, rule := range rules[dialed] {
			fmt.Fprintf(&sb, " same  => n(supervise-%d),NoOp(Simson %s %s -> %s)\n", i, rule.Mode, rule.Supervisor, rule.Target)
			fmt.Fprintf(&sb, " same  => n,ChanSpy(PJSIP/%s-,%s)\n", rule.Target, rule.Options)
			sb.WriteString(" same  => n,Hangup()\n")
		}
	}
	return sb.String()
}

func normalizeSupervisionDialKey(value string) string {
	key := strings.TrimSpace(value)
	if len(key) < 2 || len(key) > 7 || key[0] != '*' {
		return ""
	}
	for _, ch := range key[1:] {
		if ch < '0' || ch > '9' {
			return ""
		}
	}
	return key
}

func callbackSourceMode(ep SIPEndpointDef) string {
	if ep.CallbackCallerAutoSpeaker {
		return "speaker"
	}
	if ep.CallbackCallerAutoAnswer {
		return "normal"
	}
	return ""
}

func appendConditionalCallbackBridge(sb *strings.Builder, callers, sourceMode, targetExpr string, controlCode bool) {
	allowed := parseAutoAnswerCallers(callers)
	if len(allowed) == 0 {
		sb.WriteString(" same  => n,NoOp(Simson callback bridge enabled but no caller allowlist configured)\n")
		return
	}
	appendCallerIdentityVars(sb)
	sb.WriteString(" same  => n,Set(SIMSON_CALLBACK_BRIDGE_MATCH=)\n")
	for _, caller := range allowed {
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${SIMSON_CALLER_ENDPOINT}\" = \"%s\"]?simson-callback-match)\n", caller)
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${SIMSON_SOURCE_EXTENSION}\" = \"%s\"]?simson-callback-match)\n", caller)
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${CALLERID(num)}\" = \"%s\"]?simson-callback-match)\n", caller)
	}
	sb.WriteString(" same  => n,Goto(simson-callback-done)\n")
	sb.WriteString(" same  => n(simson-callback-match),NoOp(Simson callback bridge matched caller ${SIMSON_CALLER_ENDPOINT}/${CALLERID(num)})\n")
	sb.WriteString(" same  => n,Set(SIMSON_CALLBACK_SOURCE=${SIMSON_CALLER_ENDPOINT})\n")
	sb.WriteString(" same  => n,GotoIf($[\"${SIMSON_CALLBACK_SOURCE}\" != \"\"]?simson-callback-send)\n")
	sb.WriteString(" same  => n,Set(SIMSON_CALLBACK_SOURCE=${SIMSON_SOURCE_EXTENSION})\n")
	controlValue := "no"
	if controlCode {
		controlValue = "yes"
	}
	sb.WriteString(" same  => n(simson-callback-send),UserEvent(SimsonIntercomCallback,Source: ${SIMSON_CALLBACK_SOURCE},Target: " + targetExpr + ",Caller: ${CALLERID(num)},UniqueID: ${UNIQUEID},Channel: ${CHANNEL},SourceAutoMode: " + sourceMode + ",TargetAutoMode: ${SIMSON_AUTO_ANSWER_MODE},ControlCode: " + controlValue + ")\n")
	sb.WriteString(" same  => n,Answer()\n")
	if controlCode {
		sb.WriteString(" same  => n,Wait(0.03)\n")
	} else {
		sb.WriteString(" same  => n,Wait(0.2)\n")
	}
	sb.WriteString(" same  => n,Hangup()\n")
	sb.WriteString(" same  => n(simson-callback-done),NoOp(Simson callback bridge not used)\n")
}

func buildBLFHintDialplan(endpoints []SIPEndpointDef) string {
	seen := map[string]struct{}{}
	var sb strings.Builder
	for _, ep := range endpoints {
		if !ep.Enabled || strings.TrimSpace(ep.RouteTo) != "" {
			continue
		}
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if ext == "" || isReservedGatewayExtension(ext) {
			continue
		}
		if _, ok := seen[ext]; ok {
			continue
		}
		seen[ext] = struct{}{}
		fmt.Fprintf(&sb, "exten => %s,hint,PJSIP/%s\n", ext, ext)
	}
	if sb.Len() == 0 {
		return "; No direct SIP endpoints available for BLF.\n"
	}
	return sb.String()
}

func appendConditionalAutoAnswerMode(sb *strings.Builder, callers string, speaker bool, speakerCallers string) {
	sb.WriteString(" same  => n,Set(SIMSON_AUTO_ANSWER_MODE=)\n")
	allowed := parseAutoAnswerCallers(callers)
	speakerAllowed := parseAutoAnswerCallers(speakerCallers)
	if speaker && len(speakerAllowed) == 0 {
		speakerAllowed = append([]string(nil), allowed...)
	}
	if len(allowed) == 0 {
		sb.WriteString(" same  => n,Set(SIMSON_AUTO_ANSWER_MODE=normal)\n")
		if speaker {
			if len(speakerAllowed) > 0 {
				appendCallerIdentityVars(sb)
			}
			appendConditionalSpeakerMode(sb, speakerAllowed)
		}
		return
	}

	appendCallerIdentityVars(sb)
	for _, caller := range allowed {
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${SIMSON_CALLER_ENDPOINT}\" = \"%s\"]?simson-auto-answer-match)\n", caller)
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${SIMSON_SOURCE_EXTENSION}\" = \"%s\"]?simson-auto-answer-match)\n", caller)
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${CALLERID(num)}\" = \"%s\"]?simson-auto-answer-match)\n", caller)
	}
	sb.WriteString(" same  => n,Goto(simson-auto-answer-done)\n")
	sb.WriteString(" same  => n(simson-auto-answer-match),NoOp(Simson route-specific auto-answer matched caller ${SIMSON_CALLER_ENDPOINT}/${CALLERID(num)})\n")
	sb.WriteString(" same  => n,Set(SIMSON_AUTO_ANSWER_MODE=normal)\n")
	if speaker {
		appendConditionalSpeakerMode(sb, speakerAllowed)
	}
	sb.WriteString(" same  => n(simson-auto-answer-done),NoOp(Simson auto-answer mode ${SIMSON_AUTO_ANSWER_MODE})\n")
}

func appendCallerIdentityVars(sb *strings.Builder) {
	sb.WriteString(" same  => n,Set(SIMSON_CALLER_ENDPOINT=${CHANNEL(pjsip,endpoint)})\n")
	sb.WriteString(" same  => n,Set(SIMSON_SOURCE_EXTENSION=${IF($[\"${SIMSON_SOURCE_EXTENSION}\" = \"\"]?${CALLERID(num)}:${SIMSON_SOURCE_EXTENSION})})\n")
}

func appendConditionalSpeakerMode(sb *strings.Builder, allowed []string) {
	if len(allowed) == 0 {
		sb.WriteString(" same  => n,Set(SIMSON_AUTO_ANSWER_MODE=speaker)\n")
		return
	}
	sb.WriteString(" same  => n,Set(SIMSON_SPEAKER_MATCH=)\n")
	for _, caller := range allowed {
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${SIMSON_CALLER_ENDPOINT}\" = \"%s\"]?simson-speaker-match)\n", caller)
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${SIMSON_SOURCE_EXTENSION}\" = \"%s\"]?simson-speaker-match)\n", caller)
		fmt.Fprintf(sb, " same  => n,GotoIf($[\"${CALLERID(num)}\" = \"%s\"]?simson-speaker-match)\n", caller)
	}
	sb.WriteString(" same  => n,Goto(simson-speaker-done)\n")
	sb.WriteString(" same  => n(simson-speaker-match),Set(SIMSON_AUTO_ANSWER_MODE=speaker)\n")
	sb.WriteString(" same  => n(simson-speaker-done),NoOp(Simson speaker match ${SIMSON_AUTO_ANSWER_MODE})\n")
}

func buildAutoAnswerExtensionDialplan(endpoints []SIPEndpointDef) string {
	seen := map[string]struct{}{}
	var sb strings.Builder
	for _, ep := range endpoints {
		hasTransferPolicy := ep.AccountFeaturesEnabled && normalizeAccountDialCode(ep.AccountTransferCode) != "" && accountTransferContextName(ep.AccountID) != ""
		if !ep.Enabled || (!ep.AutoAnswer && strings.TrimSpace(ep.AnswerAnnouncement) == "" && strings.TrimSpace(ep.PreRingAnnouncement) == "" && len(parseCallDurationRules(ep.CallDurationRules)) == 0 && !hasTransferPolicy) {
			continue
		}
		ext := sanitizeID(strings.TrimSpace(ep.Extension))
		if ext == "" || isReservedGatewayExtension(ext) {
			continue
		}
		if _, ok := seen[ext]; ok {
			continue
		}
		seen[ext] = struct{}{}
		if ep.AutoAnswer {
			fmt.Fprintf(&sb, "exten => %s,1,NoOp(Simson dial auto-answer SIP endpoint ${EXTEN})\n", ext)
			appendConditionalAutoAnswerMode(&sb, ep.AutoAnswerCallers, ep.AutoSpeaker, ep.AutoSpeakerCallers)
		} else {
			fmt.Fprintf(&sb, "exten => %s,1,NoOp(Simson call policy SIP endpoint ${EXTEN})\n", ext)
			sb.WriteString(" same  => n,Set(SIMSON_AUTO_ANSWER_MODE=)\n")
		}
		appendAccountTransferChannelVars(&sb, ep)
		appendCallerPreRingAnnouncement(&sb, ep.PreRingAnnouncement)
		sb.WriteString(" same  => n,Set(SIMSON_DIAL_OPTIONS=rTb(simson-outbound-mark^s^1(${SIMSON_CALL_ID})))\n")
		sb.WriteString(" same  => n,GotoIf($[\"${SIMSON_AUTO_ANSWER_MODE}\" = \"\"]?simson-dial)\n")
		sb.WriteString(" same  => n,Set(SIMSON_DIAL_OPTIONS=rTb(simson-extension-predial^s^1(${SIMSON_CALL_ID}^${SIMSON_AUTO_ANSWER_MODE})))\n")
		appendCalledPartyAnnouncement(&sb, ep.AnswerAnnouncement)
		appendCallDurationRules(&sb, ep.CallDurationRules)
		sb.WriteString(" same  => n,Dial(PJSIP/${EXTEN},${SIMSON_WAIT_TIMEOUT:=120},${SIMSON_DIAL_OPTIONS})\n")
		sb.WriteString(" same  => n,Hangup()\n\n")
	}
	return sb.String()
}

// appendCalledPartyAnnouncement adds Dial's A(x) option. Asterisk plays x only
// to the called endpoint after it answers and bridges the caller afterwards.
// The sound name is generated from an admin-validated, extension-free path.
func appendCalledPartyAnnouncement(sb *strings.Builder, sound string) {
	sound = sanitizeSoundName(sound)
	if sound == "" {
		sb.WriteString(" same  => n(simson-dial),NoOp(Simson called-party prompt disabled)\n")
		return
	}
	fmt.Fprintf(sb, " same  => n(simson-dial),Set(SIMSON_DIAL_OPTIONS=${SIMSON_DIAL_OPTIONS}A(%s))\n", sound)
}

// appendCallerPreRingAnnouncement emits early media to the caller before any
// target Dial is started. The receiving phone therefore does not ring until
// the announcement completes. This is distinct from Dial's A() option, which
// remains private to the receiving phone after it answers.
func appendCallerPreRingAnnouncement(sb *strings.Builder, sound string) {
	sound = sanitizeSoundName(sound)
	if sound == "" {
		return
	}
	sb.WriteString(" same  => n,Progress()\n")
	fmt.Fprintf(sb, " same  => n,Playback(%s,noanswer)\n", sound)
}

// appendCallDurationRules adds Dial's L(milliseconds) option only for an exact
// configured source extension. L starts its limit when the called party
// answers, so ringing and a caller-side pre-ring announcement do not consume
// the configured connected-call duration.
func appendCallDurationRules(sb *strings.Builder, encoded string) {
	rules := parseCallDurationRules(encoded)
	if len(rules) == 0 {
		return
	}
	appendCallerIdentityVars(sb)
	sb.WriteString(" same  => n,Set(SIMSON_ROUTE_LIMIT_MS=)\n")
	for _, source := range sortedMapKeys(rules) {
		milliseconds := rules[source] * 1000
		fmt.Fprintf(sb, " same  => n,ExecIf($[\"${SIMSON_CALLER_ENDPOINT}\" = \"%s\"]?Set(SIMSON_ROUTE_LIMIT_MS=%d))\n", source, milliseconds)
		fmt.Fprintf(sb, " same  => n,ExecIf($[\"${SIMSON_SOURCE_EXTENSION}\" = \"%s\"]?Set(SIMSON_ROUTE_LIMIT_MS=%d))\n", source, milliseconds)
		fmt.Fprintf(sb, " same  => n,ExecIf($[\"${CALLERID(num)}\" = \"%s\"]?Set(SIMSON_ROUTE_LIMIT_MS=%d))\n", source, milliseconds)
	}
	sb.WriteString(" same  => n,ExecIf($[\"${SIMSON_ROUTE_LIMIT_MS}\" != \"\"]?Set(SIMSON_DIAL_OPTIONS=${SIMSON_DIAL_OPTIONS}L(${SIMSON_ROUTE_LIMIT_MS})))\n")
}

func parseCallDurationRules(encoded string) map[string]int {
	rules := map[string]int{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(encoded)), &rules); err != nil {
		return map[string]int{}
	}
	for source, seconds := range rules {
		if sanitizeID(source) != source || seconds < 1 || seconds > 86400 {
			delete(rules, source)
		}
	}
	return rules
}

func sortedMapKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func parseAutoAnswerCallers(callers string) []string {
	parts := strings.FieldsFunc(callers, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		caller := sanitizeID(strings.TrimSpace(part))
		if caller == "" {
			continue
		}
		if _, ok := seen[caller]; ok {
			continue
		}
		seen[caller] = struct{}{}
		out = append(out, caller)
	}
	return out
}

func isReservedGatewayExtension(ext string) bool {
	return len(ext) == 4 && strings.HasPrefix(ext, "70")
}

// sanitizeID strips unsafe characters from an endpoint ID.
func sanitizeID(id string) string {
	var sb strings.Builder
	for _, r := range id {
		if r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
