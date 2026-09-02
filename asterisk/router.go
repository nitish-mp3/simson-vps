package asterisk

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/nitish-mp3/simson-vps/logging"
)

// IncomingSIPCall describes an inbound call that Asterisk has received from a
// SIP phone and delegated to the Simson routing layer.
type IncomingSIPCall struct {
	Channel        string // Asterisk channel (e.g. PJSIP/phone1-00000001)
	Extension      string // extension that was dialled (e.g. "1001")
	CallerID       string // caller number / display name
	CallerEndpoint string // PJSIP endpoint that Asterisk matched, when available
	GatewaySource  string // no-auth gateway extension that accepted the anonymous call, when known
	UniqueID       string // Asterisk unique call ID
	BridgeID       string // ConfBridge room the SIP channel is already parked in
}

// IntercomCallbackRequest asks the server to replace a direct SIP caller leg
// with a fresh callback leg so caller-side auto-answer/speaker hints can be sent.
type IntercomCallbackRequest struct {
	Channel         string
	SourceExtension string
	TargetExtension string
	CallerID        string
	UniqueID        string
	SourceAutoMode  string
	TargetAutoMode  string
	ControlCode     bool
}

// DirectSIPCallEvent reports the lifecycle of an ordinary SIP-to-SIP Dial().
// These calls deliberately stay in Asterisk's native bridge; the event exists
// only so site addons can display an accurate live-call roster.
type DirectSIPCallEvent struct {
	Phase      string
	CallID     string
	AccountID  string
	Source     string
	Target     string
	Channel    string
	DialStatus string
}

// ContactStatus describes the live PJSIP registration/contact state for an AoR.
type ContactStatus struct {
	Registered bool   `json:"registered"`
	Status     string `json:"status,omitempty"`
	URI        string `json:"uri,omitempty"`
	Address    string `json:"address,omitempty"`
	LatencyMS  string `json:"latency_ms,omitempty"`
}

// ChannelHangup describes why Asterisk tore down a channel. Retaining the AMI
// cause fields is important for distinguishing a handset BYE from network loss,
// malformed SIP, congestion, or a server-initiated cleanup.
type ChannelHangup struct {
	Channel   string
	Cause     string
	CauseText string
	UniqueID  string
	LinkedID  string
}

// ChannelDTMF is one completed DTMF digit received from a live Asterisk
// channel. The server uses this for feature codes on ConfBridge calls, where
// Dial()'s built-in transfer feature hooks are not present.
type ChannelDTMF struct {
	Channel   string
	Digit     string
	Direction string
}

// BridgeTransferResult is the asynchronous outcome of adding a replacement
// SIP handset to an existing Simson ConfBridge call.
type BridgeTransferResult struct {
	CallID        string
	SourceChannel string
	SourceExt     string
	TargetExt     string
	ReplaceSource bool
	OK            bool
	Reason        string
	Channel       string
}

type pendingBridgeTransfer struct {
	callID        string
	sourceChannel string
	sourceExt     string
	targetExt     string
	replaceSource bool
}

// Router orchestrates call routing between VPS Asterisk (via AMI) and the
// Simson WebSocket nodes.
//
// It wraps an AMIClient and provides higher-level operations:
//   - Tracking Simson call IDs ↔ Asterisk channel names
//   - Firing callbacks when a SIP phone calls in or hangs up
//   - Tracking async Originate results so the server can update call state
type Router struct {
	ami *AMIClient
	log *logging.Logger

	// Callbacks set by server.go after construction.
	OnIncomingCall     func(in IncomingSIPCall)                    // SIP phone dialled in
	OnIntercomCallback func(req IntercomCallbackRequest)           // SIP direct route requested callback bridge
	OnDirectSIPCall    func(event DirectSIPCallEvent)              // native direct SIP call lifecycle
	OnChannelHangup    func(info ChannelHangup)                    // SIP channel hung up
	OnOriginateResult  func(callID string, ok bool, reason string) // async Originate outcome
	OnChannelDTMF      func(info ChannelDTMF)                      // completed received DTMF digit
	OnBridgeTransfer   func(result BridgeTransferResult)           // ConfBridge transfer outcome

	// call tracking
	mu                    sync.RWMutex
	chanToCallID          map[string]string   // asterisk channel → simson call ID
	callIDToChan          map[string]string   // simson call ID  → asterisk channel
	callIDToChannelPrefix map[string][]string // simson call ID → probable ringing channel prefixes

	// async originate tracking
	originateMu      sync.Mutex
	actionIDToCallID map[string]string // originate actionID → simson call ID
	bridgeTransfers  map[string]pendingBridgeTransfer
}

// NewRouter creates a Router wrapping the given AMI client and registers the
// event handler. The AMI client must not be started yet.
func NewRouter(ami *AMIClient, log *logging.Logger) *Router {
	r := &Router{
		ami:                   ami,
		log:                   log,
		chanToCallID:          make(map[string]string),
		callIDToChan:          make(map[string]string),
		callIDToChannelPrefix: make(map[string][]string),
		actionIDToCallID:      make(map[string]string),
		bridgeTransfers:       make(map[string]pendingBridgeTransfer),
	}
	ami.OnEvent(r.onEvent)
	return r
}

// OriginateBridgeTransfer rings targetExtension and sends the answered Local
// leg into bridgeExt. It has separate result tracking from ordinary call
// originates so a failed transfer never changes the parent call's state.
func (r *Router) OriginateBridgeTransfer(targetExtension, context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt string, timeoutSec int) (string, error) {
	return r.originateBridgeParticipant(targetExtension, context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt, timeoutSec, true)
}

// OriginateBridgeConference rings another handset into an existing Simson
// bridge while retaining the source handset. This is the in-call *85 path;
// unlike a transfer, answering the new leg must not release the caller.
func (r *Router) OriginateBridgeConference(targetExtension, context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt string, timeoutSec int) (string, error) {
	return r.originateBridgeParticipant(targetExtension, context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt, timeoutSec, false)
}

// OriginateBridgeExternalParticipant dials a number through an explicitly
// selected same-account gateway and joins the answered leg to a managed bridge.
func (r *Router) OriginateBridgeExternalParticipant(number, trunk, outContext, context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt string, timeoutSec int, replaceSource bool) (string, error) {
	number, trunk = strings.TrimSpace(number), strings.TrimSpace(trunk)
	if number == "" || trunk == "" || outContext == "" {
		return "", fmt.Errorf("external bridge participant requires number, trunk, and outbound context")
	}
	channel := fmt.Sprintf("Local/%s@%s/n", number, outContext)
	return r.originateBridgeParticipantChannel(channel, "outside:"+number, trunk, context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt, timeoutSec, replaceSource)
}

// OriginateDirectConference rings targetExtension and, once answered, barges
// that handset into the existing direct SIP channel. This is intentionally
// separate from Simson ConfBridge calls: ordinary SIP-to-SIP calls live in an
// Asterisk basic bridge and therefore have no Simson bridge extension to join.
func (r *Router) OriginateDirectConference(targetExtension, sourceChannel, callerID string, timeoutSec int) (string, error) {
	return r.OriginateDirectSupervision(targetExtension, sourceChannel, callerID, "barge", timeoutSec)
}

// OriginateDirectSupervision lets an active participant invite an authorised
// same-site handset to monitor, whisper to that participant, or barge. The
// destination joins only after answering and the original bridge is untouched.
func (r *Router) OriginateDirectSupervision(targetExtension, sourceChannel, callerID, mode string, timeoutSec int) (string, error) {
	targetExtension = strings.TrimSpace(targetExtension)
	sourceChannel = normalizeChannel(sourceChannel)
	if targetExtension == "" || sourceChannel == "" {
		return "", fmt.Errorf("direct conference requires target and source channel")
	}
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "listen" && mode != "whisper" && mode != "barge" {
		return "", fmt.Errorf("invalid direct supervision mode")
	}
	actionID := uuid.NewString()
	_, err := r.ami.OriginateWithVars(
		fmt.Sprintf("PJSIP/%s", targetExtension),
		"simson-direct-supervision",
		"s",
		callerID,
		timeoutSec*1000,
		actionID,
		map[string]string{
			"SIMSON_SPY_CHANNEL": sourceChannel,
			"SIMSON_SPY_MODE":    mode,
		},
	)
	if err != nil {
		return "", err
	}
	return actionID, nil
}

// OriginateDirectExternalSupervision is the explicit *gateway*number variant
// for an active direct SIP call.
func (r *Router) OriginateDirectExternalSupervision(number, trunk, outContext, sourceChannel, callerID, mode string, timeoutSec int) (string, error) {
	number, trunk = strings.TrimSpace(number), strings.TrimSpace(trunk)
	sourceChannel = normalizeChannel(sourceChannel)
	mode = strings.ToLower(strings.TrimSpace(mode))
	if number == "" || trunk == "" || outContext == "" || sourceChannel == "" {
		return "", fmt.Errorf("external supervision requires number, trunk, context, and source channel")
	}
	if mode != "listen" && mode != "whisper" && mode != "barge" {
		return "", fmt.Errorf("invalid direct supervision mode")
	}
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	actionID := uuid.NewString()
	_, err := r.ami.OriginateWithVars(fmt.Sprintf("Local/%s@%s/n", number, outContext),
		"simson-direct-supervision", "s", callerID, timeoutSec*1000, actionID,
		map[string]string{"SIMSON_SPY_CHANNEL": sourceChannel, "SIMSON_SPY_MODE": mode,
			"SIMSON_TRUNK": trunk, "__SIMSON_TRUNK": trunk})
	return actionID, err
}

func (r *Router) originateBridgeParticipant(targetExtension, context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt string, timeoutSec int, replaceSource bool) (string, error) {
	targetExtension = strings.TrimSpace(targetExtension)
	sourceChannel = normalizeChannel(sourceChannel)
	if targetExtension == "" || bridgeExt == "" || callID == "" || sourceChannel == "" {
		return "", fmt.Errorf("bridge transfer requires target, bridge, call, and source channel")
	}
	channel := fmt.Sprintf("Local/%s@from-simson-extension/n", targetExtension)
	return r.originateBridgeParticipantChannel(channel, targetExtension, "", context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt, timeoutSec, replaceSource)
}

func (r *Router) originateBridgeParticipantChannel(channel, targetLabel, trunk, context, bridgeExt, callerID, callID, fromNode, sourceChannel, sourceExt string, timeoutSec int, replaceSource bool) (string, error) {
	sourceChannel = normalizeChannel(sourceChannel)
	if channel == "" || targetLabel == "" || bridgeExt == "" || callID == "" || sourceChannel == "" {
		return "", fmt.Errorf("bridge transfer requires target, bridge, call, and source channel")
	}
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, strings.TrimSuffix(channel, "/n")+"-")
	if !strings.HasPrefix(targetLabel, "outside:") {
		r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", targetLabel))
	}

	r.originateMu.Lock()
	if r.bridgeTransfers == nil {
		r.bridgeTransfers = make(map[string]pendingBridgeTransfer)
	}
	r.bridgeTransfers[actionID] = pendingBridgeTransfer{
		callID: callID, sourceChannel: sourceChannel, sourceExt: sourceExt,
		targetExt: targetLabel, replaceSource: replaceSource,
	}
	r.originateMu.Unlock()

	vars := map[string]string{
		"SIMSON_CALL_ID":      callID,
		"__SIMSON_CALL_ID":    callID,
		"SIMSON_FROM_NODE":    fromNode,
		"__SIMSON_FROM_NODE":  fromNode,
		"SIMSON_WAIT_TIMEOUT": fmt.Sprintf("%d", timeoutSec),
	}
	if trunk != "" {
		vars["SIMSON_TRUNK"] = trunk
		vars["__SIMSON_TRUNK"] = trunk
	}
	_, err := r.ami.OriginateWithVars(channel, context, bridgeExt, callerID, timeoutSec*1000, actionID, vars)
	if err != nil {
		r.originateMu.Lock()
		delete(r.bridgeTransfers, actionID)
		r.originateMu.Unlock()
		return "", err
	}
	return actionID, nil
}

// Connect connects to Asterisk AMI.
func (r *Router) Connect() error { return r.ami.Connect() }

// Start starts the AMI read loop in a background goroutine (non-blocking).
func (r *Router) Start() { go r.ami.ReadLoop() }

// Run connects to Asterisk and blocks until the connection is closed.
// Reconnect by calling Run again. Suitable for a retry loop.
func (r *Router) Run() error {
	if err := r.ami.Connect(); err != nil {
		return err
	}
	r.ami.ReadLoop() // blocks until disconnected
	return nil
}

// Disconnect closes the AMI connection.
func (r *Router) Disconnect() { r.ami.Disconnect() }

// Connected reports whether AMI is connected.
func (r *Router) Connected() bool { return r.ami.Connected() }

// TrackCall registers a Simson call ID ↔ Asterisk channel mapping.
func (r *Router) TrackCall(callID, channel string) {
	channel = normalizeChannel(channel)
	if callID == "" || channel == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chanToCallID[channel] = callID
	r.callIDToChan[callID] = channel
}

func (r *Router) TrackPendingPrefix(callID, prefix string) {
	callID = strings.TrimSpace(callID)
	prefix = normalizeChannel(prefix)
	if callID == "" || prefix == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.callIDToChannelPrefix[callID] {
		if existing == prefix {
			return
		}
	}
	r.callIDToChannelPrefix[callID] = append(r.callIDToChannelPrefix[callID], prefix)
}

// UntrackCall removes tracking for a Simson call ID.
func (r *Router) UntrackCall(callID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ch, id := range r.chanToCallID {
		if id == callID {
			delete(r.chanToCallID, ch)
		}
	}
	delete(r.callIDToChan, callID)
	delete(r.callIDToChannelPrefix, callID)
}

// ChannelForCall returns the Asterisk channel for a Simson call ID.
func (r *Router) ChannelForCall(callID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ch, ok := r.callIDToChan[callID]
	return ch, ok
}

// ChannelsForCall returns every Asterisk channel currently mapped to a Simson call.
func (r *Router) ChannelsForCall(callID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	channels := []string{}
	for ch, id := range r.chanToCallID {
		if id == callID {
			channels = append(channels, ch)
		}
	}
	if ch, ok := r.callIDToChan[callID]; ok {
		found := false
		for _, existing := range channels {
			if existing == ch {
				found = true
				break
			}
		}
		if !found {
			channels = append(channels, ch)
		}
	}
	return channels
}

func (r *Router) PendingPrefixesForCall(callID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	prefixes := r.callIDToChannelPrefix[callID]
	out := make([]string, len(prefixes))
	copy(out, prefixes)
	return out
}

// CallIDForChannel returns the Simson call ID for an Asterisk channel.
func (r *Router) CallIDForChannel(channel string) (string, bool) {
	channel = normalizeChannel(channel)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, _, ok := r.findCallByChannelLocked(channel)
	return id, ok
}

// OriginateToExtension dials a SIP extension on behalf of a Simson node.
// bridgeExt is the extension in nodeCtx that answered SIP legs are sent to.
// Returns the AMI ActionID that can be used to match the async OriginateResponse event.
func (r *Router) OriginateToExtension(extension, context, bridgeExt, callerID, callID, fromNode string, timeoutSec int) (string, error) {
	channel := fmt.Sprintf("Local/%s@from-simson-extension/n", extension)
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, fmt.Sprintf("Local/%s@from-simson-extension-", extension))
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", extension))

	// Register before sending Originate so very fast OriginateResponse events
	// (for immediate failures) cannot race ahead of tracking.
	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()

	vars := map[string]string{
		"SIMSON_CALL_ID":      callID,
		"__SIMSON_CALL_ID":    callID,
		"SIMSON_FROM_NODE":    fromNode,
		"__SIMSON_FROM_NODE":  fromNode,
		"SIMSON_WAIT_TIMEOUT": fmt.Sprintf("%d", timeoutSec),
	}
	_, err := r.ami.OriginateWithVars(channel, context, bridgeExt, callerID, timeoutSec*1000, actionID, vars)
	if err != nil {
		r.originateMu.Lock()
		delete(r.actionIDToCallID, actionID)
		r.originateMu.Unlock()
		return "", err
	}

	return actionID, nil
}

// OriginateDoorStationCall calls an outdoor SIP station first and, once that
// device auto-answers, dials the selected indoor SIP extension through a plain
// Asterisk Dial bridge. Keeping this path outside ConfBridge preserves native
// SIP video negotiation for camera door stations without changing browser or
// gateway audio behavior.
func (r *Router) OriginateDoorStationCall(sourceExtension, targetExtension, callerID, callID string, timeoutSec int) (string, error) {
	channel := fmt.Sprintf("PJSIP/%s", sourceExtension)
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", sourceExtension))
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", targetExtension))

	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()

	vars := map[string]string{
		"SIMSON_CALL_ID":      callID,
		"__SIMSON_CALL_ID":    callID,
		"SIMSON_WAIT_TIMEOUT": fmt.Sprintf("%d", timeoutSec),
	}
	_, err := r.ami.OriginateWithVarsAndCodecs(
		channel,
		"from-simson-door",
		targetExtension,
		callerID,
		timeoutSec*1000,
		actionID,
		vars,
		"ulaw,alaw,h264",
	)
	if err != nil {
		r.originateMu.Lock()
		delete(r.actionIDToCallID, actionID)
		r.originateMu.Unlock()
		return "", err
	}

	return actionID, nil
}

// OriginateDoorStationToBridge calls an outdoor SIP station and parks it in a
// ConfBridge room so HAOS/browser cards can join the same SIP media bridge via
// WebRTC. Native SIP-to-SIP video calls should keep using OriginateDoorStationCall.
func (r *Router) OriginateDoorStationToBridge(sourceExtension, bridgeExt, callerID, callID string, timeoutSec int) (string, error) {
	channel := fmt.Sprintf("PJSIP/%s", sourceExtension)
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", sourceExtension))

	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()

	vars := map[string]string{
		"SIMSON_CALL_ID":      callID,
		"__SIMSON_CALL_ID":    callID,
		"SIMSON_BRIDGE_ID":    bridgeExt,
		"__SIMSON_BRIDGE_ID":  bridgeExt,
		"SIMSON_WAIT_TIMEOUT": fmt.Sprintf("%d", timeoutSec),
	}
	_, err := r.ami.OriginateWithVarsAndCodecs(
		channel,
		"from-simson-node",
		bridgeExt,
		callerID,
		timeoutSec*1000,
		actionID,
		vars,
		"ulaw,alaw",
	)
	if err != nil {
		r.originateMu.Lock()
		delete(r.actionIDToCallID, actionID)
		r.originateMu.Unlock()
		return "", err
	}

	return actionID, nil
}

// OriginateIntercomCallback calls the original source phone back first and, once
// answered, dials the target extension. This enables caller-side intercom
// headers because the source phone becomes a called leg.
func (r *Router) OriginateIntercomCallback(sourceExtension, targetExtension, sourceLegCallerID, targetLegCallerNum, targetLegCallerName, callID, sourceAutoMode, targetAutoMode, preRingAnnouncement string, maxConnectedSec, timeoutSec int) (string, error) {
	// Speaker mode on the original caller is only reliable when that phone is the
	// first fresh called leg. Target-first callback can preserve target timing,
	// but several SIP handsets ignore intercom/speaker hints on the later source
	// leg. The server waits for the original outbound dialog to release before
	// calling this, so source-first remains fast without reintroducing retry loops.
	channel := fmt.Sprintf("Local/%s@from-simson-callback-source/n", sourceExtension)
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, fmt.Sprintf("Local/%s@from-simson-callback-source-", sourceExtension))
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", sourceExtension))
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", targetExtension))

	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()

	vars := map[string]string{
		"SIMSON_CALL_ID":                 callID,
		"__SIMSON_CALL_ID":               callID,
		"SIMSON_WAIT_TIMEOUT":            fmt.Sprintf("%d", timeoutSec),
		"SIMSON_SOURCE_AUTO_MODE":        sourceAutoMode,
		"__SIMSON_SOURCE_AUTO_MODE":      sourceAutoMode,
		"SIMSON_TARGET_AUTO_MODE":        targetAutoMode,
		"__SIMSON_TARGET_AUTO_MODE":      targetAutoMode,
		"SIMSON_TARGET_LEG_CALLER_NUM":   targetLegCallerNum,
		"SIMSON_TARGET_LEG_CALLER_NAME":  targetLegCallerName,
		"SIMSON_PRE_RING_ANNOUNCEMENT":   sanitizeSoundName(preRingAnnouncement),
		"__SIMSON_PRE_RING_ANNOUNCEMENT": sanitizeSoundName(preRingAnnouncement),
		"SIMSON_MAX_CONNECTED_MS":        fmt.Sprintf("%d", maxConnectedSec*1000),
		"__SIMSON_MAX_CONNECTED_MS":      fmt.Sprintf("%d", maxConnectedSec*1000),
	}
	_, err := r.ami.OriginateWithVars(
		channel,
		"from-simson-callback-target",
		targetExtension,
		sourceLegCallerID,
		timeoutSec*1000,
		actionID,
		vars,
	)
	if err != nil {
		r.originateMu.Lock()
		delete(r.actionIDToCallID, actionID)
		r.originateMu.Unlock()
		return "", err
	}

	return actionID, nil
}

func (r *Router) originateIntercomCallbackTargetFirst(sourceExtension, targetExtension, sourceLegCallerID, targetLegCallerNum, targetLegCallerName, callID, sourceAutoMode, targetAutoMode string, timeoutSec int) (string, error) {
	channel := fmt.Sprintf("Local/%s@from-simson-callback-target-first/n", targetExtension)
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, fmt.Sprintf("Local/%s@from-simson-callback-target-first-", targetExtension))
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", sourceExtension))
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", targetExtension))

	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()

	targetLegCallerID := targetLegCallerName
	if targetLegCallerID == "" {
		targetLegCallerID = targetLegCallerNum
	} else if targetLegCallerNum != "" && !strings.Contains(targetLegCallerID, "<") {
		targetLegCallerID = fmt.Sprintf("%s <%s>", targetLegCallerID, targetLegCallerNum)
	}

	vars := map[string]string{
		"SIMSON_CALL_ID":                callID,
		"__SIMSON_CALL_ID":              callID,
		"SIMSON_WAIT_TIMEOUT":           fmt.Sprintf("%d", timeoutSec),
		"SIMSON_SOURCE_AUTO_MODE":       sourceAutoMode,
		"__SIMSON_SOURCE_AUTO_MODE":     sourceAutoMode,
		"SIMSON_TARGET_AUTO_MODE":       targetAutoMode,
		"__SIMSON_TARGET_AUTO_MODE":     targetAutoMode,
		"SIMSON_TARGET_LEG_CALLER_NUM":  targetLegCallerNum,
		"SIMSON_TARGET_LEG_CALLER_NAME": targetLegCallerName,
		"SIMSON_SOURCE_LEG_CALLER_ID":   sourceLegCallerID,
	}
	_, err := r.ami.OriginateWithVarsAndCodecs(
		channel,
		"from-simson-callback-source-after-target",
		sourceExtension,
		targetLegCallerID,
		timeoutSec*1000,
		actionID,
		vars,
		"ulaw,alaw,h264",
	)
	if err != nil {
		r.originateMu.Lock()
		delete(r.actionIDToCallID, actionID)
		r.originateMu.Unlock()
		return "", err
	}

	return actionID, nil
}

// OriginateToTrunk dials an external number through an existing PJSIP trunk and
// then sends the answered leg into the same ConfBridge extension used by SIP
// phone calls.
func (r *Router) OriginateToTrunk(number, trunk, outContext, bridgeContext, bridgeExt, callerID, callID, fromNode, dialTerminator, postAnswerDTMF string, timeoutSec, maxConnectedSec int) (string, error) {
	if outContext == "" {
		outContext = "from-simson-out"
	}
	// Keep the Local channel from being optimized away before we can track the
	// real outbound PJSIP leg and bridge/hang it up cleanly.
	channel := fmt.Sprintf("Local/%s@%s/n", number, outContext)
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, fmt.Sprintf("Local/%s@%s-", number, outContext))
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", trunk))

	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()

	vars := map[string]string{
		"SIMSON_CALL_ID":          callID,
		"__SIMSON_CALL_ID":        callID,
		"SIMSON_FROM_NODE":        fromNode,
		"__SIMSON_FROM_NODE":      fromNode,
		"SIMSON_TRUNK":            trunk,
		"SIMSON_DIAL_SUFFIX":      dialTerminator,
		"SIMSON_POST_ANSWER_DTMF": postAnswerDTMF,
		"SIMSON_WAIT_TIMEOUT":     fmt.Sprintf("%d", timeoutSec),
	}
	if maxConnectedSec > 0 {
		vars["SIMSON_MAX_CONNECTED_MS"] = fmt.Sprintf("%d", maxConnectedSec*1000)
	}
	_, err := r.ami.OriginateWithVars(channel, bridgeContext, bridgeExt, callerID, timeoutSec*1000, actionID, vars)
	if err != nil {
		r.originateMu.Lock()
		delete(r.actionIDToCallID, actionID)
		r.originateMu.Unlock()
		return "", err
	}

	return actionID, nil
}

// HangupCall hangs up the Asterisk channel mapped to a Simson call ID.
// Silently succeeds if no channel is tracked.
func (r *Router) HangupCall(callID string) error {
	return r.hangupCall(callID, "")
}

// HangupCallExcept hangs up all channels for a Simson call except the supplied
// channel. This is useful from hangup callbacks where Asterisk already removed
// the channel that emitted the event.
func (r *Router) HangupCallExcept(callID, exceptChannel string) error {
	return r.hangupCall(callID, exceptChannel)
}

// HangupTrackedCallNoWait sends hangup requests only for channels already
// tracked in memory. It deliberately does not issue AMI Command actions or
// wait for replies, so it is safe to call from an AMI event callback.
//
// The AMI reader invokes callbacks serially. Waiting for an AMI response from
// inside one of those callbacks deadlocks the reader until its timeout expires.
func (r *Router) HangupTrackedCallNoWait(callID, exceptChannel string) error {
	exceptChannel = normalizeChannel(exceptChannel)
	channels := r.ChannelsForCall(callID)
	if len(channels) == 0 {
		return nil
	}

	var firstErr error
	seen := make(map[string]struct{}, len(channels))
	for _, ch := range channels {
		ch = normalizeChannel(ch)
		if ch == "" || (exceptChannel != "" && ch == exceptChannel) {
			continue
		}
		if _, ok := seen[ch]; ok {
			continue
		}
		seen[ch] = struct{}{}
		if err := r.ami.HangupChannelNoWait(ch); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// HangupBridge hangs up every active Asterisk channel currently parked in a
// Simson ConfBridge room. This is the final safety net for browser/WebRTC
// bridge legs that did not carry the Simson call ID in their channel data.
func (r *Router) HangupBridge(bridgeID, exceptChannel string) error {
	bridgeID = strings.TrimSpace(bridgeID)
	exceptChannel = normalizeChannel(exceptChannel)
	if bridgeID == "" {
		return nil
	}
	channels := r.channelsInBridge(bridgeID)
	if len(channels) == 0 {
		return nil
	}
	var firstErr error
	for _, ch := range channels {
		if exceptChannel != "" && normalizeChannel(ch) == exceptChannel {
			continue
		}
		if err := r.ami.HangupChannel(ch); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no such channel") {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// CleanupOrphanSimsonChannels clears media legs left behind after a control-plane
// restart. Asterisk keeps ConfBridge channels alive independently of this process,
// so without this cleanup stale WebRTC/CBAnn legs can build up and hurt audio.
func (r *Router) CleanupOrphanSimsonChannels() (int, error) {
	out, err := r.ami.RunCommand("core show channels concise")
	if err != nil {
		return 0, err
	}

	var firstErr error
	cleaned := 0
	seen := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "!")
		if len(parts) < 3 {
			continue
		}
		channel := strings.TrimSpace(parts[0])
		context := strings.TrimSpace(parts[1])
		if channel == "" {
			continue
		}
		if _, ok := seen[channel]; ok {
			continue
		}
		seen[channel] = struct{}{}

		isSimsonBridgeLeg := context == "from-simson-node" ||
			strings.HasPrefix(channel, "CBAnn/bridge-")
		if !isSimsonBridgeLeg {
			continue
		}
		if err := r.ami.HangupChannel(channel); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no such channel") {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			r.log.Warn("failed to clean orphan Simson channel",
				map[string]any{"channel": channel, "err": err.Error()})
			continue
		}
		cleaned++
	}
	return cleaned, firstErr
}

func (r *Router) hangupCall(callID, exceptChannel string) error {
	exceptChannel = normalizeChannel(exceptChannel)
	channels := r.ChannelsForCall(callID)
	for _, ch := range r.channelsWithCallID(callID) {
		found := false
		for _, existing := range channels {
			if existing == ch {
				found = true
				break
			}
		}
		if !found {
			channels = append(channels, ch)
		}
	}
	for _, ch := range r.channelsWithPendingPrefixes(callID) {
		found := false
		for _, existing := range channels {
			if existing == ch {
				found = true
				break
			}
		}
		if !found {
			channels = append(channels, ch)
		}
	}
	if len(channels) == 0 {
		return nil
	}
	var firstErr error
	for _, ch := range channels {
		if exceptChannel != "" && normalizeChannel(ch) == exceptChannel {
			continue
		}
		if err := r.ami.HangupChannel(ch); err != nil {
			// Asterisk often removes Local/PJSIP helper channels while we are
			// already clearing the bridge. Treat that as successful cleanup.
			if strings.Contains(strings.ToLower(err.Error()), "no such channel") {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (r *Router) channelsWithCallID(callID string) []string {
	callID = strings.TrimSpace(callID)
	if callID == "" {
		return nil
	}
	out, err := r.ami.RunCommand("core show channels concise")
	if err != nil {
		r.log.Warn("could not inspect channels for call cleanup",
			map[string]any{"call_id": callID, "err": err.Error()})
		return nil
	}

	var channels []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, callID) {
			continue
		}
		parts := strings.Split(line, "!")
		if len(parts) == 0 {
			continue
		}
		if ch := normalizeChannel(parts[0]); ch != "" {
			channels = append(channels, ch)
		}
	}
	return channels
}

func (r *Router) channelsWithPendingPrefixes(callID string) []string {
	prefixes := r.PendingPrefixesForCall(callID)
	if len(prefixes) == 0 {
		return nil
	}
	out, err := r.ami.RunCommand("core show channels concise")
	if err != nil {
		r.log.Warn("could not inspect channels for pending call cleanup",
			map[string]any{"call_id": callID, "err": err.Error()})
		return nil
	}

	var channels []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "!")
		if len(parts) == 0 {
			continue
		}
		ch := normalizeChannel(parts[0])
		if ch == "" {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(ch, prefix) {
				channels = append(channels, ch)
				break
			}
		}
	}
	return channels
}

func (r *Router) channelsInBridge(bridgeID string) []string {
	bridgeID = strings.TrimSpace(bridgeID)
	if bridgeID == "" {
		return nil
	}
	out, err := r.ami.RunCommand("core show channels concise")
	if err != nil {
		r.log.Warn("could not inspect channels for bridge cleanup",
			map[string]any{"bridge": bridgeID, "err": err.Error()})
		return nil
	}

	var channels []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, bridgeID) {
			continue
		}
		parts := strings.Split(line, "!")
		if len(parts) == 0 {
			continue
		}
		ch := normalizeChannel(parts[0])
		if ch == "" {
			continue
		}
		if _, ok := seen[ch]; ok {
			continue
		}
		seen[ch] = struct{}{}
		channels = append(channels, ch)
	}
	return channels
}

// HangupChannel hangs up an Asterisk channel directly by name.
func (r *Router) HangupChannel(channel string) error {
	return r.ami.HangupChannel(channel)
}

// HangupChannelNoWait sends Hangup without waiting for AMI acknowledgement.
// Use only where the caller immediately follows with another AMI action.
func (r *Router) HangupChannelNoWait(channel string) error {
	return r.ami.HangupChannelNoWait(channel)
}

// ClearEndpointChannels releases live PJSIP channels for one endpoint. It is
// intentionally endpoint-scoped so an operator can recover an orphaned FXO,
// GSM, or SIP-phone channel without disturbing unrelated calls.
func (r *Router) ClearEndpointChannels(extension string) (int, error) {
	extension = strings.TrimSpace(extension)
	if extension == "" || strings.ContainsAny(extension, "! \t\r\n") {
		return 0, fmt.Errorf("invalid endpoint extension")
	}
	out, err := r.ami.RunCommand("core show channels concise")
	if err != nil {
		return 0, err
	}
	channels := endpointCleanupChannels(out, extension)
	cleared := 0
	var firstErr error
	for _, channel := range channels {
		if err := r.ami.HangupChannel(channel); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no such channel") {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		cleared++
	}
	return cleared, firstErr
}

// FindActiveEndpointChannel resolves the one answered PJSIP channel currently
// owned by an extension. Refusing ambiguous matches prevents a supervisor from
// being attached to the wrong call when a handset has multiple appearances.
func (r *Router) FindActiveEndpointChannel(extension string) (string, error) {
	extension = strings.TrimSpace(extension)
	if extension == "" || strings.ContainsAny(extension, "! \t\r\n") {
		return "", fmt.Errorf("invalid endpoint extension")
	}
	out, err := r.ami.RunCommand("core show channels concise")
	if err != nil {
		return "", err
	}
	channels := activeEndpointChannels(out, extension)
	switch len(channels) {
	case 0:
		return "", fmt.Errorf("SIP %s has no answered active call", extension)
	case 1:
		return channels[0], nil
	default:
		return "", fmt.Errorf("SIP %s has multiple active calls; select a call explicitly", extension)
	}
}

func activeEndpointChannels(output, extension string) []string {
	prefix := "PJSIP/" + strings.TrimSpace(extension) + "-"
	seen := make(map[string]struct{})
	channels := make([]string, 0, 1)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "!")
		if len(parts) < 5 {
			continue
		}
		channel := normalizeChannel(parts[0])
		state := strings.TrimSpace(parts[4])
		if !strings.HasPrefix(channel, prefix) || !strings.EqualFold(state, "Up") {
			continue
		}
		if _, ok := seen[channel]; ok {
			continue
		}
		seen[channel] = struct{}{}
		channels = append(channels, channel)
	}
	sort.Strings(channels)
	return channels
}

type conciseChannel struct {
	name     string
	base     string
	linkedID string
	bridgeID string
}

// endpointCleanupChannels returns the complete Asterisk call family rooted at
// one PJSIP endpoint. core show channels concise fields 11 and 12 are the
// Linkedid and BridgeId on supported Asterisk versions. Clearing only the
// PJSIP leg can leave its Local/ConfBridge sibling alive and keep an analog
// gateway off-hook indefinitely.
func endpointCleanupChannels(output, extension string) []string {
	extension = strings.TrimSpace(extension)
	prefix := "PJSIP/" + extension + "-"
	rows := make([]conciseChannel, 0)
	linkedIDs := map[string]struct{}{}
	bridgeIDs := map[string]struct{}{}
	selected := map[string]struct{}{}

	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "!")
		if len(parts) == 0 {
			continue
		}
		row := conciseChannel{name: strings.TrimSpace(parts[0]), base: normalizeChannel(parts[0])}
		if row.name == "" || row.base == "" {
			continue
		}
		if len(parts) > 11 {
			row.linkedID = strings.TrimSpace(parts[11])
		}
		if len(parts) > 12 {
			row.bridgeID = strings.TrimSpace(parts[12])
		}
		rows = append(rows, row)
		if strings.HasPrefix(row.base, prefix) {
			selected[row.name] = struct{}{}
			if row.linkedID != "" && row.linkedID != "0" {
				linkedIDs[row.linkedID] = struct{}{}
			}
			if row.bridgeID != "" && row.bridgeID != "0" {
				bridgeIDs[row.bridgeID] = struct{}{}
			}
		}
	}

	// Repeat because a linked Local channel may reveal a bridge shared with
	// another leg that was not present on the original PJSIP row.
	for changed := true; changed; {
		changed = false
		for _, row := range rows {
			_, sameLinked := linkedIDs[row.linkedID]
			_, sameBridge := bridgeIDs[row.bridgeID]
			if !sameLinked && !sameBridge {
				continue
			}
			if _, exists := selected[row.name]; !exists {
				selected[row.name] = struct{}{}
				changed = true
			}
			if row.linkedID != "" && row.linkedID != "0" {
				if _, exists := linkedIDs[row.linkedID]; !exists {
					linkedIDs[row.linkedID] = struct{}{}
					changed = true
				}
			}
			if row.bridgeID != "" && row.bridgeID != "0" {
				if _, exists := bridgeIDs[row.bridgeID]; !exists {
					bridgeIDs[row.bridgeID] = struct{}{}
					changed = true
				}
			}
		}
	}

	// Release helper/peer legs first and the selected gateway leg last, which
	// ensures the final SIP BYE/on-hook signal is not masked by a live sibling.
	channels := make([]string, 0, len(selected))
	for _, row := range rows {
		if _, ok := selected[row.name]; ok && !strings.HasPrefix(row.base, prefix) {
			channels = append(channels, row.name)
		}
	}
	for _, row := range rows {
		if _, ok := selected[row.name]; ok && strings.HasPrefix(row.base, prefix) {
			channels = append(channels, row.name)
		}
	}
	return channels
}

// BridgeCall bridges the SIP channel of callID with a second Asterisk channel
// (typically the local channel of the node-callback leg).
func (r *Router) BridgeCall(callID, nodeChannel string) error {
	sipCh, ok := r.ChannelForCall(callID)
	if !ok {
		return fmt.Errorf("no channel tracked for call %s", callID)
	}
	return r.ami.BridgeChannels(sipCh, nodeChannel)
}

// ReloadSIP asks Asterisk to reload the PJSIP module (after config changes).
func (r *Router) ReloadSIP() error {
	_, err := r.ami.RunCommand("pjsip reload")
	return err
}

// ReloadDialplan asks Asterisk to reload the dialplan.
func (r *Router) ReloadDialplan() error {
	_, err := r.ami.RunCommand("dialplan reload")
	return err
}

// RunCommand sends an Asterisk CLI command via AMI and returns the output.
func (r *Router) RunCommand(cmd string) (string, error) {
	return r.ami.RunCommand(cmd)
}

// EndpointHasContacts returns true if the given PJSIP AoR has at least one
// registered contact. Use this to pre-flight outbound calls and give the
// caller a clear error instead of a silent immediate failure.
//
// NOTE: "pjsip show contacts <ext>" does NOT filter by AoR — it matches the
// literal string anywhere in the output, so it returns contacts belonging to
// *other* endpoints. Use "pjsip show aor <ext>" instead, which scopes the
// query to that specific AoR object. A registered contact appears as
// "<ext>/sip:..." in that output.
func (r *Router) EndpointHasContacts(ext string) bool {
	out, err := r.ami.RunCommand("pjsip show aor " + ext)
	if err != nil {
		// Cannot verify — assume contacts exist so transient AMI issues
		// don't block calls entirely.
		r.log.Warn("could not check endpoint aor via AMI",
			map[string]any{"ext": ext, "err": err.Error()})
		return true
	}
	// A registered contact always appears as "<aor>/sip:..." or "<aor>/sips:..."
	return strings.Contains(out, ext+"/sip:") || strings.Contains(out, ext+"/sips:")
}

// ContactStatuses returns live PJSIP contact state keyed by AoR/username.
func (r *Router) ContactStatuses() map[string]ContactStatus {
	out, err := r.ami.RunCommand("pjsip show contacts")
	if err != nil {
		r.log.Warn("could not list PJSIP contacts via AMI", map[string]any{"err": err.Error()})
		return map[string]ContactStatus{}
	}
	statuses := map[string]ContactStatus{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Contact:") {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "Contact:")))
		if len(fields) < 2 {
			continue
		}
		aorURI := fields[0]
		slash := strings.Index(aorURI, "/")
		if slash <= 0 {
			continue
		}
		aor := strings.TrimSpace(aorURI[:slash])
		uri := strings.TrimSpace(aorURI[slash+1:])
		if aor == "" || uri == "" {
			continue
		}
		status := ""
		latency := ""
		for i := 1; i < len(fields); i++ {
			f := strings.TrimSpace(fields[i])
			switch f {
			case "Avail", "Unavail", "Unknown", "Reachable", "NonQual":
				status = f
				if i+1 < len(fields) {
					latency = strings.Trim(fields[i+1], "()")
				}
			}
		}
		if status == "" {
			status = "Registered"
		}
		statuses[aor] = ContactStatus{
			Registered: status == "Avail" || status == "Reachable" || status == "Registered",
			Status:     status,
			URI:        uri,
			Address:    contactAddress(uri),
			LatencyMS:  latency,
		}
	}
	return statuses
}

// ---- AMI event dispatch -----------------------------------------------------

func (r *Router) onEvent(ev Event) {
	switch ev.Name {

	case "UserEvent":
		// Our dialplan fires: UserEvent(SimsonRoute,Extension:…,Caller:…,…)
		switch ev.Fields["UserEvent"] {
		case "SimsonRoute":
			r.handleSimsonRoute(ev)
		case "SimsonIntercomCallback":
			r.handleSimsonIntercomCallback(ev)
		case "SimsonDirectCall":
			r.handleSimsonDirectCall(ev)
		}

	case "Hangup":
		r.handleHangup(ev)

	case "OriginateResponse":
		r.handleOriginateResponse(ev)

	case "DTMFEnd":
		r.handleDTMF(ev)

	case "DTMF":
		// Older Asterisk releases emit a single DTMF event. Ignore an explicit
		// begin event so one key is never collected twice.
		if !strings.EqualFold(strings.TrimSpace(ev.Fields["Begin"]), "Yes") {
			r.handleDTMF(ev)
		}

	case "VarSet":
		// When Asterisk sets SIMSON_CALL_ID on a channel we can start tracking it.
		if ev.Fields["Variable"] == "SIMSON_CALL_ID" {
			callID := ev.Fields["Value"]
			channel := ev.Fields["Channel"]
			if callID != "" && channel != "" {
				r.TrackCall(callID, channel)
			}
		}
	}
}

func (r *Router) handleSimsonDirectCall(ev Event) {
	event := DirectSIPCallEvent{
		Phase:      strings.ToLower(strings.TrimSpace(ev.Fields["Phase"])),
		CallID:     strings.TrimSpace(ev.Fields["CallID"]),
		AccountID:  strings.TrimSpace(ev.Fields["AccountID"]),
		Source:     strings.TrimSpace(ev.Fields["Source"]),
		Target:     strings.TrimSpace(ev.Fields["Target"]),
		Channel:    normalizeChannel(ev.Fields["Channel"]),
		DialStatus: strings.TrimSpace(ev.Fields["DialStatus"]),
	}
	if event.CallID == "" || event.AccountID == "" || event.Source == "" || event.Target == "" {
		r.log.Warn("SimsonDirectCall event missing required fields", map[string]any{"fields": ev.Fields})
		return
	}
	if event.Phase != "ringing" && event.Phase != "active" && event.Phase != "ended" {
		r.log.Warn("SimsonDirectCall event has invalid phase", map[string]any{"phase": event.Phase, "call_id": event.CallID})
		return
	}
	if r.OnDirectSIPCall != nil {
		r.OnDirectSIPCall(event)
	}
}

func (r *Router) handleDTMF(ev Event) {
	// Asterisk 16 commonly sends DigitReceived on DTMFEnd, while other
	// versions and AMI proxies use Digit (or DTMF). Accept all completed-event
	// spellings; otherwise native blind transfer may work while Simson's
	// account-scoped conference/custom feature codes appear completely dead.
	digit := strings.TrimSpace(ev.Fields["Digit"])
	if digit == "" {
		digit = strings.TrimSpace(ev.Fields["DigitReceived"])
	}
	if digit == "" {
		digit = strings.TrimSpace(ev.Fields["DTMF"])
	}
	if digit == "" {
		digit = strings.TrimSpace(ev.Fields["Key"])
	}
	info := ChannelDTMF{
		Channel:   normalizeChannel(ev.Fields["Channel"]),
		Digit:     digit,
		Direction: strings.TrimSpace(ev.Fields["Direction"]),
	}
	if info.Channel == "" || len(info.Digit) != 1 {
		return
	}
	if info.Direction != "" && !strings.EqualFold(info.Direction, "Received") && !strings.EqualFold(info.Direction, "In") {
		return
	}
	if r.OnChannelDTMF != nil {
		// Preserve keypad order. The server callback is intentionally a
		// non-blocking queue write; dispatching one goroutine per digit can turn
		// *841026 into a different sequence on fast phones.
		r.OnChannelDTMF(info)
	}
}

func (r *Router) handleSimsonIntercomCallback(ev Event) {
	req := IntercomCallbackRequest{
		Channel:         ev.Fields["Channel"],
		SourceExtension: strings.TrimSpace(ev.Fields["Source"]),
		TargetExtension: strings.TrimSpace(ev.Fields["Target"]),
		CallerID:        strings.TrimSpace(ev.Fields["Caller"]),
		UniqueID:        ev.Fields["UniqueID"],
		SourceAutoMode:  strings.TrimSpace(ev.Fields["SourceAutoMode"]),
		TargetAutoMode:  strings.TrimSpace(ev.Fields["TargetAutoMode"]),
		ControlCode:     strings.EqualFold(strings.TrimSpace(ev.Fields["ControlCode"]), "yes"),
	}
	if req.Channel == "" || req.SourceExtension == "" || req.TargetExtension == "" {
		r.log.Warn("SimsonIntercomCallback event missing required fields", map[string]any{"fields": ev.Fields})
		return
	}
	r.log.Info("SIP intercom callback requested", map[string]any{
		"source": req.SourceExtension, "target": req.TargetExtension, "source_mode": req.SourceAutoMode, "target_mode": req.TargetAutoMode, "control_code": req.ControlCode,
	})
	if r.OnIntercomCallback != nil {
		go r.OnIntercomCallback(req)
	}
}

func (r *Router) handleSimsonRoute(ev Event) {
	channel := ev.Fields["Channel"]
	extension := strings.TrimSpace(ev.Fields["Extension"])
	callerID := strings.TrimSpace(ev.Fields["Caller"])
	callerEndpoint := strings.TrimSpace(ev.Fields["CallerEndpoint"])
	gatewaySource := strings.TrimSpace(ev.Fields["GatewaySource"])
	uniqueID := ev.Fields["UniqueID"]
	bridgeID := ev.Fields["Bridge"]

	if channel == "" || extension == "" {
		r.log.Warn("SimsonRoute event missing required fields", map[string]any{
			"fields": ev.Fields,
		})
		return
	}

	r.log.Info("incoming SIP call via AMI", map[string]any{
		"channel":         channel,
		"extension":       extension,
		"caller_id":       callerID,
		"caller_endpoint": callerEndpoint,
		"gateway_source":  gatewaySource,
	})

	if r.OnIncomingCall != nil {
		r.OnIncomingCall(IncomingSIPCall{
			Channel:        channel,
			Extension:      extension,
			CallerID:       callerID,
			CallerEndpoint: callerEndpoint,
			GatewaySource:  gatewaySource,
			UniqueID:       uniqueID,
			BridgeID:       bridgeID,
		})
	}
}

func (r *Router) handleHangup(ev Event) {
	channel := normalizeChannel(ev.Fields["Channel"])
	if channel == "" {
		return
	}

	info := ChannelHangup{
		Channel:   channel,
		Cause:     strings.TrimSpace(ev.Fields["Cause"]),
		CauseText: strings.TrimSpace(ev.Fields["Cause-txt"]),
		UniqueID:  strings.TrimSpace(ev.Fields["Uniqueid"]),
		LinkedID:  strings.TrimSpace(ev.Fields["Linkedid"]),
	}
	r.mu.RLock()
	_, _, tracked := r.findCallByChannelLocked(channel)
	r.mu.RUnlock()
	fields := map[string]any{
		"channel":    info.Channel,
		"cause":      info.Cause,
		"cause_text": info.CauseText,
		"unique_id":  info.UniqueID,
		"linked_id":  info.LinkedID,
	}
	if tracked {
		r.log.Info("asterisk channel hangup", fields)
	} else {
		// Public SIP scanners generate a large volume of rejected anonymous
		// channels. They are useful at debug level, but must not crowd out real
		// call diagnostics or grow production journals at INFO level.
		r.log.Debug("untracked asterisk channel hangup", fields)
	}

	if r.OnChannelHangup != nil {
		r.OnChannelHangup(info)
	}

	// Clean up tracking.
	r.mu.Lock()
	if callID, trackedChannel, ok := r.findCallByChannelLocked(channel); ok {
		delete(r.chanToCallID, trackedChannel)
		if tracked, exists := r.callIDToChan[callID]; exists && tracked == trackedChannel {
			delete(r.callIDToChan, callID)
		}
	}
	r.mu.Unlock()
}

func (r *Router) handleOriginateResponse(ev Event) {
	actionID := ev.Fields["ActionID"]
	if actionID == "" {
		return
	}

	r.originateMu.Lock()
	transfer, isBridgeTransfer := r.bridgeTransfers[actionID]
	if isBridgeTransfer {
		delete(r.bridgeTransfers, actionID)
	}
	callID, exists := r.actionIDToCallID[actionID]
	if exists {
		delete(r.actionIDToCallID, actionID)
	}
	r.originateMu.Unlock()

	if isBridgeTransfer {
		ok := ev.Fields["Response"] == "Success"
		channel := normalizeChannel(ev.Fields["Channel"])
		if ok && channel != "" {
			r.TrackCall(transfer.callID, channel)
		}
		result := BridgeTransferResult{
			CallID: transfer.callID, SourceChannel: transfer.sourceChannel,
			SourceExt: transfer.sourceExt, TargetExt: transfer.targetExt,
			ReplaceSource: transfer.replaceSource,
			OK:            ok, Reason: ev.Fields["Reason"], Channel: channel,
		}
		r.log.Info("bridge transfer originate result", map[string]any{
			"call_id": transfer.callID, "source": transfer.sourceExt, "target": transfer.targetExt,
			"replace_source": transfer.replaceSource,
			"ok":             ok, "reason": result.Reason, "channel": channel,
		})
		if r.OnBridgeTransfer != nil {
			go r.OnBridgeTransfer(result)
		}
		return
	}

	if !exists {
		return
	}

	ok := ev.Fields["Response"] == "Success"
	channel := normalizeChannel(ev.Fields["Channel"])

	if ok && channel != "" {
		r.TrackCall(callID, channel)
	}

	reason := ev.Fields["Reason"]
	r.log.Info("originate result", map[string]any{
		"call_id": callID,
		"ok":      ok,
		"reason":  reason,
		"channel": channel,
	})

	if r.OnOriginateResult != nil {
		r.OnOriginateResult(callID, ok, reason)
	}
}

func normalizeChannel(channel string) string {
	ch := strings.TrimSpace(channel)
	if ch == "" {
		return ""
	}
	if idx := strings.Index(ch, ";"); idx > 0 {
		ch = ch[:idx]
	}
	return ch
}

func (r *Router) findCallByChannelLocked(channel string) (callID string, trackedChannel string, ok bool) {
	if id, found := r.chanToCallID[channel]; found {
		return id, channel, true
	}

	var prefixMatchedID string
	var prefixMatchedPrefix string
	for id, prefixes := range r.callIDToChannelPrefix {
		for _, prefix := range prefixes {
			if prefix == "" || !strings.HasPrefix(channel, prefix) {
				continue
			}
			if prefixMatchedID != "" && prefixMatchedID != id {
				// Ambiguous prefix match; refuse to guess.
				return "", "", false
			}
			prefixMatchedID = id
			prefixMatchedPrefix = prefix
		}
	}
	if prefixMatchedID != "" {
		return prefixMatchedID, prefixMatchedPrefix, true
	}

	// PJSIP channel names are unique call legs. Falling back to a base key like
	// PJSIP/anonymous would collapse unrelated gateway retries/legs into the
	// active call and can end the real call when a duplicate leg hangs up.
	if strings.HasPrefix(channel, "PJSIP/") {
		return "", "", false
	}

	base := channelBaseKey(channel)
	if base == "" {
		return "", "", false
	}

	var matchedID string
	var matchedChannel string
	for ch, id := range r.chanToCallID {
		if channelBaseKey(ch) != base {
			continue
		}
		if matchedID != "" && matchedID != id {
			// Ambiguous base-channel match; refuse to guess.
			return "", "", false
		}
		matchedID = id
		matchedChannel = ch
	}
	if matchedID == "" {
		return "", "", false
	}
	return matchedID, matchedChannel, true
}

func channelBaseKey(channel string) string {
	ch := normalizeChannel(channel)
	if ch == "" {
		return ""
	}

	slash := strings.Index(ch, "/")
	if slash < 0 {
		return ch
	}

	dash := strings.LastIndex(ch, "-")
	if dash <= slash+1 || dash+1 >= len(ch) {
		return ch
	}

	suffix := ch[dash+1:]
	if len(suffix) < 6 || !isHexString(suffix) {
		return ch
	}
	return ch[:dash]
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func contactAddress(uri string) string {
	value := strings.TrimSpace(uri)
	value = strings.TrimPrefix(value, "sip:")
	value = strings.TrimPrefix(value, "sips:")
	if at := strings.LastIndex(value, "@"); at >= 0 && at+1 < len(value) {
		value = value[at+1:]
	}
	if semi := strings.Index(value, ";"); semi >= 0 {
		value = value[:semi]
	}
	return strings.TrimSpace(value)
}
