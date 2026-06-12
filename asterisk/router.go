package asterisk

import (
	"fmt"
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
	UniqueID       string // Asterisk unique call ID
	BridgeID       string // ConfBridge room the SIP channel is already parked in
}

// ContactStatus describes the live PJSIP registration/contact state for an AoR.
type ContactStatus struct {
	Registered bool   `json:"registered"`
	Status     string `json:"status,omitempty"`
	URI        string `json:"uri,omitempty"`
	Address    string `json:"address,omitempty"`
	LatencyMS  string `json:"latency_ms,omitempty"`
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
	OnIncomingCall    func(in IncomingSIPCall)                    // SIP phone dialled in
	OnChannelHangup   func(channel string)                        // SIP channel hung up
	OnOriginateResult func(callID string, ok bool, reason string) // async Originate outcome

	// call tracking
	mu                    sync.RWMutex
	chanToCallID          map[string]string   // asterisk channel → simson call ID
	callIDToChan          map[string]string   // simson call ID  → asterisk channel
	callIDToChannelPrefix map[string][]string // simson call ID → probable ringing channel prefixes

	// async originate tracking
	originateMu      sync.Mutex
	actionIDToCallID map[string]string // originate actionID → simson call ID
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
	}
	ami.OnEvent(r.onEvent)
	return r
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

// OriginateToTrunk dials an external number through an existing PJSIP trunk and
// then sends the answered leg into the same ConfBridge extension used by SIP
// phone calls.
func (r *Router) OriginateToTrunk(number, trunk, outContext, bridgeContext, bridgeExt, callerID, callID, fromNode string, timeoutSec int) (string, error) {
	if outContext == "" {
		outContext = "from-simson-out"
	}
	// Keep the Local channel from being optimized away before we can track the
	// real outbound PJSIP leg and bridge/hang it up cleanly.
	channel := fmt.Sprintf("Local/%s@%s/n", number, outContext)
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, fmt.Sprintf("Local/%s@%s-", number, outContext))

	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()

	vars := map[string]string{
		"SIMSON_CALL_ID":      callID,
		"__SIMSON_CALL_ID":    callID,
		"SIMSON_FROM_NODE":    fromNode,
		"__SIMSON_FROM_NODE":  fromNode,
		"SIMSON_TRUNK":        trunk,
		"SIMSON_WAIT_TIMEOUT": fmt.Sprintf("%d", timeoutSec),
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
		if err := r.ami.HangupChannel(ch); err != nil && firstErr == nil {
			firstErr = err
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

// HangupChannel hangs up an Asterisk channel directly by name.
func (r *Router) HangupChannel(channel string) error {
	return r.ami.HangupChannel(channel)
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
		if ev.Fields["UserEvent"] == "SimsonRoute" {
			r.handleSimsonRoute(ev)
		}

	case "Hangup":
		r.handleHangup(ev)

	case "OriginateResponse":
		r.handleOriginateResponse(ev)

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

func (r *Router) handleSimsonRoute(ev Event) {
	channel := ev.Fields["Channel"]
	extension := strings.TrimSpace(ev.Fields["Extension"])
	callerID := strings.TrimSpace(ev.Fields["Caller"])
	callerEndpoint := strings.TrimSpace(ev.Fields["CallerEndpoint"])
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
	})

	if r.OnIncomingCall != nil {
		r.OnIncomingCall(IncomingSIPCall{
			Channel:        channel,
			Extension:      extension,
			CallerID:       callerID,
			CallerEndpoint: callerEndpoint,
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

	r.log.Debug("asterisk channel hangup", map[string]any{"channel": channel})

	if r.OnChannelHangup != nil {
		r.OnChannelHangup(channel)
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
	callID, exists := r.actionIDToCallID[actionID]
	if exists {
		delete(r.actionIDToCallID, actionID)
	}
	r.originateMu.Unlock()

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
