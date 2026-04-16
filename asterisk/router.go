package asterisk

import (
	"fmt"
	"strings"
	"sync"

	"github.com/nitish-mp3/simson-vps/logging"
)

// IncomingSIPCall describes an inbound call that Asterisk has received from a
// SIP phone and delegated to the Simson routing layer.
type IncomingSIPCall struct {
	Channel   string // Asterisk channel (e.g. PJSIP/phone1-00000001)
	Extension string // extension that was dialled (e.g. "1001")
	CallerID  string // caller number / display name
	UniqueID  string // Asterisk unique call ID
	BridgeID  string // ConfBridge room the SIP channel is already parked in
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
	OnIncomingCall    func(in IncomingSIPCall)       // SIP phone dialled in
	OnChannelHangup   func(channel string)           // SIP channel hung up
	OnOriginateResult func(actionID string, ok bool) // async Originate outcome

	// call tracking
	mu           sync.Mutex
	chanToCallID map[string]string // asterisk channel → simson call ID
	callIDToChan map[string]string // simson call ID  → asterisk channel

	// async originate tracking
	originateMu      sync.Mutex
	actionIDToCallID map[string]string // originate actionID → simson call ID
}

// NewRouter creates a Router wrapping the given AMI client and registers the
// event handler. The AMI client must not be started yet.
func NewRouter(ami *AMIClient, log *logging.Logger) *Router {
	r := &Router{
		ami:              ami,
		log:              log,
		chanToCallID:     make(map[string]string),
		callIDToChan:     make(map[string]string),
		actionIDToCallID: make(map[string]string),
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

// UntrackCall removes tracking for a Simson call ID.
func (r *Router) UntrackCall(callID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ch, ok := r.callIDToChan[callID]; ok {
		delete(r.chanToCallID, ch)
	}
	delete(r.callIDToChan, callID)
}

// ChannelForCall returns the Asterisk channel for a Simson call ID.
func (r *Router) ChannelForCall(callID string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.callIDToChan[callID]
	return ch, ok
}

// CallIDForChannel returns the Simson call ID for an Asterisk channel.
func (r *Router) CallIDForChannel(channel string) (string, bool) {
	channel = normalizeChannel(channel)
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.chanToCallID[channel]
	return id, ok
}

// OriginateToExtension dials a SIP extension on behalf of a Simson node.
// bridgeExt is the extension in nodeCtx that answered SIP legs are sent to.
// Returns the AMI ActionID that can be used to match the async OriginateResponse event.
func (r *Router) OriginateToExtension(extension, context, bridgeExt, callerID, callID, fromNode string, timeoutSec int) (string, error) {
	channel := fmt.Sprintf("PJSIP/%s", extension)
	actionID, err := r.ami.Originate(channel, context, bridgeExt, callerID, callID, fromNode, timeoutSec*1000)
	if err != nil {
		return "", err
	}

	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()

	return actionID, nil
}

// HangupCall hangs up the Asterisk channel mapped to a Simson call ID.
// Silently succeeds if no channel is tracked.
func (r *Router) HangupCall(callID string) error {
	ch, ok := r.ChannelForCall(callID)
	if !ok {
		return nil
	}
	return r.ami.HangupChannel(ch)
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
	uniqueID := ev.Fields["UniqueID"]
	bridgeID := ev.Fields["Bridge"]

	if channel == "" || extension == "" {
		r.log.Warn("SimsonRoute event missing required fields", map[string]any{
			"fields": ev.Fields,
		})
		return
	}

	r.log.Info("incoming SIP call via AMI", map[string]any{
		"channel":   channel,
		"extension": extension,
		"caller_id": callerID,
	})

	if r.OnIncomingCall != nil {
		r.OnIncomingCall(IncomingSIPCall{
			Channel:   channel,
			Extension: extension,
			CallerID:  callerID,
			UniqueID:  uniqueID,
			BridgeID:  bridgeID,
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
	if callID, ok := r.chanToCallID[channel]; ok {
		delete(r.chanToCallID, channel)
		if tracked, exists := r.callIDToChan[callID]; exists && tracked == channel {
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

	r.log.Info("originate result", map[string]any{
		"call_id": callID,
		"ok":      ok,
		"reason":  ev.Fields["Reason"],
		"channel": channel,
	})

	if r.OnOriginateResult != nil {
		r.OnOriginateResult(callID, ok)
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
