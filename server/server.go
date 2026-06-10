package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/nitish-mp3/simson-vps/asterisk"
	"github.com/nitish-mp3/simson-vps/calls"
	"github.com/nitish-mp3/simson-vps/config"
	"github.com/nitish-mp3/simson-vps/hub"
	"github.com/nitish-mp3/simson-vps/logging"
	"github.com/nitish-mp3/simson-vps/protocol"
	"github.com/nitish-mp3/simson-vps/ratelimit"
	"github.com/nitish-mp3/simson-vps/store"
)

// Server is the main control-plane process.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	hub      *hub.Hub
	calls    *calls.Manager
	limiter  *ratelimit.Limiter
	log      *logging.Logger
	upgrader websocket.Upgrader
	asterisk *asterisk.Router // nil when Asterisk integration is disabled

	// recentSIPInvites tracks short-lived SIP source keys to suppress rapid
	// duplicate AMI UserEvent bursts from misdialing phones.
	recentSIPInvitesMu sync.Mutex
	recentSIPInvites   map[string]time.Time

	sipOutboundMu      sync.Mutex
	sipOutboundRetries map[string]*sipOutboundRetry

	// sipBridgeTransfers makes SIP bridge handoffs idempotent. A reconnect,
	// duplicated addon timer, or replayed authenticated WSS message must never
	// originate a second desk-phone leg for the same live bridge.
	sipBridgeTransfersMu sync.Mutex
	sipBridgeTransfers   map[string]time.Time

	doorEventMu   sync.Mutex
	doorEventLast map[string]time.Time

	asteriskStartupCleanupDone bool
}

type sipOutboundRetry struct {
	Numbers   []string
	Index     int
	Trunk     string
	BridgeID  string
	CallerID  string
	FromNode  string
	CallerExt string
}

// New constructs a Server.
func New(cfg *config.Config, st *store.Store, log *logging.Logger) *Server {
	s := &Server{
		cfg:                cfg,
		store:              st,
		hub:                hub.New(),
		calls:              calls.NewManager(),
		limiter:            ratelimit.New(cfg.RateLimitPerSec, cfg.RateLimitPerSec*2),
		log:                log,
		recentSIPInvites:   make(map[string]time.Time),
		sipOutboundRetries: make(map[string]*sipOutboundRetry),
		sipBridgeTransfers: make(map[string]time.Time),
		doorEventLast:      make(map[string]time.Time),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     func(r *http.Request) bool { return true }, // Caddy handles origin
		},
	}

	if cfg.Asterisk.Enabled {
		ami := asterisk.NewAMIClient(
			cfg.Asterisk.Host,
			cfg.Asterisk.Port,
			cfg.Asterisk.User,
			cfg.Asterisk.Secret,
			log,
		)
		router := asterisk.NewRouter(ami, log)
		router.OnIncomingCall = s.handleSIPIncomingCall
		router.OnChannelHangup = s.handleSIPChannelHangup
		router.OnOriginateResult = s.handleSIPOriginateResult
		s.asterisk = router
	}

	return s
}

// Hub returns the live session hub (for admin API).
func (s *Server) Hub() *hub.Hub { return s.hub }

// Calls returns the call manager (for admin API).
func (s *Server) Calls() *calls.Manager { return s.calls }

// Store returns the persistent store (for admin API).
func (s *Server) Store() *store.Store { return s.store }

// Asterisk returns the AMI router, or nil if Asterisk is disabled.
func (s *Server) Asterisk() *asterisk.Router { return s.asterisk }

// HandleNodeWebRTCConfig returns ICE/TURN and SIP-over-WebSocket credentials
// to an authenticated addon node. This lets browser cards join the central
// Asterisk ConfBridge without users manually copying SIP passwords into each
// addon instance.
func (s *Server) HandleNodeWebRTCConfig(w http.ResponseWriter, r *http.Request) {
	node, ok := s.authenticateNodeRequest(w, r, "webrtc-config")
	if !ok {
		return
	}
	_ = node

	iceServers := []map[string]any{}
	for _, stun := range s.cfg.ICE.STUNServers {
		iceServers = append(iceServers, map[string]any{"urls": stun})
	}
	if s.cfg.ICE.TURNEnabled && len(s.cfg.ICE.TURNURLs) > 0 {
		entry := map[string]any{
			"urls":       s.cfg.ICE.TURNURLs,
			"username":   s.cfg.ICE.TURNUsername,
			"credential": s.cfg.ICE.TURNSecret,
		}
		iceServers = append(iceServers, entry)
	}

	wsPath := s.cfg.Asterisk.SIPWebRTC.WSPath
	if wsPath == "" {
		wsPath = "/sip/ws"
	}
	sipConfig := map[string]any{
		"enabled":  s.cfg.Asterisk.Enabled && s.cfg.Asterisk.SIPWebRTC.Enabled,
		"username": s.cfg.Asterisk.SIPWebRTC.Username,
		"password": s.cfg.Asterisk.SIPWebRTC.Password,
		"domain":   s.cfg.Asterisk.SIPDomain,
		"ws_path":  wsPath,
		"ws_url":   sipWSURL(s.cfg.Asterisk.SIPDomain, wsPath),
	}

	writeNodeJSON(w, http.StatusOK, map[string]any{
		"ice_servers": iceServers,
		"sip":         sipConfig,
	})
}

func (s *Server) authenticateNodeRequest(w http.ResponseWriter, r *http.Request, purpose string) (*store.Node, bool) {
	accountID := strings.TrimSpace(r.Header.Get("X-Simson-Account-ID"))
	nodeID := strings.TrimSpace(r.Header.Get("X-Simson-Node-ID"))
	token := strings.TrimSpace(r.Header.Get("X-Simson-Install-Token"))
	if accountID == "" {
		accountID = strings.TrimSpace(r.URL.Query().Get("account_id"))
	}
	if nodeID == "" {
		nodeID = strings.TrimSpace(r.URL.Query().Get("node_id"))
	}
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("install_token"))
	}
	if accountID == "" || nodeID == "" || token == "" {
		http.Error(w, "missing node credentials", http.StatusUnauthorized)
		return nil, false
	}

	node, err := s.store.GetNode(nodeID)
	if err != nil {
		s.log.Error("node request lookup failed", map[string]any{"purpose": purpose, "err": err.Error(), "node_id": nodeID})
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	if node == nil ||
		node.AccountID != accountID ||
		!node.Enabled ||
		subtle.ConstantTimeCompare([]byte(node.AuthToken), []byte(token)) != 1 {
		s.log.Warn("node request auth failed", map[string]any{"purpose": purpose, "node_id": nodeID, "account": accountID, "ip": extractIP(r)})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return node, true
}

// HandleNodeDoorEvent starts a tenant-scoped outdoor camera SIP bridge from an
// authenticated addon. The webhook-facing addon chooses only saved presets;
// this endpoint independently verifies the node token and endpoint ownership.
func (s *Server) HandleNodeDoorEvent(w http.ResponseWriter, r *http.Request) {
	node, ok := s.authenticateNodeRequest(w, r, "door-event")
	if !ok {
		return
	}
	if s.asterisk == nil || !s.asterisk.Connected() {
		writeNodeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Asterisk integration unavailable"})
		return
	}
	var body struct {
		SourceExtension string `json:"source_extension"`
		TargetExtension string `json:"target_extension"`
		CallerID        string `json:"caller_id"`
		TriggerID       string `json:"trigger_id"`
		TimeoutSec      int    `json:"timeout_sec"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeNodeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	source := strings.TrimSpace(body.SourceExtension)
	target := strings.TrimSpace(body.TargetExtension)
	if !isSafeDoorSIPExtension(source) || !isSafeDoorSIPExtension(target) || source == target {
		writeNodeJSON(w, http.StatusBadRequest, map[string]any{"error": "source_extension and target_extension must be different numeric SIP extensions"})
		return
	}
	sourceEP, err := s.store.GetSIPEndpointByExtension(source)
	if err != nil {
		s.log.Error("door source lookup failed", map[string]any{"err": err.Error()})
		writeNodeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	targetEP, err := s.store.GetSIPEndpointByExtension(target)
	if err != nil {
		s.log.Error("door target lookup failed", map[string]any{"err": err.Error()})
		writeNodeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if sourceEP == nil || targetEP == nil || sourceEP.AccountID != node.AccountID || targetEP.AccountID != node.AccountID {
		writeNodeJSON(w, http.StatusNotFound, map[string]any{"error": "door station or indoor SIP target not found for this site"})
		return
	}
	if !sourceEP.VideoEnabled || !targetEP.VideoEnabled {
		writeNodeJSON(w, http.StatusConflict, map[string]any{"error": "enable Video capable device for both door station and indoor SIP target"})
		return
	}
	if !s.asterisk.EndpointHasContacts(source) {
		writeNodeJSON(w, http.StatusConflict, map[string]any{"error": "door station is not registered"})
		return
	}
	if !s.asterisk.EndpointHasContacts(target) {
		writeNodeJSON(w, http.StatusConflict, map[string]any{"error": "indoor SIP target is not registered"})
		return
	}
	timeoutSec := body.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 30
	}
	if timeoutSec < 5 || timeoutSec > 120 {
		writeNodeJSON(w, http.StatusBadRequest, map[string]any{"error": "timeout_sec must be between 5 and 120"})
		return
	}
	key := node.AccountID + ":" + source + ":" + target
	s.doorEventMu.Lock()
	last := s.doorEventLast[key]
	// Panels commonly repeat the same unknown-face callback while the visitor
	// remains in frame. Suppress duplicates for the configured ring window so
	// one visitor cannot create overlapping calls to the real SIP devices.
	if elapsed := time.Since(last); !last.IsZero() && elapsed < time.Duration(timeoutSec)*time.Second {
		retryAfter := int((time.Duration(timeoutSec)*time.Second - elapsed).Seconds()) + 1
		s.doorEventMu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeNodeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "door event rate limited", "retry_after": retryAfter})
		return
	}
	s.doorEventLast[key] = time.Now()
	s.doorEventMu.Unlock()

	callerID := strings.TrimSpace(body.CallerID)
	if callerID == "" {
		callerID = "\"Door Station\" <" + source + ">"
	}
	callID := "door-" + uuid.NewString()
	if _, err := s.asterisk.OriginateDoorStationCall(source, target, callerID, callID, timeoutSec); err != nil {
		s.doorEventMu.Lock()
		delete(s.doorEventLast, key)
		s.doorEventMu.Unlock()
		s.log.Error("node door station originate failed", map[string]any{"err": err.Error(), "source": source, "target": target})
		writeNodeJSON(w, http.StatusBadGateway, map[string]any{"error": "could not start door station call"})
		return
	}
	s.store.WriteAudit(node.AccountID, node.ID, "door_event_call", "trigger="+strings.TrimSpace(body.TriggerID)+" source="+source+" target="+target, extractIP(r))
	s.log.Info("node door station call started", map[string]any{"account_id": node.AccountID, "node_id": node.ID, "call_id": callID, "source": source, "target": target})
	writeNodeJSON(w, http.StatusAccepted, map[string]any{
		"call_id":          callID,
		"status":           "calling_door_station",
		"source_extension": source,
		"target_extension": target,
	})
}

// HandleNodeDoorNodeEvent starts an audio bridge between a door SIP station and
// one or more HAOS/browser nodes. This is intentionally separate from
// HandleNodeDoorEvent: native SIP-to-SIP H.264 door video is preserved there,
// while HAOS/browser cards join this ConfBridge-backed path via WebRTC audio.
func (s *Server) HandleNodeDoorNodeEvent(w http.ResponseWriter, r *http.Request) {
	node, ok := s.authenticateNodeRequest(w, r, "door-node-event")
	if !ok {
		return
	}
	if s.asterisk == nil || !s.asterisk.Connected() {
		writeNodeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Asterisk integration unavailable"})
		return
	}
	var body struct {
		SourceExtension     string   `json:"source_extension"`
		TargetNodeID        string   `json:"target_node_id"`
		TargetNodeIDs       []string `json:"target_node_ids"`
		TargetSIPExtensions []string `json:"target_sip_extensions"`
		CallerID            string   `json:"caller_id"`
		TriggerID           string   `json:"trigger_id"`
		TimeoutSec          int      `json:"timeout_sec"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeNodeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	source := strings.TrimSpace(body.SourceExtension)
	if !isSafeDoorSIPExtension(source) {
		writeNodeJSON(w, http.StatusBadRequest, map[string]any{"error": "source_extension must be a numeric SIP extension"})
		return
	}
	sourceEP, err := s.store.GetSIPEndpointByExtension(source)
	if err != nil {
		s.log.Error("door source lookup failed", map[string]any{"err": err.Error()})
		writeNodeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if sourceEP == nil || sourceEP.AccountID != node.AccountID {
		writeNodeJSON(w, http.StatusNotFound, map[string]any{"error": "door station not found for this site"})
		return
	}
	if !s.asterisk.EndpointHasContacts(source) {
		writeNodeJSON(w, http.StatusConflict, map[string]any{"error": "door station is not registered"})
		return
	}

	targetNodeIDs := make([]string, 0, len(body.TargetNodeIDs)+1)
	appendTarget := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		for _, existing := range targetNodeIDs {
			if existing == id {
				return
			}
		}
		targetNodeIDs = append(targetNodeIDs, id)
	}
	appendTarget(body.TargetNodeID)
	for _, id := range body.TargetNodeIDs {
		appendTarget(id)
	}
	onlineTargets := make([]string, 0, len(targetNodeIDs))
	for _, targetNodeID := range targetNodeIDs {
		targetNode, err := s.store.GetNode(targetNodeID)
		if err != nil {
			s.log.Error("door HAOS target lookup failed", map[string]any{"err": err.Error(), "node_id": targetNodeID})
			writeNodeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
			return
		}
		if targetNode == nil || targetNode.AccountID != node.AccountID || !targetNode.Enabled {
			writeNodeJSON(w, http.StatusNotFound, map[string]any{"error": "target HAOS node not found for this site", "target_node_id": targetNodeID})
			return
		}
		if targetSess := s.hub.Get(targetNodeID); targetSess != nil && targetSess.AccountID == node.AccountID {
			onlineTargets = append(onlineTargets, targetNodeID)
		}
	}
	targetSIPExtensions := make([]string, 0, len(body.TargetSIPExtensions))
	for _, ext := range body.TargetSIPExtensions {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		if !isSafeDoorSIPExtension(ext) || ext == source {
			writeNodeJSON(w, http.StatusBadRequest, map[string]any{"error": "target_sip_extensions must contain numeric SIP extensions different from source_extension"})
			return
		}
		already := false
		for _, existing := range targetSIPExtensions {
			if existing == ext {
				already = true
				break
			}
		}
		if already {
			continue
		}
		ep, err := s.store.GetSIPEndpointByExtension(ext)
		if err != nil {
			s.log.Error("door SIP fanout target lookup failed", map[string]any{"err": err.Error(), "ext": ext})
			writeNodeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
			return
		}
		if ep == nil || ep.AccountID != node.AccountID || !ep.Enabled {
			writeNodeJSON(w, http.StatusNotFound, map[string]any{"error": "SIP fanout target not found for this site", "target_extension": ext})
			return
		}
		if !s.asterisk.EndpointHasContacts(ext) {
			writeNodeJSON(w, http.StatusConflict, map[string]any{"error": "SIP fanout target is not registered", "target_extension": ext})
			return
		}
		targetSIPExtensions = append(targetSIPExtensions, ext)
	}

	if len(onlineTargets) == 0 && len(targetSIPExtensions) == 0 {
		writeNodeJSON(w, http.StatusConflict, map[string]any{"error": "no selected HAOS node is online and no SIP fanout target is registered"})
		return
	}

	timeoutSec := body.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 30
	}
	if timeoutSec < 5 || timeoutSec > 120 {
		writeNodeJSON(w, http.StatusBadRequest, map[string]any{"error": "timeout_sec must be between 5 and 120"})
		return
	}

	keyParts := append([]string{}, onlineTargets...)
	keyParts = append(keyParts, targetSIPExtensions...)
	key := node.AccountID + ":" + source + ":shared:" + strings.Join(keyParts, ",")
	s.doorEventMu.Lock()
	last := s.doorEventLast[key]
	if elapsed := time.Since(last); !last.IsZero() && elapsed < time.Duration(timeoutSec)*time.Second {
		retryAfter := int((time.Duration(timeoutSec)*time.Second - elapsed).Seconds()) + 1
		s.doorEventMu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeNodeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "door event rate limited", "retry_after": retryAfter})
		return
	}
	s.doorEventLast[key] = time.Now()
	s.doorEventMu.Unlock()

	callerID := strings.TrimSpace(body.CallerID)
	if callerID == "" {
		callerID = "\"Door Station\" <" + source + ">"
	}
	callID := "call_" + uuid.NewString()
	bridgeID := "bridge-" + strings.TrimPrefix(callID, "call_")
	c := &calls.Call{
		ID:          callID,
		FromNode:    "sip:" + source,
		ToNode:      firstNonEmpty(onlineTargets, targetSIPExtensions),
		InviteNodes: append([]string(nil), onlineTargets...),
		AccountID:   node.AccountID,
		CallType:    "sip",
		SIPBridgeID: bridgeID,
		CallerID:    callerID,
	}
	if !s.calls.Create(c) {
		writeNodeJSON(w, http.StatusConflict, map[string]any{"error": "duplicate call"})
		return
	}

	meta, _ := json.Marshal(map[string]string{
		"sip_bridge_id":         bridgeID,
		"sip_caller_id":         callerID,
		"sip_extension":         source,
		"door_source_extension": source,
		"door_trigger_id":       strings.TrimSpace(body.TriggerID),
		"media_mode":            "webrtc-audio",
	})
	invite := protocol.NewEnvelope(protocol.TypeCallInvite, protocol.CallInvitePayload{
		CallID:     callID,
		FromNodeID: "sip:" + source,
		FromLabel:  callerID,
		CallType:   "sip",
		Metadata:   json.RawMessage(meta),
	})
	inviteData, _ := invite.Encode()
	for _, targetNodeID := range onlineTargets {
		if targetSess := s.hub.Get(targetNodeID); targetSess != nil && targetSess.AccountID == node.AccountID {
			targetSess.Send(inviteData)
		}
	}

	if _, err := s.asterisk.OriginateDoorStationToBridge(source, bridgeID, callerID, callID, timeoutSec); err != nil {
		if ended, ok := s.calls.End(callID, "originate_failed"); ok {
			s.notifyCallStatus(ended)
		}
		s.asterisk.UntrackCall(callID)
		s.doorEventMu.Lock()
		delete(s.doorEventLast, key)
		s.doorEventMu.Unlock()
		s.log.Error("door station HAOS bridge originate failed", map[string]any{"err": err.Error(), "source": source, "targets": onlineTargets})
		writeNodeJSON(w, http.StatusBadGateway, map[string]any{"error": "could not start door station HAOS bridge"})
		return
	}

	originatedSIPExtensions := make([]string, 0, len(targetSIPExtensions))
	for _, ext := range targetSIPExtensions {
		if !s.reserveSIPBridgeTransfer(bridgeID, ext) {
			continue
		}
		if _, err := s.asterisk.OriginateToExtension(
			ext,
			s.cfg.Asterisk.NodeContext,
			bridgeID,
			callerID,
			callID,
			node.ID,
			timeoutSec,
		); err != nil {
			s.releaseSIPBridgeTransfer(bridgeID, ext)
			s.log.Warn("door SIP fanout target originate failed", map[string]any{"call_id": callID, "ext": ext, "err": err.Error()})
			continue
		}
		originatedSIPExtensions = append(originatedSIPExtensions, ext)
	}

	s.store.WriteAudit(node.AccountID, node.ID, "door_event_shared_call", "trigger="+strings.TrimSpace(body.TriggerID)+" source="+source+" haos="+strings.Join(onlineTargets, ",")+" sip="+strings.Join(originatedSIPExtensions, ","), extractIP(r))
	s.log.Info("node door station shared bridge started", map[string]any{"account_id": node.AccountID, "node_id": node.ID, "call_id": callID, "source": source, "haos_targets": onlineTargets, "sip_targets": originatedSIPExtensions, "bridge": bridgeID})
	writeNodeJSON(w, http.StatusAccepted, map[string]any{
		"call_id":               callID,
		"sip_bridge_id":         bridgeID,
		"status":                "calling_door_station",
		"source_extension":      source,
		"target_node_ids":       onlineTargets,
		"target_sip_extensions": originatedSIPExtensions,
	})
}

func firstNonEmpty(primary, secondary []string) string {
	if len(primary) > 0 && strings.TrimSpace(primary[0]) != "" {
		return primary[0]
	}
	if len(secondary) > 0 && strings.TrimSpace(secondary[0]) != "" {
		return "sip:" + strings.TrimSpace(secondary[0])
	}
	return ""
}

func isSafeDoorSIPExtension(extension string) bool {
	if len(extension) < 2 || len(extension) > 12 {
		return false
	}
	for _, ch := range extension {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func writeNodeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// HandleWS is the HTTP handler for WebSocket upgrades at /ws.
func (s *Server) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Error("ws upgrade failed", map[string]any{"err": err.Error()})
		return
	}

	remoteIP := extractIP(r)
	s.log.Debug("ws connected", map[string]any{"ip": remoteIP})

	conn.SetReadLimit(int64(s.cfg.MaxPayloadBytes))

	// First message must be "hello" within 15 seconds.
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		s.log.Warn("ws read hello failed", map[string]any{"ip": remoteIP, "err": err.Error()})
		conn.Close()
		return
	}

	env, err := protocol.DecodeEnvelope(msg)
	if err != nil || env.Type != protocol.TypeHello {
		s.sendError(conn, "", protocol.ErrCodeBadRequest, "first message must be hello")
		conn.Close()
		return
	}

	hello, err := protocol.DecodePayload[protocol.HelloPayload](env)
	if err != nil {
		s.sendError(conn, env.ID, protocol.ErrCodeBadRequest, "invalid hello payload")
		conn.Close()
		return
	}

	// Rate-limit by IP.
	if !s.limiter.Allow(remoteIP) {
		s.sendError(conn, env.ID, protocol.ErrCodeRateLimited, "rate limited")
		conn.Close()
		return
	}

	// Version check.
	if hello.ProtocolVersion != protocol.ProtocolVersion {
		s.sendError(conn, env.ID, protocol.ErrCodeVersionMismatch,
			fmt.Sprintf("protocol version mismatch: server=%s client=%s", protocol.ProtocolVersion, hello.ProtocolVersion))
		conn.Close()
		return
	}

	// Authenticate: look up node by token.
	node, err := s.store.GetNode(hello.NodeID)
	if err != nil {
		s.log.Error("db error during auth", map[string]any{"err": err.Error()})
		s.sendError(conn, env.ID, protocol.ErrCodeInternal, "internal error")
		conn.Close()
		return
	}
	if node == nil || subtle.ConstantTimeCompare([]byte(node.AuthToken), []byte(hello.InstallToken)) != 1 {
		s.log.Warn("auth failed", map[string]any{"node_id": hello.NodeID, "ip": remoteIP})
		s.store.WriteAudit(hello.AccountID, hello.NodeID, "auth_failed", "invalid token", remoteIP)
		s.sendError(conn, env.ID, protocol.ErrCodeUnauthorized, "invalid credentials")
		conn.Close()
		return
	}

	if !node.Enabled {
		s.store.WriteAudit(node.AccountID, node.ID, "auth_failed", "node disabled", remoteIP)
		s.sendError(conn, env.ID, protocol.ErrCodeForbidden, "node is disabled")
		conn.Close()
		return
	}

	// Check account.
	acct, err := s.store.GetAccount(node.AccountID)
	if err != nil || acct == nil {
		s.sendError(conn, env.ID, protocol.ErrCodeForbidden, "account not found")
		conn.Close()
		return
	}
	if acct.LicenseStatus != "active" {
		s.store.WriteAudit(node.AccountID, node.ID, "auth_failed", "license "+acct.LicenseStatus, remoteIP)
		s.sendError(conn, env.ID, protocol.ErrCodeForbidden, "account license "+acct.LicenseStatus)
		conn.Close()
		return
	}

	// Verify account ID matches.
	if node.AccountID != hello.AccountID {
		s.sendError(conn, env.ID, protocol.ErrCodeUnauthorized, "account mismatch")
		conn.Close()
		return
	}

	// Verify HMAC signature (mandatory).
	if env.Signature == "" || !env.Verify([]byte(node.AuthToken)) {
		s.store.WriteAudit(node.AccountID, node.ID, "auth_failed", "bad or missing signature", remoteIP)
		s.sendError(conn, env.ID, protocol.ErrCodeUnauthorized, "invalid or missing signature")
		conn.Close()
		return
	}

	// Auth success — create session.
	session := &hub.Session{
		Conn:         conn,
		NodeID:       node.ID,
		AccountID:    node.AccountID,
		Capabilities: hello.Capabilities,
		AddonVersion: hello.AddonVersion,
		RemoteIP:     remoteIP,
		ConnectedAt:  time.Now().UTC(),
		LastSeen:     time.Now().UTC(),
	}
	s.hub.Register(session)
	s.store.WriteAudit(node.AccountID, node.ID, "connected", "ip="+remoteIP, remoteIP)
	s.log.Info("node authenticated", map[string]any{"node_id": node.ID, "account": node.AccountID, "ip": remoteIP})

	// Send auth result.
	authResult := protocol.NewEnvelope(protocol.TypeAuthResult, protocol.AuthResultPayload{
		OK:              true,
		ServerVersion:   "1.5.0",
		ProtocolVersion: protocol.ProtocolVersion,
		HeartbeatSec:    s.cfg.HeartbeatSec,
	})
	data, _ := authResult.Encode()
	session.Send(data)

	// Enter read loop.
	s.readLoop(session)
}

// readLoop processes messages from an authenticated node.
func (s *Server) readLoop(sess *hub.Session) {
	defer func() {
		s.hub.Unregister(sess.NodeID, sess.Conn)
		sess.Conn.Close()
		s.store.WriteAudit(sess.AccountID, sess.NodeID, "disconnected", "", sess.RemoteIP)
		s.log.Info("node disconnected", map[string]any{"node_id": sess.NodeID})

		// End any in-flight calls for this node.
		activeCalls := s.calls.ActiveByNode(sess.NodeID)
		for _, c := range activeCalls {
			if c.CallType == "sip" && s.asterisk != nil {
				if err := s.asterisk.HangupCall(c.ID); err != nil {
					s.log.Warn("failed to hang up SIP call on disconnect", map[string]any{"call_id": c.ID, "err": err.Error()})
				}
			}
			if ended, ok := s.calls.End(c.ID, "disconnect"); ok {
				s.notifyCallStatus(ended)
			}
		}
	}()

	for {
		sess.Conn.SetReadDeadline(time.Now().Add(s.cfg.HeartbeatTimeout))
		_, msg, err := sess.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				s.log.Warn("ws read error", map[string]any{"node_id": sess.NodeID, "err": err.Error()})
			}
			return
		}

		sess.Touch()

		// Rate limit per node.
		if !s.limiter.Allow(sess.NodeID) {
			s.sendErrorSafe(sess, "", protocol.ErrCodeRateLimited, "rate limited")
			continue
		}

		env, err := protocol.DecodeEnvelope(msg)
		if err != nil {
			s.sendErrorSafe(sess, "", protocol.ErrCodeBadRequest, "invalid message")
			continue
		}

		switch env.Type {
		case protocol.TypeHeartbeat:
			s.handleHeartbeat(sess, env)
		case protocol.TypeCallRequest:
			s.handleCallRequest(sess, env)
		case protocol.TypeCallAccept:
			s.handleCallAccept(sess, env)
		case protocol.TypeCallReject:
			s.handleCallReject(sess, env)
		case protocol.TypeCallEnd:
			s.handleCallEnd(sess, env)
		case protocol.TypeCallTransfer:
			s.handleCallTransfer(sess, env)
		case protocol.TypeWebRTCSignal:
			s.handleWebRTCSignal(sess, env)
		case protocol.TypeUsersUpdate:
			s.handleUsersUpdate(sess, env)
		case protocol.TypeUsersQuery:
			s.handleUsersQuery(sess, env)
		default:
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "unknown message type: "+env.Type)
		}
	}
}

// --- Heartbeat ---

func (s *Server) handleHeartbeat(sess *hub.Session, env *protocol.Envelope) {
	ack := protocol.NewEnvelope(protocol.TypeHeartbeatAck, protocol.HeartbeatAckPayload{
		ServerTime: time.Now().UTC(),
	})
	data, _ := ack.Encode()
	sess.Send(data)
}

// --- Call Request ---

func (s *Server) handleCallRequest(sess *hub.Session, env *protocol.Envelope) {
	req, err := protocol.DecodePayload[protocol.CallRequestPayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid call.request payload")
		return
	}

	// Validate: from_node_id must match session.
	if req.FromNodeID != sess.NodeID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "from_node_id mismatch")
		return
	}

	// ── SIP extension target: "sip:EXTENSION" ─────────────────────────────────
	// When a node wants to call an IP phone managed by the central VPS Asterisk,
	// it sets to_node_id = "sip:1001".  Route via AMI instead of WebSocket.
	if strings.HasPrefix(req.ToNodeID, "sip:") {
		s.handleSIPCallRequest(sess, env, req)
		return
	}

	// Validate target node exists and belongs to the same account or is reachable.
	targetNode, err := s.store.GetNode(req.ToNodeID)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "internal error")
		return
	}
	if targetNode == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "target node not found")
		return
	}
	if !targetNode.Enabled {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "target node is disabled")
		return
	}

	// Cross-account call isolation: nodes can only call within their own account.
	if targetNode.AccountID != sess.AccountID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "target node belongs to a different account")
		return
	}

	// Check account-level limits.
	acct, _ := s.store.GetAccount(sess.AccountID)
	if acct != nil {
		activeCalls := s.calls.CountActiveByAccount(sess.AccountID)
		if activeCalls >= acct.MaxCalls {
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeLimitExceeded, "concurrent call limit reached")
			return
		}
	}

	// Check target is online.
	if !s.hub.IsOnline(req.ToNodeID) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNodeOffline, "target node is offline")
		s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_failed", "target offline: "+req.ToNodeID, sess.RemoteIP)
		return
	}

	// Generate call ID if not provided.
	callID := req.CallID
	if callID == "" {
		callID = "call_" + uuid.NewString()
	}

	// Create call record.
	c := &calls.Call{
		ID:        callID,
		FromNode:  sess.NodeID,
		ToNode:    req.ToNodeID,
		AccountID: sess.AccountID,
		CallType:  req.CallType,
	}
	if !s.calls.Create(c) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "duplicate call ID")
		return
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_request", fmt.Sprintf("call=%s to=%s", callID, req.ToNodeID), sess.RemoteIP)
	s.log.Info("call request", map[string]any{"call_id": callID, "from": sess.NodeID, "to": req.ToNodeID})

	// Get caller node label for the invite.
	callerNode, _ := s.store.GetNode(sess.NodeID)
	fromLabel := ""
	if callerNode != nil {
		fromLabel = callerNode.Label
	}

	// Send invite to target.
	invite := protocol.NewEnvelope(protocol.TypeCallInvite, protocol.CallInvitePayload{
		CallID:     callID,
		FromNodeID: sess.NodeID,
		FromLabel:  fromLabel,
		CallType:   req.CallType,
		Metadata:   req.Metadata,
	})
	inviteData, _ := invite.Encode()

	targetSess := s.hub.Get(req.ToNodeID)
	if targetSess == nil {
		s.calls.End(callID, "target_disappeared")
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNodeOffline, "target node went offline")
		return
	}
	if err := targetSess.Send(inviteData); err != nil {
		s.calls.End(callID, "send_failed")
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "failed to reach target")
		return
	}

	// Notify caller that ring started.
	status := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
		CallID: callID,
		Status: string(calls.StateRinging),
	})
	statusData, _ := status.Encode()
	sess.Send(statusData)
}

// --- Call Accept ---

func (s *Server) handleCallAccept(sess *hub.Session, env *protocol.Envelope) {
	payload, err := protocol.DecodePayload[protocol.CallAcceptPayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid call.accept payload")
		return
	}

	// Verify the accepter is an invited target BEFORE mutating state.
	existing := s.calls.Get(payload.CallID)
	if existing == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
		return
	}
	if !existing.CanNodeAnswer(sess.NodeID) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "not the call target")
		return
	}

	invitedNodes := s.calls.Invitees(payload.CallID)
	c, ok := s.calls.Accept(payload.CallID, sess.NodeID)
	if !ok {
		// Active SIP bridge calls may be answered by a transfer target. In that
		// case the external/SIP leg stays up and only the browser participant
		// changes.
		c, previousNode, transferred := s.calls.AcceptTransfer(payload.CallID, sess.NodeID)
		if !transferred {
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found or not ringing")
			return
		}

		answeredBy := payload.AnsweredByUserID
		s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_transfer_accepted", "call="+payload.CallID, sess.RemoteIP)
		s.log.Info("call transfer accepted", map[string]any{"call_id": payload.CallID, "answered_by": sess.NodeID})
		s.notifyCallStatusToNode(sess.NodeID, c, string(calls.StateActive), "", answeredBy)
		if previousNode != "" && previousNode != sess.NodeID {
			s.notifyCallStatusToNode(previousNode, c, string(calls.StateEnded), "transferred", answeredBy)
		}
		return
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_accepted", "call="+payload.CallID, sess.RemoteIP)
	s.log.Info("call accepted", map[string]any{"call_id": payload.CallID, "answered_by": payload.AnsweredByUserID})

	// Include answered_by_user_id so call-all participants can dismiss.
	answeredBy := payload.AnsweredByUserID

	// Notify caller.
	callerSess := s.hub.Get(c.FromNode)
	if callerSess != nil {
		status := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
			CallID:           c.ID,
			Status:           string(calls.StateActive),
			SIPBridgeID:      c.SIPBridgeID,
			AnsweredByUserID: answeredBy,
		})
		data, _ := status.Encode()
		callerSess.Send(data)
	}

	// Notify callee too.
	calleeStatus := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
		CallID:           c.ID,
		Status:           string(calls.StateActive),
		SIPBridgeID:      c.SIPBridgeID,
		AnsweredByUserID: answeredBy,
	})
	data, _ := calleeStatus.Encode()
	sess.Send(data)

	// For SIP fan-out calls, clear the ringing popup on every node that did
	// not answer. The accepting node receives "active" above.
	for _, nodeID := range invitedNodes {
		if nodeID == "" || nodeID == sess.NodeID {
			continue
		}
		s.notifyCallStatusToNode(nodeID, c, string(calls.StateEnded), "answered_elsewhere", answeredBy)
	}
}

// --- Call Reject ---

func (s *Server) handleCallReject(sess *hub.Session, env *protocol.Envelope) {
	payload, err := protocol.DecodePayload[protocol.CallRejectPayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid call.reject payload")
		return
	}

	// Verify the rejecter is an invited target BEFORE mutating state.
	existing := s.calls.Get(payload.CallID)
	if existing == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
		return
	}
	if !existing.CanNodeAnswer(sess.NodeID) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "not the call target")
		return
	}

	if existing.State == calls.StateActive && sess.NodeID != existing.FromNode && sess.NodeID != existing.ToNode {
		c, ok := s.calls.RemoveInvitee(payload.CallID, sess.NodeID)
		if !ok {
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
			return
		}
		s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_transfer_rejected", "call="+payload.CallID+" reason="+payload.Reason, sess.RemoteIP)
		s.log.Info("call transfer rejected", map[string]any{"call_id": payload.CallID, "node_id": sess.NodeID})
		s.notifyCallStatusToNode(sess.NodeID, c, string(calls.StateEnded), "rejected", "")
		return
	}

	// In a SIP fan-out call, one support node declining should not cancel the
	// caller for every other available support node.
	if len(existing.InviteNodes) > 1 {
		c, keepRinging, ok := s.calls.DeclineByNode(payload.CallID, sess.NodeID, "rejected")
		if !ok {
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found or already ended")
			return
		}
		s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_rejected", "call="+payload.CallID+" reason="+payload.Reason, sess.RemoteIP)
		s.log.Info("call invite rejected", map[string]any{"call_id": payload.CallID, "node_id": sess.NodeID, "keep_ringing": keepRinging})
		s.notifyCallStatusToNode(sess.NodeID, c, string(calls.StateEnded), "rejected", "")
		if !keepRinging {
			s.notifyCallStatus(c)
		}
		return
	}

	c, ok := s.calls.End(payload.CallID, "rejected")
	if !ok {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found or already ended")
		return
	}

	if existing.CallType == "sip" && s.asterisk != nil {
		s.clearSIPOutboundRetry(payload.CallID)
		go func() {
			if err := s.asterisk.HangupCall(payload.CallID); err != nil {
				s.log.Warn("failed to hang up SIP leg after reject",
					map[string]any{"call_id": payload.CallID, "err": err.Error()})
			}
			s.asterisk.UntrackCall(payload.CallID)
		}()
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_rejected", "call="+payload.CallID+" reason="+payload.Reason, sess.RemoteIP)
	s.log.Info("call rejected", map[string]any{"call_id": payload.CallID, "reason": payload.Reason})

	s.notifyCallStatus(c)
}

// --- Call End ---

func (s *Server) handleCallEnd(sess *hub.Session, env *protocol.Envelope) {
	payload, err := protocol.DecodePayload[protocol.CallEndPayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid call.end payload")
		return
	}

	reason := payload.Reason
	if reason == "" {
		reason = "hangup"
	}

	// Verify the ender is a participant BEFORE mutating state.
	existing := s.calls.Get(payload.CallID)
	if existing == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
		return
	}
	if sess.NodeID != existing.FromNode && sess.NodeID != existing.ToNode && !existing.CanNodeAnswer(sess.NodeID) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "not a participant")
		return
	}

	c, ok := s.calls.End(payload.CallID, reason)
	if !ok {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found or already ended")
		return
	}

	if existing.CallType == "sip" && s.asterisk != nil {
		s.clearSIPOutboundRetry(payload.CallID)
		go func() {
			if err := s.asterisk.HangupCall(payload.CallID); err != nil {
				s.log.Warn("failed to hang up SIP leg", map[string]any{"call_id": payload.CallID, "err": err.Error()})
			}
			s.asterisk.UntrackCall(payload.CallID)
		}()
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_ended", "call="+payload.CallID+" reason="+reason, sess.RemoteIP)
	s.log.Info("call ended", map[string]any{"call_id": payload.CallID, "reason": reason})

	s.notifyCallStatus(c)
}

// --- Call Transfer ---

func (s *Server) handleCallTransfer(sess *hub.Session, env *protocol.Envelope) {
	payload, err := protocol.DecodePayload[protocol.CallTransferPayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid call.transfer payload")
		return
	}

	callID := strings.TrimSpace(payload.CallID)
	targetNodeID := strings.TrimSpace(payload.TargetNodeID)
	if callID == "" || targetNodeID == "" {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "call_id and target_node_id are required")
		return
	}
	if payload.FromNodeID != "" && payload.FromNodeID != sess.NodeID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "from_node_id mismatch")
		return
	}

	c := s.calls.Get(callID)
	if c == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
		return
	}
	if (c.State != calls.StateActive && c.State != calls.StateRinging) || c.SIPBridgeID == "" {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "only active/ringing SIP gateway calls can be transferred")
		return
	}
	if c.FromNode != sess.NodeID && c.ToNode != sess.NodeID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "not a call participant")
		return
	}

	if strings.HasPrefix(strings.ToLower(targetNodeID), "sip:") {
		s.handleSIPBridgeTransfer(sess, env, c, strings.TrimPrefix(targetNodeID, "sip:"))
		return
	}

	targetSess := s.hub.Get(targetNodeID)
	if targetSess == nil || targetSess.AccountID != sess.AccountID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNodeOffline, "target node is offline")
		return
	}
	if len(s.calls.ActiveByNode(targetNodeID)) > 0 {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeLimitExceeded, "target node is busy")
		return
	}
	if _, ok := s.calls.AddInvitee(callID, targetNodeID); !ok {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
		return
	}

	remoteNode := c.FromNode
	if remoteNode == sess.NodeID {
		remoteNode = c.ToNode
	}
	meta, _ := json.Marshal(map[string]any{
		"sip_bridge_id":    c.SIPBridgeID,
		"transfer":         true,
		"transfer_from":    sess.NodeID,
		"target_user_id":   strings.TrimSpace(payload.TargetUserID),
		"target_user_name": strings.TrimSpace(payload.TargetUserName),
	})
	invite := protocol.NewEnvelope(protocol.TypeCallInvite, protocol.CallInvitePayload{
		CallID:     c.ID,
		FromNodeID: remoteNode,
		FromLabel:  "Transferred call",
		CallType:   c.CallType,
		Metadata:   json.RawMessage(meta),
	})
	data, _ := invite.Encode()
	if err := targetSess.Send(data); err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "failed to reach transfer target")
		return
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_transfer",
		fmt.Sprintf("call=%s target=%s", callID, targetNodeID), sess.RemoteIP)
	s.log.Info("call transfer invite sent", map[string]any{
		"call_id": callID, "from": sess.NodeID, "target": targetNodeID,
	})
}

func (s *Server) handleSIPBridgeTransfer(sess *hub.Session, env *protocol.Envelope, c *calls.Call, ext string) {
	if s.asterisk == nil || !s.asterisk.Connected() {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "central Asterisk AMI is not connected")
		return
	}

	ext = strings.TrimSpace(ext)
	if ext == "" || isExternalDialString(ext) || !isLikelyInternalExtension(ext) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid SIP extension transfer target")
		return
	}

	ep, err := s.store.GetSIPEndpointByExtension(ext)
	if err != nil {
		s.log.Error("db error looking up transfer SIP endpoint", map[string]any{"err": err.Error(), "ext": ext})
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "internal error")
		return
	}
	if ep == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "SIP extension not found: "+ext)
		return
	}
	if ep.AccountID != sess.AccountID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "SIP extension belongs to a different account")
		return
	}
	if !ep.Enabled {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "SIP extension is disabled")
		return
	}
	if !s.asterisk.EndpointHasContacts(ext) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeSIPUnavailable,
			fmt.Sprintf("SIP phone %q is not registered. Check the phone's SIP account settings.", ext))
		return
	}
	if !s.reserveSIPBridgeTransfer(c.SIPBridgeID, ext) {
		s.log.Warn("suppressing duplicate SIP bridge transfer",
			map[string]any{"call_id": c.ID, "bridge": c.SIPBridgeID, "ext": ext, "node_id": sess.NodeID})
		return
	}

	callerID := formatSIPCallerID("Transferred call", ext)
	if strings.TrimSpace(c.CallerID) != "" {
		callerID = formatSIPCallerID(c.CallerID, c.CallerID)
	} else if node, _ := s.store.GetNode(sess.NodeID); node != nil && node.Label != "" {
		callerID = formatSIPCallerID(node.Label, "100")
	}

	_, err = s.asterisk.OriginateToExtension(
		ext,
		s.cfg.Asterisk.NodeContext,
		c.SIPBridgeID,
		callerID,
		c.ID,
		sess.NodeID,
		s.cfg.CallTimeoutSec,
	)
	if err != nil {
		s.releaseSIPBridgeTransfer(c.SIPBridgeID, ext)
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "AMI originate failed: "+err.Error())
		return
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "sip_bridge_transfer",
		fmt.Sprintf("call=%s ext=%s", c.ID, ext), sess.RemoteIP)
	s.log.Info("SIP bridge transfer originated", map[string]any{
		"call_id": c.ID, "from": sess.NodeID, "ext": ext,
	})
}

func (s *Server) reserveSIPBridgeTransfer(bridgeID, ext string) bool {
	bridgeID = strings.TrimSpace(bridgeID)
	ext = strings.TrimSpace(ext)
	if bridgeID == "" || ext == "" {
		return false
	}

	now := time.Now().UTC()
	key := strings.ToLower(bridgeID + "|" + ext)

	s.sipBridgeTransfersMu.Lock()
	defer s.sipBridgeTransfersMu.Unlock()

	// Bridge IDs are unique per call. Opportunistic cleanup keeps the replay
	// guard bounded without allowing a long-running call to ring repeatedly.
	for existing, createdAt := range s.sipBridgeTransfers {
		if now.Sub(createdAt) > 24*time.Hour {
			delete(s.sipBridgeTransfers, existing)
		}
	}
	if _, exists := s.sipBridgeTransfers[key]; exists {
		return false
	}
	s.sipBridgeTransfers[key] = now
	return true
}

func (s *Server) releaseSIPBridgeTransfer(bridgeID, ext string) {
	key := strings.ToLower(strings.TrimSpace(bridgeID) + "|" + strings.TrimSpace(ext))
	if key == "|" {
		return
	}
	s.sipBridgeTransfersMu.Lock()
	delete(s.sipBridgeTransfers, key)
	s.sipBridgeTransfersMu.Unlock()
}

// --- WebRTC Signal Relay ---

func (s *Server) handleWebRTCSignal(sess *hub.Session, env *protocol.Envelope) {
	payload, err := protocol.DecodePayload[protocol.WebRTCSignalPayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid webrtc.signal payload")
		return
	}

	// Validate sender.
	if payload.FromNodeID != sess.NodeID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "from_node_id mismatch")
		return
	}

	// Verify target is in the same account.
	targetSess := s.hub.Get(payload.ToNodeID)
	if targetSess == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNodeOffline, "target node not online")
		return
	}
	if targetSess.AccountID != sess.AccountID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "target node belongs to a different account")
		return
	}

	// Verify the call exists and both parties are participants.
	c := s.calls.Get(payload.CallID)
	if c == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
		return
	}

	// Forward the signal as-is to the target node.
	fwd := protocol.NewEnvelope(protocol.TypeWebRTCSignal, protocol.WebRTCSignalPayload{
		CallID:     payload.CallID,
		FromNodeID: payload.FromNodeID,
		ToNodeID:   payload.ToNodeID,
		SignalType: payload.SignalType,
		Data:       payload.Data,
	})
	data, _ := fwd.Encode()
	if err := targetSess.Send(data); err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "failed to relay signal")
	}
}

// --- Users Update ---

func (s *Server) handleUsersUpdate(sess *hub.Session, env *protocol.Envelope) {
	payload, err := protocol.DecodePayload[protocol.UsersUpdatePayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid users.update payload")
		return
	}

	// Validate sender.
	if payload.NodeID != sess.NodeID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "node_id mismatch")
		return
	}

	// Convert to hub.UserPresence and store in session.
	users := make([]hub.UserPresence, 0, len(payload.Users))
	for _, u := range payload.Users {
		users = append(users, hub.UserPresence{
			UserID:   u.UserID,
			UserName: u.UserName,
			LastSeen: time.Now().UTC(),
		})
	}
	sess.SetUsers(users)

	s.log.Debug("users updated", map[string]any{
		"node_id": sess.NodeID, "user_count": len(users),
	})
}

// --- Users Query ---

func (s *Server) handleUsersQuery(sess *hub.Session, env *protocol.Envelope) {
	payload, err := protocol.DecodePayload[protocol.UsersQueryPayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid users.query payload")
		return
	}

	// Verify target node belongs to same account.
	targetSess := s.hub.Get(payload.TargetNodeID)
	if targetSess == nil {
		// Node offline — return empty list (not an error).
		resp := protocol.NewEnvelope(protocol.TypeUsersList, protocol.UsersListPayload{
			NodeID: payload.TargetNodeID,
			Users:  []protocol.UserPresenceEntry{},
			Ref:    env.ID,
		})
		data, _ := resp.Encode()
		sess.Send(data)
		return
	}
	if targetSess.AccountID != sess.AccountID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "target node belongs to a different account")
		return
	}

	// Get users from target session.
	hubUsers := targetSess.GetUsers()
	users := make([]protocol.UserPresenceEntry, 0, len(hubUsers))
	for _, u := range hubUsers {
		users = append(users, protocol.UserPresenceEntry{
			UserID:   u.UserID,
			UserName: u.UserName,
		})
	}

	resp := protocol.NewEnvelope(protocol.TypeUsersList, protocol.UsersListPayload{
		NodeID: payload.TargetNodeID,
		Users:  users,
		Ref:    env.ID,
	})
	data, _ := resp.Encode()
	sess.Send(data)
}

// --- Helpers ---

// notifyCallStatus sends a call.status to both participants.
func (s *Server) notifyCallStatus(c *calls.Call) {
	status := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
		CallID:      c.ID,
		Status:      string(c.State),
		Reason:      c.EndReason,
		SIPBridgeID: c.SIPBridgeID,
	})
	data, _ := status.Encode()

	if fromSess := s.hub.Get(c.FromNode); fromSess != nil {
		fromSess.Send(data)
	}
	if toSess := s.hub.Get(c.ToNode); toSess != nil {
		toSess.Send(data)
	}
	for _, nodeID := range c.InviteNodes {
		if nodeID == "" || nodeID == c.FromNode || nodeID == c.ToNode {
			continue
		}
		if nodeSess := s.hub.Get(nodeID); nodeSess != nil {
			nodeSess.Send(data)
		}
	}
}

func (s *Server) notifyCallStatusToNode(nodeID string, c *calls.Call, status, reason, answeredBy string) {
	if nodeID == "" {
		return
	}
	nodeSess := s.hub.Get(nodeID)
	if nodeSess == nil {
		return
	}
	env := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
		CallID:           c.ID,
		Status:           status,
		Reason:           reason,
		SIPBridgeID:      c.SIPBridgeID,
		AnsweredByUserID: answeredBy,
	})
	data, _ := env.Encode()
	nodeSess.Send(data)
}

// ---- Central VPS Asterisk (SIP) handlers ------------------------------------

// handleSIPCallRequest handles call.request when to_node_id = "sip:EXTENSION".
// It looks up the SIP endpoint in the DB and originates a call via Asterisk AMI.
func (s *Server) handleSIPCallRequest(sess *hub.Session, env *protocol.Envelope, req *protocol.CallRequestPayload) {
	if s.asterisk == nil || !s.asterisk.Connected() {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal,
			"central Asterisk AMI is not connected; set asterisk.enabled=true in server config")
		return
	}

	ext := strings.TrimPrefix(req.ToNodeID, "sip:")
	if ext == "" {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "empty SIP extension in to_node_id")
		return
	}

	callerID := ""
	trunk := ""
	if len(req.Metadata) > 0 {
		var metaMap map[string]any
		if err := json.Unmarshal(req.Metadata, &metaMap); err == nil {
			if v, ok := metaMap["caller_id"]; ok {
				if s, ok := v.(string); ok {
					callerID = s
				}
			}
			if v, ok := metaMap["trunk"]; ok {
				if s, ok := v.(string); ok {
					trunk = strings.TrimSpace(s)
				}
			}
		}
	}

	originalExt := ext
	ep, err := s.store.GetSIPEndpointByExtension(ext)
	if err != nil {
		s.log.Error("db error looking up SIP endpoint", map[string]any{"err": err.Error()})
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "internal error")
		return
	}
	if ep != nil && ep.AccountID != sess.AccountID {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "SIP extension belongs to a different account")
		return
	}
	if ep != nil && !ep.Enabled {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "SIP extension is disabled")
		return
	}

	// Check account call limits.
	acct, _ := s.store.GetAccount(sess.AccountID)
	if acct != nil {
		if s.calls.CountActiveByAccount(sess.AccountID) >= acct.MaxCalls {
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeLimitExceeded, "concurrent call limit reached")
			return
		}
	}

	callID := req.CallID
	if callID == "" {
		callID = "call_" + uuid.NewString()
	}
	bridgeID := "bridge-" + strings.TrimPrefix(callID, "call_")
	dialCandidates := []string(nil)

	if ep == nil && trunk == "" && isExternalDialString(ext) {
		trunk = strings.TrimSpace(s.cfg.Asterisk.DefaultPSTNTrunk)
		if trunk == "" {
			trunk = "7009"
		}
	}
	if ep == nil && trunk != "" {
		rawDigits := digitsOnly(ext)
		rawDigits = stripOutboundTrunkPrefix(rawDigits, trunk)
		ext = normalizePSTNDigits(rawDigits, trunk, s.cfg.Asterisk.DefaultPSTNTrunk)
		dialCandidates = outboundGatewayDialCandidates(rawDigits, ext)
	}

	c := &calls.Call{
		ID:          callID,
		FromNode:    sess.NodeID,
		ToNode:      "sip:" + ext, // virtual node ID for the SIP side
		AccountID:   sess.AccountID,
		CallType:    "sip",
		SIPBridgeID: bridgeID,
	}
	if !s.calls.Create(c) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "duplicate call ID")
		return
	}

	if callerID == "" {
		label := sess.NodeID
		if node, _ := s.store.GetNode(sess.NodeID); node != nil && node.Label != "" {
			label = node.Label
		}
		// SIP CallerID format: "Display Name" <number>
		// Use 100 as a callback extension the phone can redial.
		// Any number works because from-simson-sip catches _X.
		callerID = fmt.Sprintf("\"%s\" <100>", label)
	}

	if ep == nil {
		if trunk == "" {
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "SIP extension not registered: "+originalExt)
			return
		}
		if !isSafeDialNumber(ext) || !isSafeAsteriskName(trunk) {
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid outbound trunk target")
			return
		}
	} else {
		// Pre-flight: verify the SIP phone has at least one registered contact.
		// This prevents a silent immediate failure when the phone is offline or
		// misconfigured, and gives the caller a meaningful error message.
		if !s.asterisk.EndpointHasContacts(ext) {
			if c2, ended := s.calls.End(callID, "phone_unavailable"); ended {
				s.notifyCallStatus(c2)
			}
			s.log.Warn("SIP phone has no registered contacts — rejecting call",
				map[string]any{"ext": ext, "call_id": callID})
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeSIPUnavailable,
				fmt.Sprintf("SIP phone %q is not registered. Check the phone's SIP account settings (server: %s, username: %s).",
					ext, s.cfg.Asterisk.SIPDomain, ext))
			return
		}
	}

	// Notify the caller of ringing BEFORE the async Originate fires.
	// This guarantees the addon always sees "ringing" before any AMI result
	// event, eliminating the race between the ReadLoop goroutine and this handler.
	s.notifyCallStatus(c)

	// Originate the call via AMI. NodeContext contains the bridge-joining
	// dialplan (extension _bridge-.) that the answered leg joins.
	if trunk != "" {
		if len(dialCandidates) == 0 {
			dialCandidates = []string{ext}
		}
		s.setSIPOutboundRetry(callID, &sipOutboundRetry{
			Numbers:  dialCandidates,
			Trunk:    trunk,
			BridgeID: bridgeID,
			CallerID: callerID,
			FromNode: sess.NodeID,
		})
		if !s.trySIPPhoneOutboundGateway(callID) {
			s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "AMI originate failed")
			return
		}
	} else {
		_, err = s.asterisk.OriginateToExtension(
			ext,
			s.cfg.Asterisk.NodeContext,
			bridgeID,
			callerID,
			callID,
			sess.NodeID,
			s.cfg.CallTimeoutSec,
		)
	}
	if err != nil {
		if c2, ended := s.calls.End(callID, "originate_failed"); ended {
			s.notifyCallStatus(c2)
		}
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "AMI originate failed: "+err.Error())
		return
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "sip_call_request",
		fmt.Sprintf("call=%s ext=%s", callID, ext), sess.RemoteIP)
	s.log.Info("SIP call originated", map[string]any{
		"call_id": callID, "ext": ext, "from": sess.NodeID, "trunk": trunk, "candidates": strings.Join(dialCandidates, ","),
	})
}

// handleSIPIncomingCall is the AMI callback for an incoming SIP call.
// It routes the call to the correct Simson node based on the dialled extension.
//
// Routing priority:
//  1. Dialled extension matches a SIP endpoint with RouteTo set → ring that node.
//  2. Dialled extension matches a SIP endpoint with RouteTo empty → ring all online nodes.
//  3. No matching endpoint → identify the caller’s account from the channel and ring
//     all online nodes in that account (allows a SIP phone to reach any node).
func (s *Server) handleSIPIncomingCall(in asterisk.IncomingSIPCall) {
	// Step 1: try to find a SIP endpoint matching the dialled extension.
	ep, err := s.store.GetSIPEndpointByExtension(in.Extension)
	if err != nil {
		s.log.Error("db error looking up SIP endpoint", map[string]any{"err": err.Error()})
		if s.asterisk != nil {
			s.hangupAsteriskChannelAsync(in.Channel, "SIP route has no account")
		}
		return
	}

	var accountID string
	var routeTo string
	sourceExt := strings.TrimSpace(in.Extension)

	if ep != nil {
		accountID = ep.AccountID
		routeTo = ep.RouteTo
		sourceExt = ep.Extension
	} else {
		// Step 2: no matching dialled endpoint — identify the caller’s account
		// from the Asterisk channel name (e.g. "PJSIP/7001-00000001" → ext
		// "7001"). For gateway-style endpoints, RouteTo on the caller endpoint
		// is the preferred destination for PSTN/GSM calls forwarded into Simson.
		callerExt, callerEP := s.resolveIncomingSIPCallerEndpoint(in)
		if callerEP == nil {
			s.log.Warn("caller endpoint not found — hanging up",
				map[string]any{
					"caller_ext":      callerExt,
					"caller_id":       in.CallerID,
					"caller_endpoint": in.CallerEndpoint,
					"extension":       in.Extension,
					"channel":         in.Channel,
				})
			if s.asterisk != nil {
				s.hangupAsteriskChannelAsync(in.Channel, "caller endpoint not found")
			}
			return
		}

		if isExternalDialString(in.Extension) {
			// This path runs from an AMI UserEvent. Originate must not block
			// the AMI read loop, otherwise its own response cannot be read.
			go s.handleSIPPhoneOutboundGateway(in, callerEP)
			return
		}

		// Unknown external-looking numbers should not be dispatched to nodes.
		// A configured SIP endpoint may still intentionally use a DID/landline
		// number as its extension, so this check must happen after endpoint lookup.
		if len(in.Extension) > 15 {
			s.log.Warn("rejecting unknown external-looking extension",
				map[string]any{"extension": in.Extension, "channel": in.Channel})
			if s.asterisk != nil {
				s.hangupAsteriskChannelAsync(in.Channel, "unknown external-looking extension")
			}
			return
		}
		if !isLikelyInternalExtension(in.Extension) {
			s.log.Warn("rejecting unknown non-internal extension",
				map[string]any{"extension": in.Extension, "channel": in.Channel, "caller_id": in.CallerID})
			if s.asterisk != nil {
				s.hangupAsteriskChannelAsync(in.Channel, "unknown non-internal extension")
			}
			return
		}
		accountID = callerEP.AccountID
		routeTo = callerEP.RouteTo
		sourceExt = callerEP.Extension
	}

	if s.shouldSuppressIncomingSIPInvite(accountID, in, sourceExt) {
		s.log.Warn("suppressing duplicate SIP incoming invite",
			map[string]any{"extension": in.Extension, "source_ext": sourceExt, "caller_id": in.CallerID, "channel": in.Channel, "bridge": in.BridgeID})
		if s.asterisk != nil {
			s.hangupAsteriskChannelAsync(in.Channel, "no route target")
		}
		return
	}

	// Collect target nodes, prioritizing those without active calls.
	var targetNodeIDs []string
	appendUnique := func(nodeID string) {
		if nodeID == "" {
			return
		}
		for _, existing := range targetNodeIDs {
			if existing == nodeID {
				return
			}
		}
		targetNodeIDs = append(targetNodeIDs, nodeID)
	}

	var available, busy []string
	for _, sess := range s.hub.ListByAccount(accountID) {
		if len(s.calls.ActiveByNode(sess.NodeID)) == 0 {
			available = append(available, sess.NodeID)
		} else {
			busy = append(busy, sess.NodeID)
		}
	}

	if routeTo != "" {
		if s.hub.IsOnline(routeTo) && len(s.calls.ActiveByNode(routeTo)) == 0 {
			appendUnique(routeTo)
		} else {
			// Configured route_to node is offline or busy — fall back to available
			// support nodes first, then let busy nodes ring only as a last resort.
			reason := "offline"
			if s.hub.IsOnline(routeTo) {
				reason = "busy"
			}
			s.log.Warn("route_to node unavailable, falling back to support nodes",
				map[string]any{"route_to": routeTo, "reason": reason, "extension": in.Extension})
			for _, nodeID := range available {
				appendUnique(nodeID)
			}
			if reason == "busy" {
				appendUnique(routeTo)
			}
		}
		for _, nodeID := range busy {
			appendUnique(nodeID)
		}
	} else {
		for _, nodeID := range available {
			appendUnique(nodeID)
		}
		for _, nodeID := range busy {
			appendUnique(nodeID)
		}
	}

	if len(targetNodeIDs) == 0 {
		s.log.Warn("no online target node for SIP call — hanging up",
			map[string]any{"extension": in.Extension})
		if s.asterisk != nil {
			s.hangupAsteriskChannelAsync(in.Channel, "no online target")
		}
		return
	}

	primaryNode := targetNodeIDs[0]

	callID := "call_" + uuid.NewString()
	c := &calls.Call{
		ID:          callID,
		FromNode:    "sip:" + sourceExt,
		ToNode:      primaryNode,
		InviteNodes: append([]string(nil), targetNodeIDs...),
		AccountID:   accountID,
		CallType:    "sip",
		SIPBridgeID: in.BridgeID,
		CallerID:    in.CallerID,
	}
	if !s.calls.Create(c) {
		return
	}

	s.asterisk.TrackCall(callID, in.Channel)

	// Build a friendly caller display: prefer caller name, fall back to extension.
	callerDisplay := in.CallerID
	if callerDisplay == "" {
		callerDisplay = in.Extension
	}

	sipMeta, _ := json.Marshal(map[string]string{
		"sip_channel":          in.Channel,
		"sip_bridge_id":        in.BridgeID,
		"sip_caller_id":        in.CallerID,
		"sip_extension":        in.Extension,
		"sip_source_extension": sourceExt,
		"sip_unique_id":        in.UniqueID,
	})

	invite := protocol.NewEnvelope(protocol.TypeCallInvite, protocol.CallInvitePayload{
		CallID:     callID,
		FromNodeID: "sip:" + sourceExt,
		FromLabel:  callerDisplay,
		CallType:   "sip",
		Metadata:   json.RawMessage(sipMeta),
	})
	inviteData, _ := invite.Encode()

	sentCount := 0
	for _, nodeID := range targetNodeIDs {
		if targetSess := s.hub.Get(nodeID); targetSess != nil {
			targetSess.Send(inviteData)
			sentCount++
		}
	}

	if sentCount == 0 {
		s.calls.End(callID, "target_disappeared")
		s.asterisk.UntrackCall(callID)
		return
	}

	s.store.WriteAudit(accountID, primaryNode, "sip_incoming_call",
		fmt.Sprintf("call=%s ext=%s ch=%s targets=%d", callID, in.Extension, in.Channel, sentCount), "")
	s.log.Info("SIP invite dispatched", map[string]any{
		"call_id": callID, "extension": in.Extension, "targets": sentCount,
	})
}

func (s *Server) resolveIncomingSIPCallerEndpoint(in asterisk.IncomingSIPCall) (string, *store.SIPEndpoint) {
	candidates := []string{
		strings.TrimSpace(in.CallerEndpoint),
		extractEndpointFromChannel(in.Channel),
		digitsOnly(in.CallerID),
	}
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		ep, err := s.store.GetSIPEndpointByExtension(candidate)
		if err != nil {
			s.log.Error("db error looking up SIP caller endpoint",
				map[string]any{"candidate": candidate, "err": err.Error()})
			continue
		}
		if ep != nil && ep.Enabled {
			return candidate, ep
		}
	}
	return "", nil
}

func (s *Server) handleSIPPhoneOutboundGateway(in asterisk.IncomingSIPCall, callerEP *store.SIPEndpoint) {
	if s.asterisk == nil || callerEP == nil {
		return
	}

	rawDigits := digitsOnly(in.Extension)
	trunk := s.selectOutboundGatewayTrunk(callerEP.AccountID, rawDigits)
	// Desk/SIP phones should control the PSTN dial string, but Synway-style
	// gateway trunks expect the same normalized form as HAOS-originated calls.
	// Try that proven form first, then fall back to the handset's raw callback
	// variants so redial formats can recover from gateway/operator differences.
	number := stripOutboundTrunkPrefix(rawDigits, trunk)
	preferred := normalizePSTNDigits(number, trunk, s.cfg.Asterisk.DefaultPSTNTrunk)
	numbers := outboundGatewayDialCandidates(number, preferred)
	if len(numbers) == 0 || !isSafeDialNumber(numbers[0]) || !isSafeAsteriskName(trunk) {
		s.log.Warn("rejecting unsafe SIP-phone outbound gateway dial",
			map[string]any{"extension": in.Extension, "caller_ext": callerEP.Extension, "trunk": trunk})
		s.hangupAsteriskChannelAsync(in.Channel, "unsafe SIP-phone outbound gateway dial")
		return
	}

	acct, _ := s.store.GetAccount(callerEP.AccountID)
	if acct != nil && s.calls.CountActiveByAccount(callerEP.AccountID) >= acct.MaxCalls {
		s.log.Warn("rejecting SIP-phone outbound gateway dial: account call limit reached",
			map[string]any{"account": callerEP.AccountID, "caller_ext": callerEP.Extension, "number": number})
		s.hangupAsteriskChannelAsync(in.Channel, "account call limit reached")
		return
	}

	callID := "call_" + uuid.NewString()
	c := &calls.Call{
		ID:          callID,
		FromNode:    "sip:" + callerEP.Extension,
		ToNode:      "sip:" + number,
		AccountID:   callerEP.AccountID,
		CallType:    "sip",
		SIPBridgeID: in.BridgeID,
	}
	if !s.calls.Create(c) {
		s.hangupAsteriskChannelAsync(in.Channel, "duplicate SIP-phone outbound gateway call")
		return
	}
	s.asterisk.TrackCall(callID, in.Channel)

	display := callerEP.Description
	if display == "" {
		display = callerEP.Extension
	}
	// The Synway outbound trunk has already been proven with caller number 100
	// from HAOS-originated calls. Keep that gateway-facing identity stable even
	// when a desk SIP phone starts the outside call.
	callerID := formatSIPCallerID(display, "100")
	s.setSIPOutboundRetry(callID, &sipOutboundRetry{
		Numbers:   numbers,
		Trunk:     trunk,
		BridgeID:  in.BridgeID,
		CallerID:  callerID,
		FromNode:  "sip:" + callerEP.Extension,
		CallerExt: callerEP.Extension,
	})
	if !s.trySIPPhoneOutboundGateway(callID) {
		return
	}

	s.store.WriteAudit(callerEP.AccountID, "sip:"+callerEP.Extension, "sip_phone_outbound_gateway",
		fmt.Sprintf("call=%s number=%s candidates=%s trunk=%s", callID, numbers[0], strings.Join(numbers, ","), trunk), "")
	s.log.Info("SIP-phone outbound gateway call originated", map[string]any{
		"call_id": callID, "caller_ext": callerEP.Extension, "number": numbers[0], "candidates": strings.Join(numbers, ","), "trunk": trunk,
	})
}

func (s *Server) selectOutboundGatewayTrunk(accountID, rawDigits string) string {
	endpoints, err := s.store.ListSIPEndpoints(accountID)
	if err != nil {
		s.log.Warn("failed to list SIP endpoints for gateway selection",
			map[string]any{"account": accountID, "err": err.Error()})
	}

	defaultTrunk := strings.TrimSpace(s.cfg.Asterisk.DefaultPSTNTrunk)
	if defaultTrunk == "" {
		defaultTrunk = "7009"
	}
	var fallback string
	fallbackRank := -1
	var defaultAvailable string
	for _, ep := range endpoints {
		ext := strings.TrimSpace(ep.Extension)
		if !ep.Enabled || !isGatewayLikeTrunk(ext, defaultTrunk) {
			continue
		}
		if rawDigits != "" && strings.HasPrefix(rawDigits, ext) {
			rest := strings.TrimPrefix(rawDigits, ext)
			if len(rest) >= 7 && len(rest) <= 15 {
				return ext
			}
		}
		if ext == defaultTrunk {
			defaultAvailable = ext
		}
		rank, _ := strconv.Atoi(digitsOnly(ext))
		if fallback == "" || rank > fallbackRank {
			fallback = ext
			fallbackRank = rank
		}
	}
	if defaultAvailable != "" {
		return defaultAvailable
	}
	if fallback != "" {
		return fallback
	}
	return defaultTrunk
}

func (s *Server) setSIPOutboundRetry(callID string, retry *sipOutboundRetry) {
	s.sipOutboundMu.Lock()
	defer s.sipOutboundMu.Unlock()
	if retry == nil {
		delete(s.sipOutboundRetries, callID)
		return
	}
	cp := *retry
	cp.Numbers = append([]string(nil), retry.Numbers...)
	s.sipOutboundRetries[callID] = &cp
}

func (s *Server) getSIPOutboundRetry(callID string) (*sipOutboundRetry, bool) {
	s.sipOutboundMu.Lock()
	defer s.sipOutboundMu.Unlock()
	retry, ok := s.sipOutboundRetries[callID]
	if !ok || retry == nil {
		return nil, false
	}
	cp := *retry
	cp.Numbers = append([]string(nil), retry.Numbers...)
	return &cp, true
}

func (s *Server) advanceSIPOutboundRetry(callID string) (*sipOutboundRetry, bool) {
	s.sipOutboundMu.Lock()
	defer s.sipOutboundMu.Unlock()
	retry, ok := s.sipOutboundRetries[callID]
	if !ok || retry == nil {
		return nil, false
	}
	retry.Index++
	if retry.Index >= len(retry.Numbers) {
		delete(s.sipOutboundRetries, callID)
		return nil, false
	}
	cp := *retry
	cp.Numbers = append([]string(nil), retry.Numbers...)
	return &cp, true
}

func (s *Server) clearSIPOutboundRetry(callID string) {
	s.setSIPOutboundRetry(callID, nil)
}

func (s *Server) trySIPPhoneOutboundGateway(callID string) bool {
	if c := s.calls.Get(callID); c == nil || c.State != calls.StateRinging {
		s.clearSIPOutboundRetry(callID)
		return false
	}
	retry, ok := s.getSIPOutboundRetry(callID)
	if !ok || retry.Index >= len(retry.Numbers) {
		return false
	}
	number := retry.Numbers[retry.Index]
	if !isSafeDialNumber(number) || !isSafeAsteriskName(retry.Trunk) {
		s.log.Warn("skipping unsafe SIP-phone outbound gateway retry",
			map[string]any{"call_id": callID, "number": number, "trunk": retry.Trunk})
		if next, ok := s.advanceSIPOutboundRetry(callID); ok {
			s.log.Info("retrying SIP-phone outbound gateway with next candidate",
				map[string]any{"call_id": callID, "number": next.Numbers[next.Index], "attempt": next.Index + 1})
			go s.trySIPPhoneOutboundGateway(callID)
			return true
		}
		return false
	}

	_, err := s.asterisk.OriginateToTrunk(
		number,
		retry.Trunk,
		s.cfg.Asterisk.OutContext,
		s.cfg.Asterisk.NodeContext,
		retry.BridgeID,
		retry.CallerID,
		callID,
		retry.FromNode,
		s.cfg.CallTimeoutSec,
	)
	if err != nil {
		s.log.Warn("SIP-phone outbound gateway originate attempt failed",
			map[string]any{"call_id": callID, "caller_ext": retry.CallerExt, "number": number, "trunk": retry.Trunk, "attempt": retry.Index + 1, "err": err.Error()})
		if next, ok := s.advanceSIPOutboundRetry(callID); ok {
			s.log.Info("retrying SIP-phone outbound gateway after originate error",
				map[string]any{"call_id": callID, "number": next.Numbers[next.Index], "attempt": next.Index + 1})
			time.Sleep(1200 * time.Millisecond)
			return s.trySIPPhoneOutboundGateway(callID)
		}
		if c2, ended := s.calls.End(callID, "originate_failed"); ended {
			s.notifyCallStatus(c2)
		}
		_ = s.asterisk.HangupCall(callID)
		s.asterisk.UntrackCall(callID)
		return false
	}

	s.log.Info("SIP-phone outbound gateway originate attempt sent",
		map[string]any{"call_id": callID, "caller_ext": retry.CallerExt, "number": number, "trunk": retry.Trunk, "attempt": retry.Index + 1})
	return true
}

func (s *Server) shouldSuppressIncomingSIPInvite(accountID string, in asterisk.IncomingSIPCall, sourceExt string) bool {
	now := time.Now().UTC()
	callerExt := extractEndpointFromChannel(in.Channel)
	if strings.TrimSpace(sourceExt) == "" {
		sourceExt = callerExt
	}
	key := strings.ToLower(strings.TrimSpace(accountID)) + "|" +
		strings.ToLower(strings.TrimSpace(in.Extension)) + "|" +
		strings.ToLower(strings.TrimSpace(callerExt)) + "|" +
		strings.ToLower(strings.TrimSpace(in.CallerID))

	s.recentSIPInvitesMu.Lock()
	for k, ts := range s.recentSIPInvites {
		if now.Sub(ts) > 30*time.Second {
			delete(s.recentSIPInvites, k)
		}
	}
	if ts, ok := s.recentSIPInvites[key]; ok && now.Sub(ts) < 4*time.Second {
		s.recentSIPInvites[key] = now
		s.recentSIPInvitesMu.Unlock()
		return true
	}
	s.recentSIPInvites[key] = now
	s.recentSIPInvitesMu.Unlock()

	for _, c := range s.calls.ListAll() {
		if c == nil || c.CallType != "sip" || c.AccountID != accountID {
			continue
		}
		if c.State != calls.StateRinging && c.State != calls.StateActive {
			continue
		}
		if c.FromNode != "sip:"+sourceExt {
			continue
		}
		if in.BridgeID != "" && c.SIPBridgeID == in.BridgeID {
			return true
		}
		if c.State == calls.StateRinging && now.Sub(c.CreatedAt) < 20*time.Second {
			return true
		}
	}

	return false
}

func (s *Server) hangupAsteriskChannelAsync(channel, reason string) {
	if s.asterisk == nil || strings.TrimSpace(channel) == "" {
		return
	}
	go func() {
		if err := s.asterisk.HangupChannel(channel); err != nil {
			s.log.Warn("failed to hang up Asterisk channel",
				map[string]any{"channel": channel, "reason": reason, "err": err.Error()})
		}
	}()
}

// handleSIPChannelHangup cleans up a call when the SIP channel hangs up.
func (s *Server) handleSIPChannelHangup(channel string) {
	if s.asterisk == nil {
		return
	}
	callID, ok := s.asterisk.CallIDForChannel(channel)
	if !ok {
		return
	}
	call := s.calls.Get(callID)
	if call != nil && strings.HasPrefix(channel, "Local/") && (call.State == calls.StateRinging || call.State == calls.StateActive) {
		// Local channels are helper legs for outbound trunk calls. They can hang
		// up during normal dial/bridge transitions; the real PJSIP leg owns the
		// user-visible call lifecycle.
		s.log.Debug("ignoring outbound helper channel hangup",
			map[string]any{"call_id": callID, "channel": channel, "state": call.State})
		return
	}
	if call != nil && s.isInboundSIPBridgeCall(call) && s.isSecondarySIPEndpointChannel(channel, call) {
		// Before answer, a routed SIP desk-phone leg can fail, be cancelled, or be
		// retried without meaning the original gateway caller hung up. Once that
		// leg has answered, its hangup is the user ending the bridged call and must
		// clear the outside caller too.
		if call.State != calls.StateActive || call.AnsweredAt.IsZero() {
			s.log.Info("secondary SIP bridge leg hung up before answer; keeping original incoming call alive",
				map[string]any{"call_id": callID, "channel": channel, "state": call.State})
			return
		}
		s.log.Info("secondary SIP bridge leg hung up after answer; ending incoming bridge",
			map[string]any{"call_id": callID, "channel": channel, "state": call.State})
	}
	if call != nil && call.State == calls.StateRinging && s.isOutboundGatewayCall(call) && strings.HasPrefix(channel, "PJSIP/") {
		callerExt := strings.TrimPrefix(call.FromNode, "sip:")
		trunk := extractEndpointFromChannel(channel)
		if isGatewayLikeTrunk(trunk, s.cfg.Asterisk.DefaultPSTNTrunk) {
			// Let the OriginateResponse drive retry/exhaustion. Ending here can
			// cut off the SIP phone before the alternate dial form is attempted.
			s.log.Info("gateway leg hung up before answer; waiting for originate result",
				map[string]any{"call_id": callID, "channel": channel, "trunk": trunk})
			return
		}
		if callerExt != "" && strings.HasPrefix(channel, "PJSIP/"+callerExt+"-") {
			s.clearSIPOutboundRetry(callID)
		}
	}
	if call != nil && call.State == calls.StateActive && !call.AnsweredAt.IsZero() {
		s.log.Debug("SIP channel hangup for active call",
			map[string]any{"call_id": callID, "channel": channel, "answered_age_ms": time.Since(call.AnsweredAt).Milliseconds()})
	}
	c, ok := s.calls.End(callID, "sip_hangup")
	if !ok {
		return
	}
	s.notifyCallStatus(c)
	go func() {
		if err := s.asterisk.HangupCallExcept(callID, channel); err != nil {
			s.log.Warn("failed to hang up remaining SIP bridge legs",
				map[string]any{"call_id": callID, "channel": channel, "err": err.Error()})
		}
		s.asterisk.UntrackCall(callID)
	}()
	s.log.Info("SIP call ended by channel hangup", map[string]any{"call_id": callID, "channel": channel})
}

// handleSIPOriginateResult is the AMI callback when an async Originate
// (outbound call to an IP phone) either connects or fails.
func (s *Server) handleSIPOriginateResult(callID string, ok bool, reason string) {
	if ok {
		s.clearSIPOutboundRetry(callID)
		// Phone answered — transition call to active.
		c, accepted := s.calls.Accept(callID, "")
		if accepted {
			s.notifyCallStatus(c)
			s.log.Info("SIP outbound call answered", map[string]any{"call_id": callID})
		}
	} else {
		// Map Asterisk reason code to a descriptive end reason.
		endReason := "no_answer"
		if c := s.calls.Get(callID); c != nil {
			if s.isOutboundGatewayCall(c) && c.State == calls.StateRinging {
				if next, retryOK := s.advanceSIPOutboundRetry(callID); retryOK {
					s.log.Info("outbound gateway attempt failed; retrying alternate dial form",
						map[string]any{"call_id": callID, "reason": reason, "number": next.Numbers[next.Index], "attempt": next.Index + 1})
					go func() {
						time.Sleep(1200 * time.Millisecond)
						s.trySIPPhoneOutboundGateway(callID)
					}()
					return
				}
			}
			if s.isInboundSIPBridgeCall(c) {
				s.log.Info("SIP bridge add-on leg did not answer; keeping original incoming call alive",
					map[string]any{"call_id": callID, "reason": reason, "state": c.State})
				return
			}
			if isExternalDialString(strings.TrimPrefix(c.ToNode, "sip:")) {
				endReason = "gateway_unavailable"
			}
		}
		switch reason {
		case "4", "17":
			endReason = "busy"
		case "0", "":
			if endReason == "no_answer" {
				// reason=0 typically means endpoint had no contacts or no route.
				endReason = "phone_unavailable"
			}
		}
		c, ended := s.calls.End(callID, endReason)
		if ended {
			s.clearSIPOutboundRetry(callID)
			s.notifyCallStatus(c)
			if s.asterisk != nil {
				go func() {
					if err := s.asterisk.HangupCall(callID); err != nil {
						s.log.Warn("failed to hang up SIP call after originate failure",
							map[string]any{"call_id": callID, "err": err.Error()})
					}
					s.asterisk.UntrackCall(callID)
				}()
			}
			s.log.Info("SIP outbound call not answered",
				map[string]any{"call_id": callID, "reason": endReason})
		}
	}
}

func (s *Server) sendError(conn *websocket.Conn, refID string, code int, message string) {
	env := protocol.NewEnvelope(protocol.TypeError, protocol.ErrorPayload{
		Code:    code,
		Message: message,
		Ref:     refID,
	})
	data, err := env.Encode()
	if err != nil {
		return
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.WriteMessage(websocket.TextMessage, data)
}

func isLikelyInternalExtension(ext string) bool {
	ext = strings.TrimSpace(ext)
	if len(ext) < 2 || len(ext) > 6 {
		return false
	}
	for _, ch := range ext {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func isSafeDialNumber(number string) bool {
	number = strings.TrimSpace(number)
	if len(number) < 2 || len(number) > 15 {
		return false
	}
	for _, ch := range number {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (s *Server) isSIPPhoneOutboundGatewayCall(c *calls.Call) bool {
	if c == nil || c.CallType != "sip" || c.SIPBridgeID == "" {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(c.FromNode), "sip:") {
		return false
	}
	to := strings.TrimPrefix(strings.ToLower(c.ToNode), "sip:")
	return isExternalDialString(to)
}

func (s *Server) isOutboundGatewayCall(c *calls.Call) bool {
	if c == nil || c.CallType != "sip" || c.SIPBridgeID == "" {
		return false
	}
	to := strings.TrimPrefix(strings.ToLower(c.ToNode), "sip:")
	return isExternalDialString(to)
}

func (s *Server) isInboundSIPBridgeCall(c *calls.Call) bool {
	if c == nil || c.CallType != "sip" || c.SIPBridgeID == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(c.FromNode), "sip:") &&
		!strings.HasPrefix(strings.ToLower(c.ToNode), "sip:")
}

func (s *Server) isSecondarySIPEndpointChannel(channel string, c *calls.Call) bool {
	endpoint := extractEndpointFromChannel(channel)
	if endpoint == "" || c == nil {
		return false
	}

	lowerEndpoint := strings.ToLower(endpoint)
	if lowerEndpoint == "anonymous" || lowerEndpoint == "simson-trusted-gateway-in" || lowerEndpoint == "webrtc-pool" {
		return false
	}

	sourceExt := strings.TrimPrefix(strings.ToLower(c.FromNode), "sip:")
	if sourceExt != "" && lowerEndpoint == sourceExt {
		return false
	}

	ep, err := s.store.GetSIPEndpointByExtension(endpoint)
	return err == nil && ep != nil
}

func digitsOnly(value string) string {
	var b strings.Builder
	for _, ch := range value {
		if ch >= '0' && ch <= '9' {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func formatSIPCallerID(display, number string) string {
	display = strings.TrimSpace(display)
	number = digitsOnly(number)
	if number == "" {
		number = "100"
	}
	if display == "" {
		display = number
	}
	display = strings.NewReplacer("\\", "", "\"", "", "\r", " ", "\n", " ").Replace(display)
	return fmt.Sprintf("\"%s\" <%s>", display, number)
}

func sipOutboundDialCandidates(digits string) []string {
	digits = digitsOnly(digits)
	if digits == "" {
		return nil
	}
	var candidates []string
	add := func(v string) {
		v = digitsOnly(v)
		if !isSafeDialNumber(v) {
			return
		}
		for _, existing := range candidates {
			if existing == v {
				return
			}
		}
		candidates = append(candidates, v)
	}

	add(digits)
	if len(digits) == 12 && strings.HasPrefix(digits, "91") {
		add(digits[2:])
	}
	if len(digits) == 10 {
		add("91" + digits)
	}
	return candidates
}

func outboundGatewayDialCandidates(rawDigits, preferred string) []string {
	var candidates []string
	add := func(v string) {
		v = digitsOnly(v)
		if !isSafeDialNumber(v) {
			return
		}
		for _, existing := range candidates {
			if existing == v {
				return
			}
		}
		candidates = append(candidates, v)
	}

	add(preferred)
	for _, v := range sipOutboundDialCandidates(rawDigits) {
		add(v)
	}
	return candidates
}

func stripOutboundTrunkPrefix(digits, trunk string) string {
	digits = digitsOnly(digits)
	trunk = digitsOnly(trunk)
	if digits == "" || trunk == "" || !strings.HasPrefix(digits, trunk) {
		return stripCommonDialAccessPrefix(digits)
	}
	rest := strings.TrimPrefix(digits, trunk)
	if len(rest) >= 7 && len(rest) <= 15 {
		return stripCommonDialAccessPrefix(rest)
	}
	return stripCommonDialAccessPrefix(digits)
}

func stripCommonDialAccessPrefix(digits string) string {
	digits = digitsOnly(digits)
	if len(digits) == 11 && strings.HasPrefix(digits, "0") {
		return digits[1:]
	}
	if len(digits) == 13 && strings.HasPrefix(digits, "091") {
		return digits[1:]
	}
	if len(digits) > 11 && strings.HasPrefix(digits, "00") {
		rest := digits[2:]
		if len(rest) >= 7 && len(rest) <= 15 {
			return rest
		}
	}
	// Many PBX handsets use a single outside-line access digit. Keep this
	// conservative so normal E.164/country-code numbers are not mangled.
	for _, prefix := range []string{"9", "8", "6"} {
		if len(digits) == 12 && strings.HasPrefix(digits, "91") {
			break
		}
		if strings.HasPrefix(digits, prefix) {
			rest := digits[1:]
			if len(rest) >= 10 && len(rest) <= 12 {
				return stripCommonDialAccessPrefix(rest)
			}
		}
	}
	return digits
}

func normalizePSTNDigits(digits, trunk, defaultTrunk string) string {
	if isGatewayLikeTrunk(trunk, defaultTrunk) && len(digits) == 12 && strings.HasPrefix(digits, "91") {
		return digits[2:]
	}
	return digits
}

func isGatewayLikeTrunk(trunk, defaultTrunk string) bool {
	trunk = strings.TrimSpace(trunk)
	if trunk == "" {
		return false
	}
	defaultTrunk = strings.TrimSpace(defaultTrunk)
	if defaultTrunk == "" {
		defaultTrunk = "7009"
	}
	if trunk == defaultTrunk {
		return true
	}
	digits := digitsOnly(trunk)
	return digits == trunk && strings.HasPrefix(digits, "70") && len(digits) >= 3 && len(digits) <= 8
}

func isExternalDialString(value string) bool {
	value = strings.TrimSpace(value)
	digits := digitsOnly(value)
	if strings.HasPrefix(value, "+") && len(digits) >= 7 {
		return true
	}
	return len(digits) >= 7 && len(digits) <= 15
}

func isSafeAsteriskName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return false
	}
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

// asteriskConnectLoop keeps the AMI connection alive, reconnecting on failure.
func (s *Server) asteriskConnectLoop() {
	for {
		s.log.Info("connecting to Asterisk AMI", map[string]any{
			"host": s.cfg.Asterisk.Host,
			"port": s.cfg.Asterisk.Port,
		})
		if err := s.asterisk.Connect(); err != nil {
			s.log.Warn("Asterisk AMI connect failed — retrying in 15s",
				map[string]any{"err": err.Error()})
			time.Sleep(15 * time.Second)
			continue
		}

		s.asterisk.Start() // non-blocking ReadLoop

		// Reload modules via AMI now that we have a live connection.
		// This covers the case where auto-configure wrote configs but the
		// CLI socket was unavailable for a reload.
		s.reloadAsteriskViaAMI()
		if !s.asteriskStartupCleanupDone {
			s.asteriskStartupCleanupDone = true
			if cleaned, err := s.asterisk.CleanupOrphanSimsonChannels(); err != nil {
				s.log.Warn("Asterisk orphan bridge cleanup failed", map[string]any{"err": err.Error()})
			} else if cleaned > 0 {
				s.log.Warn("Asterisk orphan bridge cleanup completed", map[string]any{"channels": cleaned})
			}
		}
		// Block until disconnected by sleeping in a check loop.
		for s.asterisk.Connected() {
			time.Sleep(5 * time.Second)
		}
		s.log.Warn("Asterisk AMI connection dropped — reconnecting in 15s", nil)
		s.asterisk.Disconnect()
		time.Sleep(15 * time.Second)
	}
}

// reloadAsteriskViaAMI sends reload commands through the AMI connection.
func (s *Server) reloadAsteriskViaAMI() {
	cmds := []string{
		"pjsip reload",
		"dialplan reload",
		"module reload app_confbridge.so",
		"module reload res_http_websocket.so",
		"module reload res_pjsip_transport_websocket.so",
	}
	for _, cmd := range cmds {
		if _, err := s.asterisk.RunCommand(cmd); err != nil {
			s.log.Warn("AMI reload command failed", map[string]any{"cmd": cmd, "err": err.Error()})
		} else {
			s.log.Debug("AMI reload OK", map[string]any{"cmd": cmd})
		}
	}
}

func (s *Server) configureAsteriskFromStore() {
	if s.asterisk == nil || !s.cfg.Asterisk.AutoConfigure {
		return
	}

	endpoints, err := s.store.ListAllSIPEndpoints()
	if err != nil {
		s.log.Error("could not load SIP endpoints for Asterisk config", map[string]any{"err": err.Error()})
		return
	}

	defs := make([]asterisk.SIPEndpointDef, 0, len(endpoints))
	for _, ep := range endpoints {
		defs = append(defs, asterisk.SIPEndpointDef{
			ID:           ep.ID,
			Extension:    ep.Extension,
			Username:     ep.Username,
			Password:     ep.Password,
			RouteTo:      ep.RouteTo,
			VideoEnabled: ep.VideoEnabled,
			Enabled:      ep.Enabled,
		})
	}

	webrtcUser := ""
	webrtcPass := ""
	if s.cfg.Asterisk.SIPWebRTC.Enabled {
		webrtcUser = s.cfg.Asterisk.SIPWebRTC.Username
		webrtcPass = s.cfg.Asterisk.SIPWebRTC.Password
	}

	if err := asterisk.Setup(asterisk.SetupConfig{
		AmiUser:                 s.cfg.Asterisk.User,
		AmiSecret:               s.cfg.Asterisk.Secret,
		SIPDomain:               s.cfg.Asterisk.SIPDomain,
		ExternalIP:              s.cfg.Asterisk.ExternalIP,
		InContext:               s.cfg.Asterisk.InContext,
		NodeContext:             s.cfg.Asterisk.NodeContext,
		OutContext:              s.cfg.Asterisk.OutContext,
		DefaultPSTNTrunk:        s.cfg.Asterisk.DefaultPSTNTrunk,
		TrustedGatewayIPs:       s.cfg.Asterisk.TrustedGatewayIPs,
		NoAuthInboundExtensions: s.cfg.Asterisk.NoAuthInboundExtensions,
		WebRTCUser:              webrtcUser,
		WebRTCPass:              webrtcPass,
	}, defs, s.log); err != nil {
		s.log.Error("Asterisk auto-configure failed", map[string]any{"err": err.Error()})
		return
	}

	s.log.Info("Asterisk auto-configure complete", map[string]any{
		"sip_endpoints": len(defs),
		"webrtc":        webrtcUser != "" && webrtcPass != "",
	})
}

// sendErrorSafe sends an error through the session's mutex-protected Send method.
// Used in readLoop where concurrent writes from notifyCallStatus are possible.
func (s *Server) sendErrorSafe(sess *hub.Session, refID string, code int, message string) {
	env := protocol.NewEnvelope(protocol.TypeError, protocol.ErrorPayload{
		Code:    code,
		Message: message,
		Ref:     refID,
	})
	data, err := env.Encode()
	if err != nil {
		return
	}
	sess.Send(data)
}

func extractIP(r *http.Request) string {
	// Trust X-Forwarded-For from Caddy.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func sipWSURL(domain, path string) string {
	host := strings.TrimSpace(domain)
	if host == "" {
		return ""
	}
	wsPath := strings.TrimSpace(path)
	if wsPath == "" {
		wsPath = "/sip/ws"
	}
	if !strings.HasPrefix(wsPath, "/") {
		wsPath = "/" + wsPath
	}
	return "wss://" + host + wsPath
}

// extractEndpointFromChannel extracts the PJSIP endpoint name from an Asterisk
// channel string like "PJSIP/1025-00000001" → "1025".
func extractEndpointFromChannel(channel string) string {
	ch := strings.TrimSpace(channel)
	if !strings.HasPrefix(ch, "PJSIP/") {
		return ""
	}
	ch = ch[len("PJSIP/"):]
	if idx := strings.Index(ch, "-"); idx > 0 {
		ch = ch[:idx]
	}
	return ch
}

// --- Background Tasks ---

// StartBackgroundTasks launches periodic maintenance goroutines.
func (s *Server) StartBackgroundTasks() {
	// ── Central VPS Asterisk ─────────────────────────────────────────────────
	if s.asterisk != nil {
		s.configureAsteriskFromStore()
		go s.asteriskConnectLoop()
	}

	// Heartbeat sweep.
	go func() {
		ticker := time.NewTicker(time.Duration(s.cfg.HeartbeatSec) * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			removed := s.hub.SweepStale(s.cfg.HeartbeatTimeout)
			for _, nodeID := range removed {
				s.log.Warn("stale node removed", map[string]any{"node_id": nodeID})
				s.store.WriteAudit("", nodeID, "stale_disconnect", "", "")
				// End calls.
				for _, c := range s.calls.ActiveByNode(nodeID) {
					if ended, ok := s.calls.End(c.ID, "stale_disconnect"); ok {
						if ended.CallType == "sip" && s.asterisk != nil {
							_ = s.asterisk.HangupCall(ended.ID)
							s.asterisk.UntrackCall(ended.ID)
						}
						s.notifyCallStatus(ended)
					}
				}
			}
		}
	}()

	// Call ring-timeout sweep.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		callTimeout := time.Duration(s.cfg.CallTimeoutSec) * time.Second
		for range ticker.C {
			expired := s.calls.SweepExpired(callTimeout)
			for _, c := range expired {
				s.log.Info("call timed out", map[string]any{"call_id": c.ID})
				s.store.WriteAudit(c.AccountID, c.FromNode, "call_timeout", "call="+c.ID, "")
				if c.CallType == "sip" && s.asterisk != nil {
					_ = s.asterisk.HangupCall(c.ID)
					s.asterisk.UntrackCall(c.ID)
				}
				s.notifyCallStatus(c)
			}
		}
	}()

	// Call cleanup (remove ended records after 1 hour).
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			removed := s.calls.Cleanup(1 * time.Hour)
			if removed > 0 {
				s.log.Debug("cleaned up ended calls", map[string]any{"count": removed})
			}
		}
	}()

	// Rate limiter cleanup.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.limiter.Cleanup(30 * time.Minute)
		}
	}()
}
