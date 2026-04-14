package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
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
}

// New constructs a Server.
func New(cfg *config.Config, st *store.Store, log *logging.Logger) *Server {
	s := &Server{
		cfg:     cfg,
		store:   st,
		hub:     hub.New(),
		calls:   calls.NewManager(),
		limiter: ratelimit.New(cfg.RateLimitPerSec, cfg.RateLimitPerSec*2),
		log:     log,
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
		ServerVersion:   "1.3.0",
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
		CallID:   callID,
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

	// Verify the accepter is the target BEFORE mutating state.
	existing := s.calls.Get(payload.CallID)
	if existing == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
		return
	}
	if sess.NodeID != existing.ToNode {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "not the call target")
		return
	}

	c, ok := s.calls.Accept(payload.CallID)
	if !ok {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found or not ringing")
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
			AnsweredByUserID: answeredBy,
		})
		data, _ := status.Encode()
		callerSess.Send(data)
	}

	// Notify callee too.
	calleeStatus := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
		CallID:           c.ID,
		Status:           string(calls.StateActive),
		AnsweredByUserID: answeredBy,
	})
	data, _ := calleeStatus.Encode()
	sess.Send(data)
}

// --- Call Reject ---

func (s *Server) handleCallReject(sess *hub.Session, env *protocol.Envelope) {
	payload, err := protocol.DecodePayload[protocol.CallRejectPayload](env)
	if err != nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "invalid call.reject payload")
		return
	}

	// Verify the rejecter is the target BEFORE mutating state.
	existing := s.calls.Get(payload.CallID)
	if existing == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found")
		return
	}
	if sess.NodeID != existing.ToNode {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "not the call target")
		return
	}

	c, ok := s.calls.End(payload.CallID, "rejected")
	if !ok {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found or already ended")
		return
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
	if sess.NodeID != existing.FromNode && sess.NodeID != existing.ToNode {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeForbidden, "not a participant")
		return
	}

	c, ok := s.calls.End(payload.CallID, reason)
	if !ok {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "call not found or already ended")
		return
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "call_ended", "call="+payload.CallID+" reason="+reason, sess.RemoteIP)
	s.log.Info("call ended", map[string]any{"call_id": payload.CallID, "reason": reason})

	s.notifyCallStatus(c)
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
		CallID: c.ID,
		Status: string(c.State),
		Reason: c.EndReason,
	})
	data, _ := status.Encode()

	if fromSess := s.hub.Get(c.FromNode); fromSess != nil {
		fromSess.Send(data)
	}
	if toSess := s.hub.Get(c.ToNode); toSess != nil {
		toSess.Send(data)
	}
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

	ep, err := s.store.GetSIPEndpointByExtension(ext)
	if err != nil {
		s.log.Error("db error looking up SIP endpoint", map[string]any{"err": err.Error()})
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "internal error")
		return
	}
	if ep == nil {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeNotFound, "SIP extension not registered: "+ext)
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

	c := &calls.Call{
		ID:        callID,
		FromNode:  sess.NodeID,
		ToNode:    "sip:" + ext, // virtual node ID for the SIP side
		AccountID: sess.AccountID,
		CallType:  "sip",
	}
	if !s.calls.Create(c) {
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeBadRequest, "duplicate call ID")
		return
	}

	// Caller label shown on the phone display.
	callerID := ""
	if len(req.Metadata) > 0 {
		var metaMap map[string]any
		if err := json.Unmarshal(req.Metadata, &metaMap); err == nil {
			if v, ok := metaMap["caller_id"]; ok {
				if s, ok := v.(string); ok {
					callerID = s
				}
			}
		}
	}
	if callerID == "" {
		if node, _ := s.store.GetNode(sess.NodeID); node != nil && node.Label != "" {
			callerID = node.Label
		} else {
			callerID = sess.NodeID
		}
	}

	// Originate the call via AMI.
	_, err = s.asterisk.OriginateToExtension(
		ext,
		s.cfg.Asterisk.InContext,
		callerID,
		callID,
		sess.NodeID,
		s.cfg.CallTimeoutSec,
	)
	if err != nil {
		s.calls.End(callID, "originate_failed")
		s.sendErrorSafe(sess, env.ID, protocol.ErrCodeInternal, "AMI originate failed: "+err.Error())
		return
	}

	s.store.WriteAudit(sess.AccountID, sess.NodeID, "sip_call_request",
		fmt.Sprintf("call=%s ext=%s", callID, ext), sess.RemoteIP)
	s.log.Info("SIP call originated", map[string]any{
		"call_id": callID, "ext": ext, "from": sess.NodeID,
	})

	// Tell the calling node the phone is ringing.
	status := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
		CallID: callID, Status: string(calls.StateRinging),
	})
	sd, _ := status.Encode()
	sess.Send(sd)
}

// handleSIPIncomingCall is the AMI callback for an incoming SIP call.
// It routes the call to the correct Simson node based on the dialled extension.
// When RouteTo is empty, it broadcasts (rings) ALL online nodes in the account.
func (s *Server) handleSIPIncomingCall(in asterisk.IncomingSIPCall) {
	ep, err := s.store.GetSIPEndpointByExtension(in.Extension)
	if err != nil || ep == nil {
		s.log.Warn("no SIP endpoint for extension — hanging up",
			map[string]any{"extension": in.Extension, "channel": in.Channel})
		if s.asterisk != nil {
			_ = s.asterisk.HangupChannel(in.Channel)
		}
		return
	}

	// Collect target nodes: either a specific RouteTo or all online nodes.
	var targetNodeIDs []string
	if ep.RouteTo != "" {
		if s.hub.IsOnline(ep.RouteTo) {
			targetNodeIDs = append(targetNodeIDs, ep.RouteTo)
		}
	} else {
		// Broadcast: ring ALL online nodes in this account.
		for _, sess := range s.hub.ListByAccount(ep.AccountID) {
			targetNodeIDs = append(targetNodeIDs, sess.NodeID)
		}
	}

	if len(targetNodeIDs) == 0 {
		s.log.Warn("no online target node for SIP call — hanging up",
			map[string]any{"extension": in.Extension})
		if s.asterisk != nil {
			_ = s.asterisk.HangupChannel(in.Channel)
		}
		return
	}

	// Use the first node as primary call target (for call state tracking).
	primaryNode := targetNodeIDs[0]

	callID := "call_" + uuid.NewString()
	c := &calls.Call{
		ID:        callID,
		FromNode:  "sip:" + in.Extension,
		ToNode:    primaryNode,
		AccountID: ep.AccountID,
		CallType:  "sip",
	}
	if !s.calls.Create(c) {
		return
	}

	// Track channel before doing anything else.
	s.asterisk.TrackCall(callID, in.Channel)

	sipMeta, _ := json.Marshal(map[string]string{
		"sip_channel":   in.Channel,
		"sip_bridge_id": in.BridgeID,
		"sip_caller_id": in.CallerID,
		"sip_extension": in.Extension,
		"sip_unique_id": in.UniqueID,
	})

	invite := protocol.NewEnvelope(protocol.TypeCallInvite, protocol.CallInvitePayload{
		CallID:     callID,
		FromNodeID: "sip:" + in.Extension,
		FromLabel:  in.CallerID,
		CallType:   "sip",
		Metadata:   json.RawMessage(sipMeta),
	})
	inviteData, _ := invite.Encode()

	// Send invite to ALL target nodes (call-all for SIP).
	sentCount := 0
	for _, nodeID := range targetNodeIDs {
		targetSess := s.hub.Get(nodeID)
		if targetSess != nil {
			targetSess.Send(inviteData)
			sentCount++
		}
	}

	if sentCount == 0 {
		s.calls.End(callID, "target_disappeared")
		s.asterisk.UntrackCall(callID)
		return
	}

	s.store.WriteAudit(ep.AccountID, primaryNode, "sip_incoming_call",
		fmt.Sprintf("call=%s ext=%s ch=%s targets=%d", callID, in.Extension, in.Channel, sentCount), "")
	s.log.Info("SIP invite dispatched", map[string]any{
		"call_id": callID, "extension": in.Extension, "targets": sentCount,
	})
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
	c, ok := s.calls.End(callID, "sip_hangup")
	if !ok {
		return
	}
	s.asterisk.UntrackCall(callID)
	s.log.Info("SIP call ended by channel hangup", map[string]any{"call_id": callID, "channel": channel})
	s.notifyCallStatus(c)
}

// handleSIPOriginateResult is the AMI callback when an async Originate
// (outbound call to an IP phone) either connects or fails.
func (s *Server) handleSIPOriginateResult(callID string, ok bool) {
	if ok {
		// Phone answered — transition call to active.
		c, accepted := s.calls.Accept(callID)
		if accepted {
			s.notifyCallStatus(c)
			s.log.Info("SIP outbound call answered", map[string]any{"call_id": callID})
		}
	} else {
		// Phone rejected / no answer.
		c, ended := s.calls.End(callID, "no_answer")
		if ended {
			s.notifyCallStatus(c)
			if s.asterisk != nil {
				s.asterisk.UntrackCall(callID)
			}
			s.log.Info("SIP outbound call not answered", map[string]any{"call_id": callID})
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

// asteriskConnectLoop keeps the AMI connection alive, reconnecting on failure.
func (s *Server) asteriskConnectLoop() {
	for {
		s.log.Info("connecting to Asterisk AMI", map[string]any{
			"host": s.cfg.Asterisk.Host,
			"port": s.cfg.Asterisk.Port,
		})
		// Run() connects and blocks until the connection drops.
		if err := s.asterisk.Run(); err != nil {
			s.log.Warn("Asterisk AMI connect failed — retrying in 15s",
				map[string]any{"err": err.Error()})
		} else {
			s.log.Warn("Asterisk AMI connection dropped — reconnecting in 15s", nil)
		}
		s.asterisk.Disconnect() // ensure clean state before reconnect
		time.Sleep(15 * time.Second)
	}
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

// --- Background Tasks ---

// StartBackgroundTasks launches periodic maintenance goroutines.
func (s *Server) StartBackgroundTasks() {
	// ── Central VPS Asterisk ─────────────────────────────────────────────────
	if s.asterisk != nil {
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
