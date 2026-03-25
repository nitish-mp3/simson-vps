package server

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

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
	cfg       *config.Config
	store     *store.Store
	hub       *hub.Hub
	calls     *calls.Manager
	limiter   *ratelimit.Limiter
	log       *logging.Logger
	upgrader  websocket.Upgrader
}

// New constructs a Server.
func New(cfg *config.Config, st *store.Store, log *logging.Logger) *Server {
	return &Server{
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
}

// Hub returns the live session hub (for admin API).
func (s *Server) Hub() *hub.Hub { return s.hub }

// Calls returns the call manager (for admin API).
func (s *Server) Calls() *calls.Manager { return s.calls }

// Store returns the persistent store (for admin API).
func (s *Server) Store() *store.Store { return s.store }

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
		ServerVersion:   "1.0.0",
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
	s.log.Info("call accepted", map[string]any{"call_id": payload.CallID})

	// Notify caller.
	callerSess := s.hub.Get(c.FromNode)
	if callerSess != nil {
		status := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
			CallID: c.ID,
			Status: string(calls.StateActive),
		})
		data, _ := status.Encode()
		callerSess.Send(data)
	}

	// Notify callee too.
	calleeStatus := protocol.NewEnvelope(protocol.TypeCallStatus, protocol.CallStatusPayload{
		CallID: c.ID,
		Status: string(calls.StateActive),
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
