package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nitish-mp3/simson-vps/calls"
	"github.com/nitish-mp3/simson-vps/protocol"
	"github.com/nitish-mp3/simson-vps/store"
)

type roomCallRequest struct {
	RoomID          string `json:"room_id"`
	SessionID       string `json:"session_id"`
	RequestID       string `json:"request_id"`
	SourceExtension string `json:"source_extension"`
	TargetNodeID    string `json:"target_node_id"`
	TargetUserID    string `json:"target_user_id"`
	CallerUserID    string `json:"caller_user_id"`
	CallerUserName  string `json:"caller_user_name"`
	SourceAutoMode  string `json:"source_auto_mode"`
	TimeoutSec      int    `json:"timeout_sec"`
}

var roomIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var roomIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var roomExtensionPattern = regexp.MustCompile(`^[0-9]{1,12}$`)

func validateRoomCallBinding(request roomCallRequest, node *store.Node, endpoint *store.SIPEndpoint, target *store.Node) error {
	if !roomIDPattern.MatchString(request.RoomID) || !roomIdentityPattern.MatchString(request.SessionID) || !roomIdentityPattern.MatchString(request.TargetUserID) || !roomIdentityPattern.MatchString(request.CallerUserID) || !roomExtensionPattern.MatchString(request.SourceExtension) || request.TargetUserID == request.CallerUserID || len(request.RequestID) == 0 || len(request.RequestID) > 128 || strings.ContainsAny(request.RequestID, "\r\n\x00") || len(request.CallerUserName) > 100 || strings.ContainsAny(request.CallerUserName, "\r\n\x00") {
		return fmt.Errorf("invalid room, session, request or participant identity")
	}
	if request.TimeoutSec < 5 || request.TimeoutSec > 120 {
		return fmt.Errorf("timeout_sec must be 5–120")
	}
	if request.SourceAutoMode != "off" && request.SourceAutoMode != "speaker" && request.SourceAutoMode != "answer" {
		return fmt.Errorf("choose off, answer or speaker for source_auto_mode")
	}
	if node == nil || !node.Enabled || endpoint == nil || !endpoint.Enabled || endpoint.AccountID != node.AccountID || endpoint.Extension != request.SourceExtension {
		return fmt.Errorf("SIP phone is unavailable for this site")
	}
	if target == nil || !target.Enabled || target.AccountID != node.AccountID || target.ID != request.TargetNodeID || target.ID != node.ID {
		return fmt.Errorf("choose this site's Home Assistant node")
	}
	return nil
}

func roomCallID(account, node string, request roomCallRequest) string {
	return "call_" + uuid.NewSHA1(uuid.NameSpaceOID, []byte(account+"\x00"+node+"\x00"+request.RoomID+"\x00"+request.RequestID)).String()
}

func roomCallMatches(call *calls.Call, account, node string, request roomCallRequest) bool {
	return call.AccountID == account && call.ControlNodeID == node && call.RoomID == request.RoomID && call.RoomSessionID == request.SessionID && call.RoomRequestID == request.RequestID && call.SourceExtension == request.SourceExtension && call.ToNode == request.TargetNodeID && call.CallerUserID == request.CallerUserID && call.TargetUserID == request.TargetUserID && call.RoomAutoMode == request.SourceAutoMode && call.RoomTimeout == request.TimeoutSec
}

func roomCallMetadata(request roomCallRequest, bridge string) map[string]string {
	return map[string]string{"sip_bridge_id": bridge, "sip_extension": request.SourceExtension, "source_extension": request.SourceExtension, "caller_user_id": request.CallerUserID, "caller_user_name": request.CallerUserName, "target_user_id": request.TargetUserID, "room_id": request.RoomID, "room_session_id": request.SessionID, "room_request_id": request.RequestID, "media_mode": "sip_room", "room_audio_mode": "sip"}
}

func roomCallResponse(call *calls.Call) map[string]any {
	return map[string]any{"call_id": call.ID, "sip_bridge_id": call.SIPBridgeID, "session_id": call.RoomSessionID, "status": string(call.State), "native_sip_rooms": true}
}

func roomPhoneAutoMode(mode string) string {
	if mode == "answer" || mode == "speaker" {
		return mode
	}
	return ""
}

func (s *Server) endRoomSIPCall(callID, reason string) {
	call, ended := s.calls.End(callID, reason)
	if !ended {
		return
	}
	s.notifyCallStatus(call)
	if s.asterisk != nil {
		go func() {
			s.asterisk.HangupCall(callID)
			s.asterisk.HangupBridge(call.SIPBridgeID, "")
			s.asterisk.UntrackCall(callID)
		}()
	}
}

func (s *Server) HandleNodeRoomCall(w http.ResponseWriter, r *http.Request) {
	node, ok := s.authenticateNodeRequest(w, r, "room-calls")
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		writeNodeJSON(w, http.StatusOK, map[string]any{"native_sip_rooms": true})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var request roomCallRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeNodeJSON(w, 400, map[string]any{"error": "invalid room request"})
		return
	}
	endpoint, err := s.store.GetSIPEndpointByExtension(request.SourceExtension)
	if err != nil {
		writeNodeJSON(w, 503, map[string]any{"error": "SIP directory unavailable"})
		return
	}
	target, err := s.store.GetNode(request.TargetNodeID)
	if err != nil {
		writeNodeJSON(w, 503, map[string]any{"error": "node directory unavailable"})
		return
	}
	if err = validateRoomCallBinding(request, node, endpoint, target); err != nil {
		writeNodeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.roomCallsMu.Lock()
	defer s.roomCallsMu.Unlock()
	if s.roomRequests == nil {
		s.roomRequests = make(map[string]*calls.Call)
	}
	id := roomCallID(node.AccountID, node.ID, request)
	previous := s.roomRequests[id]
	if previous == nil {
		previous = s.calls.Get(id)
	}
	if previous != nil {
		if !roomCallMatches(previous, node.AccountID, node.ID, request) {
			writeNodeJSON(w, 409, map[string]any{"error": "request_id was already used with different room bindings"})
			return
		}
		writeNodeJSON(w, 200, roomCallResponse(previous))
		return
	}
	for key, call := range s.roomRequests {
		if !call.EndedAt.IsZero() && time.Since(call.EndedAt) > 24*time.Hour {
			delete(s.roomRequests, key)
		}
	}
	if len(s.roomRequests) >= 4096 {
		writeNodeJSON(w, 503, map[string]any{"error": "room request capacity reached; do not redial automatically"})
		return
	}
	if s.asterisk == nil || !s.asterisk.Connected() {
		writeNodeJSON(w, 503, map[string]any{"error": "SIP bridge unavailable"})
		return
	}
	targetSession := s.hub.Get(target.ID)
	if targetSession == nil || targetSession.AccountID != node.AccountID {
		writeNodeJSON(w, 409, map[string]any{"error": "the room's Home Assistant node is offline"})
		return
	}
	if !s.asterisk.EndpointHasContacts(request.SourceExtension) {
		writeNodeJSON(w, 409, map[string]any{"error": "the selected SIP phone is not registered"})
		return
	}
	inUse, err := s.asterisk.EndpointInUse(request.SourceExtension)
	if err != nil {
		writeNodeJSON(w, 503, map[string]any{"error": "could not verify SIP phone availability"})
		return
	}
	if inUse {
		writeNodeJSON(w, 409, map[string]any{"error": "the selected SIP phone is already in a call"})
		return
	}
	for _, active := range s.calls.ListAll() {
		if active.AccountID == node.AccountID && (active.State == calls.StateRinging || active.State == calls.StateActive) && (active.SourceExtension == request.SourceExtension || active.FromNode == "sip:"+request.SourceExtension || active.ToNode == "sip:"+request.SourceExtension || active.ControlNodeID == node.ID && (active.CallerUserID == request.CallerUserID || active.TargetUserID == request.TargetUserID)) {
			writeNodeJSON(w, 409, map[string]any{"error": "a room participant is already in a call"})
			return
		}
	}
	bridge := "bridge-" + strings.TrimPrefix(id, "call_")
	callerName := request.CallerUserName
	if callerName == "" {
		callerName = "Room call"
	}
	call := &calls.Call{ID: id, AccountID: node.AccountID, FromNode: "sip:" + request.SourceExtension, ToNode: target.ID, ControlNodeID: node.ID, SourceExtension: request.SourceExtension, CallType: "sip", SIPBridgeID: bridge, CallerID: callerName, RoomID: request.RoomID, RoomSessionID: request.SessionID, RoomRequestID: request.RequestID, RoomAutoMode: request.SourceAutoMode, RoomTimeout: request.TimeoutSec, CallerUserID: request.CallerUserID, TargetUserID: request.TargetUserID}
	if !s.calls.Create(call) {
		writeNodeJSON(w, 409, map[string]any{"error": "room request creation conflict"})
		return
	}
	s.roomRequests[id] = call
	if _, err = s.asterisk.OriginateCallbackToBridge(request.SourceExtension, "from-simson-node", bridge, request.SourceExtension, id, roomPhoneAutoMode(request.SourceAutoMode), request.TimeoutSec); err != nil {
		s.endRoomSIPCall(id, "originate_failed")
		writeNodeJSON(w, 502, map[string]any{"error": "could not call the selected room phone", "call_id": id})
		return
	}
	metadata, _ := json.Marshal(roomCallMetadata(request, bridge))
	invite := protocol.NewEnvelope(protocol.TypeCallInvite, protocol.CallInvitePayload{CallID: id, FromNodeID: call.FromNode, FromLabel: callerName, CallType: "sip", Metadata: metadata})
	encoded, _ := invite.Encode()
	if err = targetSession.Send(encoded); err != nil {
		s.endRoomSIPCall(id, "phone_unavailable")
		writeNodeJSON(w, 502, map[string]any{"error": "could not notify the selected caregiver", "call_id": id})
		return
	}
	s.store.WriteAudit(node.AccountID, node.ID, "room_call_started", "room="+request.RoomID+" call="+id, extractIP(r))
	writeNodeJSON(w, http.StatusAccepted, roomCallResponse(call))
}
