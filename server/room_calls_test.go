package server

import (
	"bytes"
	"encoding/json"
	"github.com/nitish-mp3/simson-vps/calls"
	"github.com/nitish-mp3/simson-vps/hub"
	"github.com/nitish-mp3/simson-vps/logging"
	"github.com/nitish-mp3/simson-vps/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestRoomCallHTTPAuthenticationReplayAndStrictBody(t *testing.T) {
	storage, err := store.Open(filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err := storage.CreateAccount("site", "Site", 10, 10); err != nil {
		t.Fatal(err)
	}
	token, err := storage.CreateNode("node", "site", "Room site", "haos", "[]")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateSIPEndpoint(store.SIPEndpoint{ID: "phone", Username: "1040", Extension: "1040", AccountID: "site", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: storage, calls: calls.NewManager(), log: logging.New("error"), hub: hub.New()}
	request := validRoomRequest()
	body, _ := json.Marshal(request)
	run := func(method string, body []byte, secret string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/node/room-calls", bytes.NewReader(body))
		req.Header.Set("X-Simson-Account-ID", "site")
		req.Header.Set("X-Simson-Node-ID", "node")
		req.Header.Set("X-Simson-Install-Token", secret)
		response := httptest.NewRecorder()
		server.HandleNodeRoomCall(response, req)
		return response
	}
	if got := run(http.MethodGet, nil, "bad").Code; got != 401 {
		t.Fatalf("unauthenticated capability: %d", got)
	}
	if got := run(http.MethodPost, body, token).Code; got != 503 {
		t.Fatalf("unavailable SIP backend: %d", got)
	}
	if got := run(http.MethodPost, append(append([]byte{}, body...), []byte(" {}")...), token).Code; got != 400 {
		t.Fatalf("multiple JSON bodies accepted: %d", got)
	}
	id := roomCallID("site", "node", request)
	call := &calls.Call{ID: id, AccountID: "site", ControlNodeID: "node", ToNode: "node", SourceExtension: "1040", RoomID: request.RoomID, RoomSessionID: request.SessionID, RoomRequestID: request.RequestID, RoomAutoMode: request.SourceAutoMode, RoomTimeout: request.TimeoutSec, CallerUserID: request.CallerUserID, TargetUserID: request.TargetUserID, SIPBridgeID: "exact-bridge"}
	server.calls.Create(call)
	server.calls.End(id, "hangup")
	response := run(http.MethodPost, body, token)
	if response.Code != 200 {
		t.Fatalf("ended receipt not returned: %d %s", response.Code, response.Body.String())
	}
	var receipt map[string]any
	json.Unmarshal(response.Body.Bytes(), &receipt)
	if receipt["call_id"] != id || receipt["status"] != "ended" {
		t.Fatalf("incorrect replay: %v", receipt)
	}
	request.SourceExtension = "1041"
	changed, _ := json.Marshal(request)
	if err := storage.CreateSIPEndpoint(store.SIPEndpoint{ID: "other-phone", Username: "1041", Extension: "1041", AccountID: "site", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if got := run(http.MethodPost, changed, token).Code; got != 409 {
		t.Fatalf("changed replay not rejected: %d", got)
	}
	if len(server.calls.ListAll()) != 1 {
		t.Fatal("replay created another call")
	}
}

func TestRoomPhoneAnswerDoesNotAcceptForCaregiverAndFailureEndsExactCall(t *testing.T) {
	server := &Server{calls: calls.NewManager(), hub: hub.New(), log: logging.New("error")}
	server.calls.Create(&calls.Call{ID: "room-call", RoomSessionID: "session", CallType: "sip", FromNode: "sip:1040", ToNode: "node"})
	server.calls.Create(&calls.Call{ID: "unrelated-call"})
	server.handleSIPOriginateResult("room-call", true, "answered")
	if server.calls.Get("room-call").State != calls.StateRinging {
		t.Fatal("phone answer accepted caregiver call")
	}
	server.handleSIPOriginateResult("room-call", false, "busy")
	if server.calls.Get("room-call").State == calls.StateRinging {
		t.Fatal("failed phone left room ringing")
	}
	if server.calls.Get("unrelated-call").State != calls.StateRinging {
		t.Fatal("unrelated call ended")
	}
}

func validRoomRequest() roomCallRequest {
	return roomCallRequest{RoomID: "living", SessionID: "room-session-one", RequestID: "press-one", SourceExtension: "1040", TargetNodeID: "node", TargetUserID: "caregiver", CallerUserID: "resident", SourceAutoMode: "speaker", TimeoutSec: 30}
}

func TestRoomManualPickupDoesNotSendAutomaticAnswerHints(t *testing.T) {
	if roomPhoneAutoMode("off") != "" {
		t.Fatal("manual pickup requested auto-answer")
	}
	for _, mode := range []string{"answer", "speaker"} {
		if roomPhoneAutoMode(mode) != mode {
			t.Fatalf("explicit pickup hint lost: %s", mode)
		}
	}
}

func TestRoomCallBindingRejectsUnsafeAndCrossAccountDevices(t *testing.T) {
	request := validRoomRequest()
	node := &store.Node{ID: "node", AccountID: "site", Enabled: true}
	endpoint := &store.SIPEndpoint{Extension: "1040", AccountID: "site", Enabled: true}
	if err := validateRoomCallBinding(request, node, endpoint, node); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*roomCallRequest){
		func(r *roomCallRequest) { r.SourceExtension = "1040/evil" },
		func(r *roomCallRequest) { r.TargetUserID = r.CallerUserID },
		func(r *roomCallRequest) { r.SessionID = "" },
		func(r *roomCallRequest) { r.SourceAutoMode = "arbitrary" },
		func(r *roomCallRequest) { r.TimeoutSec = 500 },
	} {
		bad := request
		change(&bad)
		if validateRoomCallBinding(bad, node, endpoint, node) == nil {
			t.Fatal("unsafe request accepted", bad)
		}
	}
	endpoint.AccountID = "other"
	if validateRoomCallBinding(request, node, endpoint, node) == nil {
		t.Fatal("cross-account phone accepted")
	}
	endpoint.AccountID = "site"
	endpoint.Enabled = false
	if validateRoomCallBinding(request, node, endpoint, node) == nil {
		t.Fatal("disabled phone accepted")
	}
	endpoint.Enabled = true
	if validateRoomCallBinding(request, node, endpoint, &store.Node{ID: "node", AccountID: "other", Enabled: true}) == nil {
		t.Fatal("cross-account node accepted")
	}
}

func TestRoomCallIdentityIsIdempotentAndRejectsChangedReplay(t *testing.T) {
	request := validRoomRequest()
	first := roomCallID("site", "node", request)
	if first != roomCallID("site", "node", request) || first == roomCallID("other", "node", request) {
		t.Fatal("room identity is not scoped and deterministic")
	}
	call := &calls.Call{ID: first, AccountID: "site", ControlNodeID: "node", RoomID: request.RoomID, RoomSessionID: request.SessionID, RoomRequestID: request.RequestID, SourceExtension: "1040", ToNode: "node", TargetUserID: "caregiver", CallerUserID: "resident", RoomAutoMode: "speaker", RoomTimeout: 30}
	if !roomCallMatches(call, "site", "node", request) {
		t.Fatal("identical request rejected")
	}
	request.SourceExtension = "1041"
	if roomCallMatches(call, "site", "node", request) {
		t.Fatal("request replay changed phone")
	}
}

func TestRoomCallInviteTargetsOnlyCaregiverAndCarriesRoomIdentity(t *testing.T) {
	request := validRoomRequest()
	metadata := roomCallMetadata(request, "bridge-one")
	if metadata["target_user_id"] != "caregiver" || metadata["caller_user_id"] != "resident" || metadata["room_session_id"] != request.SessionID || metadata["sip_bridge_id"] != "bridge-one" {
		t.Fatalf("missing ownership: %v", metadata)
	}
}
