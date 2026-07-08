package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nitish-mp3/simson-vps/asterisk"
	"github.com/nitish-mp3/simson-vps/calls"
	"github.com/nitish-mp3/simson-vps/config"
	"github.com/nitish-mp3/simson-vps/hub"
	"github.com/nitish-mp3/simson-vps/logging"
	"github.com/nitish-mp3/simson-vps/store"
)

// API holds dependencies for admin handlers.
type API struct {
	cfg      *config.Config
	store    *store.Store
	hub      *hub.Hub
	calls    *calls.Manager
	log      *logging.Logger
	asterisk *asterisk.Router // nil when Asterisk disabled
	doorMu   sync.Mutex
	doorLast map[string]time.Time
}

// New creates an admin API.
func New(cfg *config.Config, st *store.Store, h *hub.Hub, cm *calls.Manager, log *logging.Logger) *API {
	return &API{cfg: cfg, store: st, hub: h, calls: cm, log: log, doorLast: make(map[string]time.Time)}
}

// SetAsterisk injects the AMI router so admin endpoints can trigger reloads.
func (a *API) SetAsterisk(r *asterisk.Router) { a.asterisk = r }

// Router returns an http.Handler with all admin routes.
func (a *API) Router() http.Handler {
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /admin/health", a.handleHealth)

	// Accounts
	mux.HandleFunc("POST /admin/accounts", a.auth(a.handleCreateAccount))
	mux.HandleFunc("GET /admin/accounts", a.auth(a.handleListAccounts))
	mux.HandleFunc("GET /admin/accounts/{id}", a.auth(a.handleGetAccount))
	mux.HandleFunc("PUT /admin/accounts/{id}/license", a.auth(a.handleUpdateLicense))

	// Nodes
	mux.HandleFunc("POST /admin/accounts/{accountId}/nodes", a.auth(a.handleCreateNode))
	mux.HandleFunc("GET /admin/accounts/{accountId}/nodes", a.auth(a.handleListNodes))
	mux.HandleFunc("GET /admin/nodes/{id}", a.auth(a.handleGetNode))
	mux.HandleFunc("PUT /admin/nodes/{id}/enable", a.auth(a.handleEnableNode))
	mux.HandleFunc("PUT /admin/nodes/{id}/disable", a.auth(a.handleDisableNode))
	mux.HandleFunc("POST /admin/nodes/{id}/revoke-token", a.auth(a.handleRevokeToken))
	mux.HandleFunc("DELETE /admin/nodes/{id}", a.auth(a.handleDeleteNode))

	// Live state
	mux.HandleFunc("GET /admin/sessions", a.auth(a.handleListSessions))
	mux.HandleFunc("GET /admin/calls", a.auth(a.handleListCalls))

	// Audit
	mux.HandleFunc("GET /admin/audit", a.auth(a.handleAudit))

	// SIP Endpoints (Central VPS Asterisk)
	mux.HandleFunc("POST /admin/accounts/{accountId}/sip-endpoints", a.auth(a.handleCreateSIPEndpoint))
	mux.HandleFunc("GET /admin/accounts/{accountId}/sip-endpoints", a.auth(a.handleListSIPEndpoints))
	mux.HandleFunc("GET /admin/sip-endpoints/{id}", a.auth(a.handleGetSIPEndpoint))
	mux.HandleFunc("PUT /admin/sip-endpoints/{id}", a.auth(a.handleUpdateSIPEndpoint))
	mux.HandleFunc("DELETE /admin/sip-endpoints/{id}", a.auth(a.handleDeleteSIPEndpoint))
	mux.HandleFunc("POST /admin/accounts/{accountId}/door-events", a.auth(a.handleDoorEvent))

	// Asterisk management
	mux.HandleFunc("POST /admin/asterisk/reload-sip", a.auth(a.handleAsteriskReloadSIP))
	mux.HandleFunc("POST /admin/asterisk/reload-dialplan", a.auth(a.handleAsteriskReloadDialplan))

	// WebRTC config (ICE/TURN + SIP credentials for browser clients)
	mux.HandleFunc("GET /admin/webrtc-config", a.auth(a.handleGetWebRTCConfig))
	mux.HandleFunc("PUT /admin/webrtc-config", a.auth(a.handlePutWebRTCConfig))

	return mux
}

// --- Auth middleware ---

func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.AdminToken)) != 1 {
			a.log.Warn("admin auth failed", map[string]any{"ip": r.RemoteAddr})
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		// Limit request body to 1 MB.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next(w, r)
	}
}

// --- Health ---

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"server_version":   "1.3.0",
		"protocol_version": "1.0.0",
	})
}

// --- Accounts ---

func (a *API) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		MaxNodes int    `json:"max_nodes"`
		MaxCalls int    `json:"max_calls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if body.ID == "" || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id and name required"})
		return
	}
	if body.MaxNodes <= 0 {
		body.MaxNodes = a.cfg.MaxNodesPerAcct
	}
	if body.MaxCalls <= 0 {
		body.MaxCalls = a.cfg.MaxConcurrentCalls
	}

	if err := a.store.CreateAccount(body.ID, body.Name, body.MaxNodes, body.MaxCalls); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "account already exists or db error"})
		return
	}
	a.log.Info("account created", map[string]any{"id": body.ID})
	writeJSON(w, http.StatusCreated, map[string]any{"id": body.ID, "status": "created"})
}

func (a *API) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := a.store.ListAccounts()
	if err != nil {
		a.log.Error("list accounts failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, accounts)
}

func (a *API) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	acct, err := a.store.GetAccount(id)
	if err != nil {
		a.log.Error("get account failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if acct == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

func (a *API) handleUpdateLicense(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Status == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "status required"})
		return
	}
	valid := map[string]bool{"active": true, "suspended": true, "expired": true}
	if !valid[body.Status] {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "status must be active, suspended, or expired"})
		return
	}

	if err := a.store.UpdateAccountLicense(id, body.Status); err != nil {
		a.log.Error("update license failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}

	// If suspended/expired, disconnect all nodes.
	if body.Status != "active" {
		for _, sess := range a.hub.ListByAccount(id) {
			sess.Conn.Close()
		}
	}

	a.log.Info("license updated", map[string]any{"account": id, "status": body.Status})
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

// --- Nodes ---

func (a *API) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("accountId")

	// Verify account exists.
	acct, err := a.store.GetAccount(accountID)
	if err != nil || acct == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "account not found"})
		return
	}

	// Check node limit.
	count, _ := a.store.CountNodesByAccount(accountID)
	if count >= acct.MaxNodes {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "node limit reached"})
		return
	}

	var body struct {
		ID           string   `json:"id"`
		Label        string   `json:"label"`
		NodeType     string   `json:"node_type"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if body.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id required"})
		return
	}
	if body.NodeType == "" {
		body.NodeType = "haos"
	}
	if body.Capabilities == nil {
		body.Capabilities = []string{"haos"}
	}

	capsJSON, _ := json.Marshal(body.Capabilities)

	token, err := a.store.CreateNode(body.ID, accountID, body.Label, body.NodeType, string(capsJSON))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "node already exists or db error"})
		return
	}

	a.log.Info("node created", map[string]any{"id": body.ID, "account": accountID})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":            body.ID,
		"account_id":    accountID,
		"install_token": token,
		"status":        "created",
	})
}

func (a *API) handleListNodes(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("accountId")
	nodes, err := a.store.ListNodesByAccount(accountID)
	if err != nil {
		a.log.Error("list nodes failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}

	// Enrich with live status -- strip auth_token from responses.
	type nodeSafe struct {
		ID           string    `json:"id"`
		AccountID    string    `json:"account_id"`
		Label        string    `json:"label"`
		NodeType     string    `json:"node_type"`
		Capabilities string    `json:"capabilities"`
		Enabled      bool      `json:"enabled"`
		Online       bool      `json:"online"`
		CreatedAt    time.Time `json:"created_at"`
	}
	out := make([]nodeSafe, len(nodes))
	for i, n := range nodes {
		out[i] = nodeSafe{
			ID: n.ID, AccountID: n.AccountID, Label: n.Label,
			NodeType: n.NodeType, Capabilities: n.Capabilities,
			Enabled: n.Enabled, Online: a.hub.IsOnline(n.ID),
			CreatedAt: n.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleGetNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := a.store.GetNode(id)
	if err != nil {
		a.log.Error("get node failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if node == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	// Strip auth_token from responses.
	writeJSON(w, http.StatusOK, map[string]any{
		"id": node.ID, "account_id": node.AccountID, "label": node.Label,
		"node_type": node.NodeType, "capabilities": node.Capabilities,
		"enabled": node.Enabled, "online": a.hub.IsOnline(node.ID),
		"created_at": node.CreatedAt,
	})
}

func (a *API) handleEnableNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.SetNodeEnabled(id, true); err != nil {
		a.log.Error("enable node failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "enabled"})
}

func (a *API) handleDisableNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.SetNodeEnabled(id, false); err != nil {
		a.log.Error("disable node failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	// Disconnect if online.
	if sess := a.hub.Get(id); sess != nil {
		sess.Conn.Close()
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "disabled"})
}

func (a *API) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	newToken, err := a.store.RevokeNodeToken(id)
	if err != nil {
		a.log.Error("revoke token failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	// Disconnect if online — old token is now invalid.
	if sess := a.hub.Get(id); sess != nil {
		sess.Conn.Close()
	}
	a.log.Info("token revoked", map[string]any{"node_id": id})
	writeJSON(w, http.StatusOK, map[string]any{"new_token": newToken})
}

func (a *API) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Disconnect first.
	if sess := a.hub.Get(id); sess != nil {
		sess.Conn.Close()
	}
	if err := a.store.DeleteNode(id); err != nil {
		a.log.Error("delete node failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	a.log.Info("node deleted", map[string]any{"node_id": id})
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// --- Live State ---

func (a *API) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions := a.hub.ListAll()
	type sessionView struct {
		NodeID       string   `json:"node_id"`
		AccountID    string   `json:"account_id"`
		Capabilities []string `json:"capabilities"`
		AddonVersion string   `json:"addon_version"`
		RemoteIP     string   `json:"remote_ip"`
		ConnectedAt  string   `json:"connected_at"`
		LastSeen     string   `json:"last_seen"`
	}
	out := make([]sessionView, len(sessions))
	for i, s := range sessions {
		out[i] = sessionView{
			NodeID:       s.NodeID,
			AccountID:    s.AccountID,
			Capabilities: s.Capabilities,
			AddonVersion: s.AddonVersion,
			RemoteIP:     s.RemoteIP,
			ConnectedAt:  s.ConnectedAt.Format(time.RFC3339),
			LastSeen:     s.LastSeen.Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleListCalls(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.calls.ListAll())
}

// --- Audit ---

func (a *API) handleAudit(w http.ResponseWriter, r *http.Request) {
	accountID := r.URL.Query().Get("account_id")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if n := parseInt(limitStr); n > 0 && n <= 1000 {
			limit = n
		}
	}

	entries, err := a.store.QueryAudit(accountID, time.Time{}, limit)
	if err != nil {
		a.log.Error("query audit failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// --- SIP Endpoints ---

func (a *API) handleCreateSIPEndpoint(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("accountId"))
	if accountID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing accountId"})
		return
	}
	var body struct {
		Extension                 string `json:"extension"`
		Username                  string `json:"username"`
		Password                  string `json:"password"`
		Description               string `json:"description"`
		RouteTo                   string `json:"route_to"`
		VideoEnabled              *bool  `json:"video_enabled"`
		AutoAnswer                *bool  `json:"auto_answer"`
		AutoAnswerCallers         string `json:"auto_answer_callers"`
		AutoSpeaker               *bool  `json:"auto_speaker"`
		AutoSpeakerCallers        string `json:"auto_speaker_callers"`
		CallbackBridge            *bool  `json:"callback_bridge"`
		CallbackBridgeCallers     string `json:"callback_bridge_callers"`
		CallbackCallerAutoAnswer  *bool  `json:"callback_caller_auto_answer"`
		CallbackCallerAutoSpeaker *bool  `json:"callback_caller_auto_speaker"`
		DefaultOutbound           *bool  `json:"default_outbound"`
		Enabled                   *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	body.Extension = strings.TrimSpace(body.Extension)
	body.Username = strings.TrimSpace(body.Username)
	body.Password = strings.TrimSpace(body.Password)
	body.Description = strings.TrimSpace(body.Description)
	body.RouteTo = strings.TrimSpace(body.RouteTo)
	if body.Username == "" {
		body.Username = body.Extension
	}
	autoAnswerCallers, ok := normalizeAutoAnswerCallersInput(body.AutoAnswerCallers)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "auto_answer_callers must contain only extension/user tokens separated by commas"})
		return
	}
	autoSpeakerCallers, ok := normalizeAutoAnswerCallersInput(body.AutoSpeakerCallers)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "auto_speaker_callers must contain only extension/user tokens separated by commas"})
		return
	}
	callbackBridgeCallers, ok := normalizeAutoAnswerCallersInput(body.CallbackBridgeCallers)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "callback_bridge_callers must contain only extension/user tokens separated by commas"})
		return
	}
	if body.Extension == "" || body.Username == "" || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "extension, username, and password are required"})
		return
	}
	if !isSafeSIPExtension(body.Extension) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "extension must be 2-12 digits"})
		return
	}
	if !isSafeSIPUsername(body.Username) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "username/auth user must be 2-64 characters and contain only letters, numbers, dot, underscore, or dash. For normal phones, use the same value as extension."})
		return
	}
	existing, err := a.store.GetSIPEndpointByUsername(body.Username)
	if err != nil {
		a.log.Error("lookup sip endpoint by username", map[string]any{"err": err.Error(), "username": body.Username})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if existing != nil {
		status := http.StatusConflict
		message := "SIP username already exists"
		if existing.AccountID == accountID {
			message = "SIP phone already exists for this site. Refresh the list and edit the existing endpoint instead of creating it again."
		}
		writeJSON(w, status, map[string]any{
			"error":             message,
			"existing_endpoint": existing,
		})
		return
	}
	if eps, err := a.store.ListSIPEndpoints(accountID); err != nil {
		a.log.Error("list sip endpoints before create", map[string]any{"err": err.Error(), "account_id": accountID})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	} else {
		for _, existing := range eps {
			if existing.Extension == body.Extension {
				writeJSON(w, http.StatusConflict, map[string]any{
					"error":             "SIP extension already exists for this site. Refresh the list and edit the existing endpoint instead of creating it again.",
					"existing_endpoint": existing,
				})
				return
			}
		}
	}
	if !a.validRouteToNode(w, accountID, body.RouteTo) {
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	videoEnabled := false
	if body.VideoEnabled != nil {
		videoEnabled = *body.VideoEnabled
	}
	autoAnswer := false
	if body.AutoAnswer != nil {
		autoAnswer = *body.AutoAnswer
	}
	autoSpeaker := false
	if body.AutoSpeaker != nil {
		autoSpeaker = *body.AutoSpeaker
	}
	callbackBridge := false
	if body.CallbackBridge != nil {
		callbackBridge = *body.CallbackBridge
	}
	callbackCallerAutoAnswer := false
	if body.CallbackCallerAutoAnswer != nil {
		callbackCallerAutoAnswer = *body.CallbackCallerAutoAnswer
	}
	callbackCallerAutoSpeaker := false
	if body.CallbackCallerAutoSpeaker != nil {
		callbackCallerAutoSpeaker = *body.CallbackCallerAutoSpeaker
	}
	defaultOutbound := false
	if body.DefaultOutbound != nil {
		defaultOutbound = *body.DefaultOutbound
	}
	// Generate a random ID
	idb := make([]byte, 16)
	rand.Read(idb) //nolint:errcheck
	ep := store.SIPEndpoint{
		ID:                        hex.EncodeToString(idb),
		AccountID:                 accountID,
		Extension:                 body.Extension,
		Username:                  body.Username,
		Password:                  body.Password,
		Description:               body.Description,
		RouteTo:                   body.RouteTo,
		VideoEnabled:              videoEnabled,
		AutoAnswer:                autoAnswer,
		AutoAnswerCallers:         autoAnswerCallers,
		AutoSpeaker:               autoSpeaker,
		AutoSpeakerCallers:        autoSpeakerCallers,
		CallbackBridge:            callbackBridge,
		CallbackBridgeCallers:     callbackBridgeCallers,
		CallbackCallerAutoAnswer:  callbackCallerAutoAnswer,
		CallbackCallerAutoSpeaker: callbackCallerAutoSpeaker,
		DefaultOutbound:           defaultOutbound,
		Enabled:                   enabled,
	}
	if err := a.store.CreateSIPEndpoint(ep); err != nil {
		a.log.Error("create sip endpoint", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if ep.DefaultOutbound {
		a.clearOtherDefaultOutboundGateways(ep.AccountID, ep.ID)
	}
	a.reconfigureAsterisk()
	writeJSON(w, http.StatusCreated, ep)
}

func (a *API) handleListSIPEndpoints(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("accountId")
	if accountID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing accountId"})
		return
	}
	eps, err := a.store.ListSIPEndpoints(accountID)
	if err != nil {
		a.log.Error("list sip endpoints", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, a.enrichSIPEndpoints(eps))
}

func (a *API) enrichSIPEndpoints(eps []store.SIPEndpoint) []map[string]any {
	contacts := map[string]asterisk.ContactStatus{}
	if a.asterisk != nil && a.asterisk.Connected() {
		contacts = a.asterisk.ContactStatuses()
	}

	out := make([]map[string]any, 0, len(eps))
	for _, ep := range eps {
		contact := contacts[ep.Username]
		if !contact.Registered {
			if byExt, ok := contacts[ep.Extension]; ok {
				contact = byExt
			}
		}
		out = append(out, map[string]any{
			"id":                           ep.ID,
			"account_id":                   ep.AccountID,
			"extension":                    ep.Extension,
			"username":                     ep.Username,
			"description":                  ep.Description,
			"route_to":                     ep.RouteTo,
			"video_enabled":                ep.VideoEnabled,
			"auto_answer":                  ep.AutoAnswer,
			"auto_answer_callers":          ep.AutoAnswerCallers,
			"auto_speaker":                 ep.AutoSpeaker,
			"auto_speaker_callers":         ep.AutoSpeakerCallers,
			"callback_bridge":              ep.CallbackBridge,
			"callback_bridge_callers":      ep.CallbackBridgeCallers,
			"callback_caller_auto_answer":  ep.CallbackCallerAutoAnswer,
			"callback_caller_auto_speaker": ep.CallbackCallerAutoSpeaker,
			"default_outbound":             ep.DefaultOutbound,
			"enabled":                      ep.Enabled,
			"created_at":                   ep.CreatedAt,
			"updated_at":                   ep.UpdatedAt,
			"registered":                   contact.Registered,
			"contact_status":               contact.Status,
			"contact_uri":                  contact.URI,
			"contact_address":              contact.Address,
			"contact_latency_ms":           contact.LatencyMS,
		})
	}
	return out
}

func (a *API) handleGetSIPEndpoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ep, err := a.store.GetSIPEndpoint(id)
	if err != nil {
		a.log.Error("get sip endpoint", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if ep == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, ep)
}

func (a *API) handleUpdateSIPEndpoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ep, err := a.store.GetSIPEndpoint(id)
	if err != nil {
		a.log.Error("get sip endpoint for update", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if ep == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	var body struct {
		Description               *string `json:"description"`
		Password                  *string `json:"password"`
		RouteTo                   *string `json:"route_to"`
		VideoEnabled              *bool   `json:"video_enabled"`
		AutoAnswer                *bool   `json:"auto_answer"`
		AutoAnswerCallers         *string `json:"auto_answer_callers"`
		AutoSpeaker               *bool   `json:"auto_speaker"`
		AutoSpeakerCallers        *string `json:"auto_speaker_callers"`
		CallbackBridge            *bool   `json:"callback_bridge"`
		CallbackBridgeCallers     *string `json:"callback_bridge_callers"`
		CallbackCallerAutoAnswer  *bool   `json:"callback_caller_auto_answer"`
		CallbackCallerAutoSpeaker *bool   `json:"callback_caller_auto_speaker"`
		DefaultOutbound           *bool   `json:"default_outbound"`
		Enabled                   *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.Description != nil {
		ep.Description = *body.Description
	}
	if body.Password != nil && *body.Password != "" {
		ep.Password = *body.Password
	}
	if body.RouteTo != nil {
		ep.RouteTo = strings.TrimSpace(*body.RouteTo)
		if !a.validRouteToNode(w, ep.AccountID, ep.RouteTo) {
			return
		}
	}
	if body.VideoEnabled != nil {
		ep.VideoEnabled = *body.VideoEnabled
	}
	if body.AutoAnswer != nil {
		ep.AutoAnswer = *body.AutoAnswer
	}
	if body.AutoAnswerCallers != nil {
		callers, ok := normalizeAutoAnswerCallersInput(*body.AutoAnswerCallers)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "auto_answer_callers must contain only extension/user tokens separated by commas"})
			return
		}
		ep.AutoAnswerCallers = callers
	}
	if body.AutoSpeaker != nil {
		ep.AutoSpeaker = *body.AutoSpeaker
	}
	if body.AutoSpeakerCallers != nil {
		callers, ok := normalizeAutoAnswerCallersInput(*body.AutoSpeakerCallers)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "auto_speaker_callers must contain only extension/user tokens separated by commas"})
			return
		}
		ep.AutoSpeakerCallers = callers
	}
	if body.CallbackBridge != nil {
		ep.CallbackBridge = *body.CallbackBridge
	}
	if body.CallbackBridgeCallers != nil {
		callers, ok := normalizeAutoAnswerCallersInput(*body.CallbackBridgeCallers)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "callback_bridge_callers must contain only extension/user tokens separated by commas"})
			return
		}
		ep.CallbackBridgeCallers = callers
	}
	if body.CallbackCallerAutoAnswer != nil {
		ep.CallbackCallerAutoAnswer = *body.CallbackCallerAutoAnswer
	}
	if body.CallbackCallerAutoSpeaker != nil {
		ep.CallbackCallerAutoSpeaker = *body.CallbackCallerAutoSpeaker
	}
	if body.DefaultOutbound != nil {
		ep.DefaultOutbound = *body.DefaultOutbound
	}
	if body.Enabled != nil {
		ep.Enabled = *body.Enabled
	}
	if err := a.store.UpdateSIPEndpoint(ep.ID, ep.Description, ep.Password, ep.RouteTo, ep.VideoEnabled, ep.AutoAnswer, ep.AutoAnswerCallers, ep.AutoSpeaker, ep.AutoSpeakerCallers, ep.CallbackBridge, ep.CallbackBridgeCallers, ep.CallbackCallerAutoAnswer, ep.CallbackCallerAutoSpeaker, ep.DefaultOutbound, ep.Enabled); err != nil {
		a.log.Error("update sip endpoint", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if ep.DefaultOutbound {
		a.clearOtherDefaultOutboundGateways(ep.AccountID, ep.ID)
	}
	a.reconfigureAsterisk()
	writeJSON(w, http.StatusOK, ep)
}

func (a *API) clearOtherDefaultOutboundGateways(accountID, keepID string) {
	eps, err := a.store.ListSIPEndpoints(accountID)
	if err != nil {
		a.log.Warn("could not enforce single default outbound gateway", map[string]any{"account_id": accountID, "err": err.Error()})
		return
	}
	for _, other := range eps {
		if other.ID == keepID || !other.DefaultOutbound {
			continue
		}
		if err := a.store.UpdateSIPEndpoint(
			other.ID,
			other.Description,
			other.Password,
			other.RouteTo,
			other.VideoEnabled,
			other.AutoAnswer,
			other.AutoAnswerCallers,
			other.AutoSpeaker,
			other.AutoSpeakerCallers,
			other.CallbackBridge,
			other.CallbackBridgeCallers,
			other.CallbackCallerAutoAnswer,
			other.CallbackCallerAutoSpeaker,
			false,
			other.Enabled,
		); err != nil {
			a.log.Warn("could not clear previous default outbound gateway", map[string]any{"endpoint": other.Extension, "err": err.Error()})
		}
	}
}

func (a *API) handleDeleteSIPEndpoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.DeleteSIPEndpoint(id); err != nil {
		a.log.Error("delete sip endpoint", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	a.reconfigureAsterisk()
	w.WriteHeader(http.StatusNoContent)
}

// handleDoorEvent starts a native SIP-to-SIP door camera bridge. The source
// door station must be configured to auto-answer SIP callbacks. Both endpoints
// are resolved from the same account so one site cannot ring another site's
// devices even if an extension is guessed.
func (a *API) handleDoorEvent(w http.ResponseWriter, r *http.Request) {
	if a.asterisk == nil || !a.asterisk.Connected() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Asterisk integration unavailable"})
		return
	}

	accountID := strings.TrimSpace(r.PathValue("accountId"))
	var body struct {
		SourceExtension string `json:"source_extension"`
		TargetExtension string `json:"target_extension"`
		CallerID        string `json:"caller_id"`
		TriggerID       string `json:"trigger_id"`
		TimeoutSec      int    `json:"timeout_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	source := strings.TrimSpace(body.SourceExtension)
	target := strings.TrimSpace(body.TargetExtension)
	if accountID == "" || !isSafeSIPExtension(source) || !isSafeSIPExtension(target) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "account, source_extension, and target_extension are required numeric SIP extensions"})
		return
	}
	if source == target {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "door station and indoor target must be different SIP extensions"})
		return
	}

	sourceEP, err := a.store.GetSIPEndpointByExtension(source)
	if err != nil {
		a.log.Error("door source lookup failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	targetEP, err := a.store.GetSIPEndpointByExtension(target)
	if err != nil {
		a.log.Error("door target lookup failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if sourceEP == nil || targetEP == nil || sourceEP.AccountID != accountID || targetEP.AccountID != accountID {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "door station or indoor SIP target not found for this site"})
		return
	}
	if !sourceEP.VideoEnabled || !targetEP.VideoEnabled {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "enable Video capable device for both door station and indoor SIP target"})
		return
	}
	if !a.asterisk.EndpointHasContacts(source) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "door station is not registered"})
		return
	}
	if !a.asterisk.EndpointHasContacts(target) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "indoor SIP target is not registered"})
		return
	}

	timeoutSec := body.TimeoutSec
	if timeoutSec == 0 {
		timeoutSec = 30
	}
	if timeoutSec < 5 || timeoutSec > 120 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "timeout_sec must be between 5 and 120"})
		return
	}
	key := accountID + ":" + source + ":" + target
	a.doorMu.Lock()
	last := a.doorLast[key]
	if elapsed := time.Since(last); !last.IsZero() && elapsed < time.Duration(timeoutSec)*time.Second {
		retryAfter := int((time.Duration(timeoutSec)*time.Second - elapsed).Seconds()) + 1
		a.doorMu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "door event rate limited", "retry_after": retryAfter})
		return
	}
	a.doorLast[key] = time.Now()
	a.doorMu.Unlock()

	callerID := strings.TrimSpace(body.CallerID)
	if callerID == "" {
		callerID = "\"Door Station\" <" + source + ">"
	}
	callID := "door-" + randomHexID(16)
	if _, err := a.asterisk.OriginateDoorStationCall(source, target, callerID, callID, timeoutSec); err != nil {
		a.doorMu.Lock()
		delete(a.doorLast, key)
		a.doorMu.Unlock()
		a.log.Error("door station originate failed", map[string]any{"err": err.Error(), "source": source, "target": target})
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "could not start door station call"})
		return
	}

	a.store.WriteAudit(accountID, "", "door_event_call", "trigger="+strings.TrimSpace(body.TriggerID)+" source="+source+" target="+target, r.RemoteAddr)
	a.log.Info("door station call started", map[string]any{"account_id": accountID, "call_id": callID, "source": source, "target": target})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"call_id":          callID,
		"status":           "calling_door_station",
		"source_extension": source,
		"target_extension": target,
	})
}

func isSafeSIPExtension(extension string) bool {
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

func isSafeSIPUsername(username string) bool {
	if len(username) < 2 || len(username) > 64 {
		return false
	}
	for _, ch := range username {
		if ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		if ch >= '0' && ch <= '9' {
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			continue
		}
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		return false
	}
	return true
}

func normalizeAutoAnswerCallersInput(value string) (string, bool) {
	parts := strings.FieldsFunc(strings.TrimSpace(value), func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		if len(token) > 32 {
			return "", false
		}
		for _, ch := range token {
			if ch != '-' && ch != '_' && (ch < '0' || ch > '9') && (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') {
				return "", false
			}
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	return strings.Join(out, ","), true
}

func (a *API) validRouteToNode(w http.ResponseWriter, accountID, routeTo string) bool {
	routeTo = strings.TrimSpace(routeTo)
	if routeTo == "" {
		return true
	}
	node, err := a.store.GetNode(routeTo)
	if err != nil {
		a.log.Error("lookup route_to node", map[string]any{"err": err.Error(), "route_to": routeTo, "account_id": accountID})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return false
	}
	if node == nil || node.AccountID != accountID || !node.Enabled {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":    "route_to must be blank or an enabled HAOS node in this same site/account",
			"route_to": routeTo,
		})
		return false
	}
	return true
}

func randomHexID(bytes int) string {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(value)
}

// --- Asterisk management ---

func (a *API) handleAsteriskReloadSIP(w http.ResponseWriter, r *http.Request) {
	if a.asterisk == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Asterisk integration disabled"})
		return
	}
	if err := a.asterisk.ReloadSIP(); err != nil {
		a.log.Error("asterisk reload-sip", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) handleAsteriskReloadDialplan(w http.ResponseWriter, r *http.Request) {
	if a.asterisk == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Asterisk integration disabled"})
		return
	}
	if err := a.asterisk.ReloadDialplan(); err != nil {
		a.log.Error("asterisk reload-dialplan", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- WebRTC config ---

// handleGetWebRTCConfig returns the ICE server list and SIP-over-WebSocket credentials
// that browser clients (cards) need to establish audio connections.
func (a *API) handleGetWebRTCConfig(w http.ResponseWriter, r *http.Request) {
	// Build ICE server list.
	iceServers := []map[string]any{}
	for _, s := range a.cfg.ICE.STUNServers {
		iceServers = append(iceServers, map[string]any{"urls": s})
	}
	if a.cfg.ICE.TURNEnabled && len(a.cfg.ICE.TURNURLs) > 0 {
		entry := map[string]any{
			"urls":       a.cfg.ICE.TURNURLs,
			"username":   a.cfg.ICE.TURNUsername,
			"credential": a.cfg.ICE.TURNSecret,
		}
		iceServers = append(iceServers, entry)
	}

	// Build SIP config.
	sipConfig := map[string]any{
		"enabled":  a.cfg.Asterisk.SIPWebRTC.Enabled,
		"username": a.cfg.Asterisk.SIPWebRTC.Username,
		"password": a.cfg.Asterisk.SIPWebRTC.Password,
		"domain":   a.cfg.Asterisk.SIPDomain,
		"ws_path":  a.cfg.Asterisk.SIPWebRTC.WSPath,
		"ws_url":   sipWSURL(a.cfg.Asterisk.SIPDomain, a.cfg.Asterisk.SIPWebRTC.WSPath),
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ice_servers": iceServers,
		"sip":         sipConfig,
	})
}

// handlePutWebRTCConfig updates TURN and SIP-over-WS credentials at runtime
// (changes take effect immediately on the next client request; no server restart needed).
func (a *API) handlePutWebRTCConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TURNEnabled  *bool    `json:"turn_enabled"`
		TURNURLs     []string `json:"turn_urls"`
		TURNUsername *string  `json:"turn_username"`
		TURNSecret   *string  `json:"turn_secret"`
		SIPEnabled   *bool    `json:"sip_enabled"`
		SIPUsername  *string  `json:"sip_username"`
		SIPPassword  *string  `json:"sip_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if body.TURNEnabled != nil {
		a.cfg.ICE.TURNEnabled = *body.TURNEnabled
	}
	if len(body.TURNURLs) > 0 {
		a.cfg.ICE.TURNURLs = body.TURNURLs
	}
	if body.TURNUsername != nil {
		a.cfg.ICE.TURNUsername = *body.TURNUsername
	}
	if body.TURNSecret != nil {
		a.cfg.ICE.TURNSecret = *body.TURNSecret
	}
	if body.SIPEnabled != nil {
		a.cfg.Asterisk.SIPWebRTC.Enabled = *body.SIPEnabled
	}
	if body.SIPUsername != nil {
		a.cfg.Asterisk.SIPWebRTC.Username = *body.SIPUsername
	}
	if body.SIPPassword != nil {
		a.cfg.Asterisk.SIPWebRTC.Password = *body.SIPPassword
	}
	a.log.Info("webrtc-config updated", map[string]any{
		"turn_enabled": a.cfg.ICE.TURNEnabled,
		"sip_enabled":  a.cfg.Asterisk.SIPWebRTC.Enabled,
	})
	a.reconfigureAsterisk()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Helpers ---

func (a *API) reconfigureAsterisk() {
	if !a.cfg.Asterisk.Enabled || !a.cfg.Asterisk.AutoConfigure {
		return
	}

	endpoints, err := a.store.ListAllSIPEndpoints()
	if err != nil {
		a.log.Error("could not load SIP endpoints for Asterisk config", map[string]any{"err": err.Error()})
		return
	}

	defs := make([]asterisk.SIPEndpointDef, 0, len(endpoints))
	for _, ep := range endpoints {
		defs = append(defs, asterisk.SIPEndpointDef{
			ID:                        ep.ID,
			Extension:                 ep.Extension,
			Username:                  ep.Username,
			Password:                  ep.Password,
			RouteTo:                   ep.RouteTo,
			VideoEnabled:              ep.VideoEnabled,
			AutoAnswer:                ep.AutoAnswer,
			AutoAnswerCallers:         ep.AutoAnswerCallers,
			AutoSpeaker:               ep.AutoSpeaker,
			AutoSpeakerCallers:        ep.AutoSpeakerCallers,
			CallbackBridge:            ep.CallbackBridge,
			CallbackBridgeCallers:     ep.CallbackBridgeCallers,
			CallbackCallerAutoAnswer:  ep.CallbackCallerAutoAnswer,
			CallbackCallerAutoSpeaker: ep.CallbackCallerAutoSpeaker,
			Enabled:                   ep.Enabled,
		})
	}

	webrtcUser := ""
	webrtcPass := ""
	if a.cfg.Asterisk.SIPWebRTC.Enabled {
		webrtcUser = a.cfg.Asterisk.SIPWebRTC.Username
		webrtcPass = a.cfg.Asterisk.SIPWebRTC.Password
	}

	if err := asterisk.Setup(asterisk.SetupConfig{
		AmiUser:                 a.cfg.Asterisk.User,
		AmiSecret:               a.cfg.Asterisk.Secret,
		SIPDomain:               a.cfg.Asterisk.SIPDomain,
		ExternalIP:              a.cfg.Asterisk.ExternalIP,
		InContext:               a.cfg.Asterisk.InContext,
		NodeContext:             a.cfg.Asterisk.NodeContext,
		OutContext:              a.cfg.Asterisk.OutContext,
		DefaultPSTNTrunk:        a.cfg.Asterisk.DefaultPSTNTrunk,
		TrustedGatewayIPs:       a.cfg.Asterisk.TrustedGatewayIPs,
		NoAuthInboundExtensions: a.cfg.Asterisk.NoAuthInboundExtensions,
		WebRTCUser:              webrtcUser,
		WebRTCPass:              webrtcPass,
	}, defs, a.log); err != nil {
		a.log.Error("Asterisk auto-configure failed", map[string]any{"err": err.Error()})
		return
	}

	if a.asterisk != nil && a.asterisk.Connected() {
		for _, cmd := range []string{
			"pjsip reload",
			"dialplan reload",
			"module reload app_confbridge.so",
			"module reload res_http_websocket.so",
			"module reload res_pjsip_transport_websocket.so",
		} {
			if _, err := a.asterisk.RunCommand(cmd); err != nil {
				a.log.Warn("AMI reload command failed", map[string]any{"cmd": cmd, "err": err.Error()})
			}
		}
	}
}

func sipWSURL(domain, path string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/sip/ws"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "wss://" + domain + path
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
