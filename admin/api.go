package admin

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/nitish-mp3/simson-vps/calls"
	"github.com/nitish-mp3/simson-vps/config"
	"github.com/nitish-mp3/simson-vps/hub"
	"github.com/nitish-mp3/simson-vps/logging"
	"github.com/nitish-mp3/simson-vps/store"
)

// API holds dependencies for admin handlers.
type API struct {
	cfg   *config.Config
	store *store.Store
	hub   *hub.Hub
	calls *calls.Manager
	log   *logging.Logger
}

// New creates an admin API.
func New(cfg *config.Config, st *store.Store, h *hub.Hub, cm *calls.Manager, log *logging.Logger) *API {
	return &API{cfg: cfg, store: st, hub: h, calls: cm, log: log}
}

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
		"status":          "ok",
		"server_version":  "1.0.0",
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

// --- Helpers ---

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
