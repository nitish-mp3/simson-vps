package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps SQLite access for persistent data.
type Store struct {
	db *sql.DB
}

// Account represents a customer account.
type Account struct {
	ID            string
	Name          string
	LicenseStatus string // "active","suspended","expired"
	MaxNodes      int
	MaxCalls      int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AccountCallFeatures contains site-wide PBX feature codes. Codes are scoped
// to one account and are applied only to that account's authenticated phones.
type AccountCallFeatures struct {
	AccountID         string    `json:"account_id"`
	TransferCode      string    `json:"transfer_code"`
	ConferenceCode    string    `json:"conference_code"`
	InviteListenCode  string    `json:"invite_listen_code"`
	InviteWhisperCode string    `json:"invite_whisper_code"`
	InviteBargeCode   string    `json:"invite_barge_code"`
	Enabled           bool      `json:"enabled"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Node represents a registered node (addon install).
type Node struct {
	ID           string
	AccountID    string
	Label        string
	NodeType     string // "haos","asterisk"
	AuthToken    string
	Capabilities string // JSON array
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AuditEntry is one row in the audit log.
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	AccountID string
	NodeID    string
	Event     string
	Detail    string
	IP        string
}

// SIPEndpoint is a PJSIP endpoint (IP phone) registered to the central VPS Asterisk.
// Each endpoint gets its own section in pjsip.conf; its Extension determines the
// number dialled in and is used to map incoming calls to a Simson node.
type SIPEndpoint struct {
	ID           string
	AccountID    string
	Extension    string // e.g. "1001"
	Username     string // SIP auth username (unique)
	Password     string // SIP auth password (stored in clear for pjsip.conf)
	Description  string
	RouteTo      string // Simson node_id to ring; "" = ring all nodes in the account
	VideoEnabled bool   // allow H.264 negotiation for camera/video SIP devices
	AutoAnswer   bool   // send SIP auto-answer headers when this endpoint is dialed by Simson
	// AutoAnswerCallers is a comma-separated allowlist of caller extensions/usernames
	// that may trigger auto-answer. Empty means any caller may trigger it.
	AutoAnswerCallers string
	AutoSpeaker       bool // request speaker/intercom mode where the SIP phone supports it
	// AutoSpeakerCallers is an optional comma-separated allowlist for speaker mode.
	// Empty keeps backward compatibility by reusing AutoAnswerCallers.
	AutoSpeakerCallers string
	// CallbackBridge re-originates matching SIP-to-SIP calls by calling the
	// original caller back first, allowing caller-side auto-answer/speaker hints.
	CallbackBridge bool
	// CallbackBridgeCallers is a comma-separated allowlist. Empty disables the
	// callback bridge even when CallbackBridge is true.
	CallbackBridgeCallers string
	// CallbackCallerAutoAnswer requests auto-answer on the callback leg to the caller.
	CallbackCallerAutoAnswer bool
	// CallbackCallerAutoSpeaker requests intercom/speaker mode on the callback leg.
	CallbackCallerAutoSpeaker bool
	// DefaultOutbound marks a gateway endpoint as this account's preferred
	// outside-line trunk when a SIP phone dials a PSTN/GSM number without a prefix.
	DefaultOutbound bool
	// GatewayInboundMode controls PSTN/GSM/FXO calls that arrive through this
	// gateway. Empty means the addon/global default. Supported values:
	// haos_then_fallback, direct_target.
	GatewayInboundMode  string
	GatewayDirectTarget string
	GatewayIVREnabled   bool
	// GatewayIVRSound is an Asterisk sound name, e.g. custom/site_welcome.
	// Empty uses the safe built-in wait prompt when GatewayIVREnabled is true.
	GatewayIVRSound string
	// AnswerAnnouncement is an Asterisk sound name played only to this phone
	// after it answers and before the caller is bridged (Dial A option).
	AnswerAnnouncement string
	// AnswerAnnouncementText is the account-scoped text used to generate
	// AnswerAnnouncement. Keeping both makes synthesis auditable and avoids
	// exposing filesystem paths as the administrator-facing configuration.
	AnswerAnnouncementText string
	// PreRingAnnouncement is played to the caller before this target starts
	// ringing. It is separate from AnswerAnnouncement, which remains private to
	// the receiving phone after answer.
	PreRingAnnouncement     string
	PreRingAnnouncementText string
	// CallDurationRules is a validated JSON object mapping a source SIP
	// extension to the maximum connected-call duration in seconds.
	CallDurationRules string
	// SupervisionConfig is validated account-scoped JSON describing which
	// extensions this authenticated SIP endpoint may monitor, whisper to, or
	// barge into. Empty/{} keeps supervision disabled.
	SupervisionConfig string
	Enabled           bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Open creates or opens the SQLite database and runs migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Single writer — serialise writes at the Go level.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// --- Migrations ---

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS accounts (
			id             TEXT PRIMARY KEY,
			name           TEXT NOT NULL,
			license_status TEXT NOT NULL DEFAULT 'active',
			max_nodes      INTEGER NOT NULL DEFAULT 10,
			max_calls      INTEGER NOT NULL DEFAULT 5,
			created_at     DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at     DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id           TEXT PRIMARY KEY,
			account_id   TEXT NOT NULL REFERENCES accounts(id),
			label        TEXT NOT NULL DEFAULT '',
			node_type    TEXT NOT NULL DEFAULT 'haos',
			auth_token   TEXT NOT NULL,
			capabilities TEXT NOT NULL DEFAULT '[]',
			enabled      INTEGER NOT NULL DEFAULT 1,
			created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at   DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_account ON nodes(account_id)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp  DATETIME NOT NULL DEFAULT (datetime('now')),
			account_id TEXT,
			node_id    TEXT,
			event      TEXT NOT NULL,
			detail     TEXT NOT NULL DEFAULT '',
			ip         TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_log(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_auth_token ON nodes(auth_token)`,
		`CREATE TABLE IF NOT EXISTS sip_endpoints (
			id          TEXT PRIMARY KEY,
			account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
			extension   TEXT NOT NULL,
			username    TEXT NOT NULL UNIQUE,
			password    TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			route_to    TEXT NOT NULL DEFAULT '',
			video_enabled INTEGER NOT NULL DEFAULT 0,
			auto_answer INTEGER NOT NULL DEFAULT 0,
			auto_answer_callers TEXT NOT NULL DEFAULT '',
			auto_speaker INTEGER NOT NULL DEFAULT 0,
			auto_speaker_callers TEXT NOT NULL DEFAULT '',
			callback_bridge INTEGER NOT NULL DEFAULT 0,
			callback_bridge_callers TEXT NOT NULL DEFAULT '',
			callback_caller_auto_answer INTEGER NOT NULL DEFAULT 0,
			callback_caller_auto_speaker INTEGER NOT NULL DEFAULT 0,
			default_outbound INTEGER NOT NULL DEFAULT 0,
			gateway_inbound_mode TEXT NOT NULL DEFAULT '',
			gateway_direct_target TEXT NOT NULL DEFAULT '',
			gateway_ivr_enabled INTEGER NOT NULL DEFAULT 0,
			gateway_ivr_sound TEXT NOT NULL DEFAULT '',
			answer_announcement TEXT NOT NULL DEFAULT '',
			answer_announcement_text TEXT NOT NULL DEFAULT '',
			pre_ring_announcement TEXT NOT NULL DEFAULT '',
			pre_ring_announcement_text TEXT NOT NULL DEFAULT '',
			call_duration_rules TEXT NOT NULL DEFAULT '{}',
			supervision_config TEXT NOT NULL DEFAULT '{}',
			enabled     INTEGER NOT NULL DEFAULT 1,
			created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sip_account   ON sip_endpoints(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sip_extension ON sip_endpoints(extension)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sip_username ON sip_endpoints(username)`,
		`CREATE TABLE IF NOT EXISTS advanced_routes (
			id            TEXT PRIMARY KEY,
			account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
			name          TEXT NOT NULL,
			ingress_kind  TEXT NOT NULL,
			ingress_value TEXT NOT NULL,
			stages_json   TEXT NOT NULL DEFAULT '[]',
			enabled       INTEGER NOT NULL DEFAULT 1,
			created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at    DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(account_id, ingress_kind, ingress_value)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_advanced_routes_account ON advanced_routes(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_advanced_routes_ingress ON advanced_routes(account_id, ingress_kind, ingress_value)`,
		`CREATE TABLE IF NOT EXISTS account_call_features (
			account_id      TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
			transfer_code   TEXT NOT NULL DEFAULT '*84',
			conference_code TEXT NOT NULL DEFAULT '*85',
			enabled         INTEGER NOT NULL DEFAULT 1,
			updated_at      DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	if err := s.ensureColumn("sip_endpoints", "video_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "auto_answer", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "auto_answer_callers", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "auto_speaker", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "auto_speaker_callers", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "callback_bridge", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "callback_bridge_callers", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "callback_caller_auto_answer", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "callback_caller_auto_speaker", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "default_outbound", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "gateway_inbound_mode", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "gateway_direct_target", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "gateway_ivr_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "gateway_ivr_sound", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "answer_announcement", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "answer_announcement_text", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "pre_ring_announcement", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "pre_ring_announcement_text", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "call_duration_rules", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	if err := s.ensureColumn("sip_endpoints", "supervision_config", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	if err := s.ensureColumn("account_call_features", "invite_listen_code", "TEXT NOT NULL DEFAULT '*86'"); err != nil {
		return err
	}
	if err := s.ensureColumn("account_call_features", "invite_whisper_code", "TEXT NOT NULL DEFAULT '*87'"); err != nil {
		return err
	}
	if err := s.ensureColumn("account_call_features", "invite_barge_code", "TEXT NOT NULL DEFAULT '*88'"); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureColumn(table, column, definition string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("inspect %s schema: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	if _, err := s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}

// --- Accounts ---

func (s *Store) CreateAccount(id, name string, maxNodes, maxCalls int) error {
	_, err := s.db.Exec(
		`INSERT INTO accounts (id, name, max_nodes, max_calls) VALUES (?, ?, ?, ?)`,
		id, name, maxNodes, maxCalls,
	)
	return err
}

func (s *Store) GetAccount(id string) (*Account, error) {
	row := s.db.QueryRow(`SELECT id, name, license_status, max_nodes, max_calls, created_at, updated_at FROM accounts WHERE id = ?`, id)
	a := &Account{}
	err := row.Scan(&a.ID, &a.Name, &a.LicenseStatus, &a.MaxNodes, &a.MaxCalls, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (s *Store) ListAccounts() ([]Account, error) {
	rows, err := s.db.Query(`SELECT id, name, license_status, max_nodes, max_calls, created_at, updated_at FROM accounts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Name, &a.LicenseStatus, &a.MaxNodes, &a.MaxCalls, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAccountLicense(id, status string) error {
	_, err := s.db.Exec(`UPDATE accounts SET license_status = ?, updated_at = datetime('now') WHERE id = ?`, status, id)
	return err
}

func (s *Store) GetAccountCallFeatures(accountID string) (*AccountCallFeatures, error) {
	row := s.db.QueryRow(`SELECT account_id, transfer_code, conference_code,
		invite_listen_code, invite_whisper_code, invite_barge_code, enabled, updated_at
		FROM account_call_features WHERE account_id = ?`, accountID)
	features := &AccountCallFeatures{AccountID: accountID, TransferCode: "*84", ConferenceCode: "*85",
		InviteListenCode: "*86", InviteWhisperCode: "*87", InviteBargeCode: "*88", Enabled: true}
	if err := row.Scan(&features.AccountID, &features.TransferCode, &features.ConferenceCode,
		&features.InviteListenCode, &features.InviteWhisperCode, &features.InviteBargeCode,
		&features.Enabled, &features.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return features, nil
		}
		return nil, err
	}
	return features, nil
}

func (s *Store) ListAccountCallFeatures() ([]AccountCallFeatures, error) {
	rows, err := s.db.Query(`SELECT a.id,
		COALESCE(f.transfer_code, '*84'), COALESCE(f.conference_code, '*85'),
		COALESCE(f.invite_listen_code, '*86'), COALESCE(f.invite_whisper_code, '*87'),
		COALESCE(f.invite_barge_code, '*88'),
		COALESCE(f.enabled, 1), CAST(strftime('%s', COALESCE(f.updated_at, a.updated_at)) AS INTEGER)
		FROM accounts a LEFT JOIN account_call_features f ON f.account_id = a.id ORDER BY a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountCallFeatures
	for rows.Next() {
		var features AccountCallFeatures
		var updatedUnix int64
		if err := rows.Scan(&features.AccountID, &features.TransferCode, &features.ConferenceCode,
			&features.InviteListenCode, &features.InviteWhisperCode, &features.InviteBargeCode,
			&features.Enabled, &updatedUnix); err != nil {
			return nil, err
		}
		features.UpdatedAt = time.Unix(updatedUnix, 0).UTC()
		out = append(out, features)
	}
	return out, rows.Err()
}

func (s *Store) UpsertAccountCallFeatures(features AccountCallFeatures) error {
	_, err := s.db.Exec(`INSERT INTO account_call_features
		(account_id, transfer_code, conference_code, invite_listen_code,
		 invite_whisper_code, invite_barge_code, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(account_id) DO UPDATE SET transfer_code=excluded.transfer_code,
		conference_code=excluded.conference_code, invite_listen_code=excluded.invite_listen_code,
		invite_whisper_code=excluded.invite_whisper_code, invite_barge_code=excluded.invite_barge_code,
		enabled=excluded.enabled,
		updated_at=datetime('now')`, features.AccountID, features.TransferCode,
		features.ConferenceCode, features.InviteListenCode, features.InviteWhisperCode,
		features.InviteBargeCode, features.Enabled)
	return err
}

// --- Nodes ---

func (s *Store) CreateNode(id, accountID, label, nodeType, capabilities string) (token string, err error) {
	token, err = generateToken()
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(
		`INSERT INTO nodes (id, account_id, label, node_type, auth_token, capabilities) VALUES (?, ?, ?, ?, ?, ?)`,
		id, accountID, label, nodeType, token, capabilities,
	)
	return token, err
}

func (s *Store) GetNode(id string) (*Node, error) {
	row := s.db.QueryRow(`SELECT id, account_id, label, node_type, auth_token, capabilities, enabled, created_at, updated_at FROM nodes WHERE id = ?`, id)
	n := &Node{}
	err := row.Scan(&n.ID, &n.AccountID, &n.Label, &n.NodeType, &n.AuthToken, &n.Capabilities, &n.Enabled, &n.CreatedAt, &n.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

func (s *Store) GetNodeByToken(token string) (*Node, error) {
	row := s.db.QueryRow(`SELECT id, account_id, label, node_type, auth_token, capabilities, enabled, created_at, updated_at FROM nodes WHERE auth_token = ?`, token)
	n := &Node{}
	err := row.Scan(&n.ID, &n.AccountID, &n.Label, &n.NodeType, &n.AuthToken, &n.Capabilities, &n.Enabled, &n.CreatedAt, &n.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

func (s *Store) ListNodesByAccount(accountID string) ([]Node, error) {
	rows, err := s.db.Query(`SELECT id, account_id, label, node_type, auth_token, capabilities, enabled, created_at, updated_at FROM nodes WHERE account_id = ? ORDER BY created_at`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.AccountID, &n.Label, &n.NodeType, &n.AuthToken, &n.Capabilities, &n.Enabled, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) CountNodesByAccount(accountID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE account_id = ?`, accountID).Scan(&count)
	return count, err
}

func (s *Store) SetNodeEnabled(id string, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	_, err := s.db.Exec(`UPDATE nodes SET enabled = ?, updated_at = datetime('now') WHERE id = ?`, val, id)
	return err
}

func (s *Store) RevokeNodeToken(id string) (string, error) {
	newToken, err := generateToken()
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`UPDATE nodes SET auth_token = ?, updated_at = datetime('now') WHERE id = ?`, newToken, id)
	return newToken, err
}

func (s *Store) DeleteNode(id string) error {
	_, err := s.db.Exec(`DELETE FROM nodes WHERE id = ?`, id)
	return err
}

// --- Audit ---

func (s *Store) WriteAudit(accountID, nodeID, event, detail, ip string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log (account_id, node_id, event, detail, ip) VALUES (?, ?, ?, ?, ?)`,
		accountID, nodeID, event, detail, ip,
	)
	return err
}

func (s *Store) QueryAudit(accountID string, since time.Time, limit int) ([]AuditEntry, error) {
	query := `SELECT id, timestamp, account_id, node_id, event, detail, ip FROM audit_log WHERE 1=1`
	args := []any{}

	if accountID != "" {
		query += ` AND account_id = ?`
		args = append(args, accountID)
	}
	if !since.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, since)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.AccountID, &e.NodeID, &e.Event, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- Helpers ---

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "stk_" + hex.EncodeToString(b), nil
}

// --- SIP Endpoints ---

// CreateSIPEndpoint inserts a new PJSIP endpoint record.
func (s *Store) CreateSIPEndpoint(ep SIPEndpoint) error {
	_, err := s.db.Exec(
		`INSERT INTO sip_endpoints (id, account_id, extension, username, password, description, route_to, video_enabled, auto_answer, auto_answer_callers, auto_speaker, auto_speaker_callers, callback_bridge, callback_bridge_callers, callback_caller_auto_answer, callback_caller_auto_speaker, default_outbound, gateway_inbound_mode, gateway_direct_target, gateway_ivr_enabled, gateway_ivr_sound, answer_announcement, answer_announcement_text, pre_ring_announcement, pre_ring_announcement_text, call_duration_rules, supervision_config, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ep.ID, ep.AccountID, ep.Extension, ep.Username, ep.Password,
		ep.Description, ep.RouteTo, boolInt(ep.VideoEnabled), boolInt(ep.AutoAnswer), ep.AutoAnswerCallers, boolInt(ep.AutoSpeaker), ep.AutoSpeakerCallers,
		boolInt(ep.CallbackBridge), ep.CallbackBridgeCallers, boolInt(ep.CallbackCallerAutoAnswer), boolInt(ep.CallbackCallerAutoSpeaker), boolInt(ep.DefaultOutbound),
		ep.GatewayInboundMode, ep.GatewayDirectTarget, boolInt(ep.GatewayIVREnabled), ep.GatewayIVRSound, ep.AnswerAnnouncement, ep.AnswerAnnouncementText,
		ep.PreRingAnnouncement, ep.PreRingAnnouncementText, ep.CallDurationRules, ep.SupervisionConfig, boolInt(ep.Enabled),
	)
	return err
}

// GetSIPEndpoint returns a single endpoint by ID, or nil.
func (s *Store) GetSIPEndpoint(id string) (*SIPEndpoint, error) {
	row := s.db.QueryRow(
		`SELECT id, account_id, extension, username, password, description, route_to, video_enabled, auto_answer, auto_answer_callers, auto_speaker, auto_speaker_callers, callback_bridge, callback_bridge_callers, callback_caller_auto_answer, callback_caller_auto_speaker, default_outbound, gateway_inbound_mode, gateway_direct_target, gateway_ivr_enabled, gateway_ivr_sound, answer_announcement, answer_announcement_text, pre_ring_announcement, pre_ring_announcement_text, call_duration_rules, supervision_config, enabled, created_at, updated_at
		 FROM sip_endpoints WHERE id = ?`, id)
	return scanSIPEndpoint(row)
}

// GetSIPEndpointByExtension returns the first enabled endpoint with this extension, or nil.
func (s *Store) GetSIPEndpointByExtension(extension string) (*SIPEndpoint, error) {
	row := s.db.QueryRow(
		`SELECT id, account_id, extension, username, password, description, route_to, video_enabled, auto_answer, auto_answer_callers, auto_speaker, auto_speaker_callers, callback_bridge, callback_bridge_callers, callback_caller_auto_answer, callback_caller_auto_speaker, default_outbound, gateway_inbound_mode, gateway_direct_target, gateway_ivr_enabled, gateway_ivr_sound, answer_announcement, answer_announcement_text, pre_ring_announcement, pre_ring_announcement_text, call_duration_rules, supervision_config, enabled, created_at, updated_at
		 FROM sip_endpoints WHERE extension = ? AND enabled = 1 LIMIT 1`, extension)
	return scanSIPEndpoint(row)
}

// GetSIPEndpointByAccountAndExtension resolves an extension inside one tenant.
// Extensions may be reused by different customer sites, so account-scoped
// control paths must never rely on the global compatibility lookup above.
func (s *Store) GetSIPEndpointByAccountAndExtension(accountID, extension string) (*SIPEndpoint, error) {
	row := s.db.QueryRow(
		`SELECT id, account_id, extension, username, password, description, route_to, video_enabled, auto_answer, auto_answer_callers, auto_speaker, auto_speaker_callers, callback_bridge, callback_bridge_callers, callback_caller_auto_answer, callback_caller_auto_speaker, default_outbound, gateway_inbound_mode, gateway_direct_target, gateway_ivr_enabled, gateway_ivr_sound, answer_announcement, answer_announcement_text, pre_ring_announcement, pre_ring_announcement_text, call_duration_rules, supervision_config, enabled, created_at, updated_at
		 FROM sip_endpoints WHERE account_id = ? AND extension = ? AND enabled = 1 LIMIT 1`, accountID, extension)
	return scanSIPEndpoint(row)
}

// GetSIPEndpointByUsername returns the endpoint using this SIP auth username, or nil.
func (s *Store) GetSIPEndpointByUsername(username string) (*SIPEndpoint, error) {
	row := s.db.QueryRow(
		`SELECT id, account_id, extension, username, password, description, route_to, video_enabled, auto_answer, auto_answer_callers, auto_speaker, auto_speaker_callers, callback_bridge, callback_bridge_callers, callback_caller_auto_answer, callback_caller_auto_speaker, default_outbound, gateway_inbound_mode, gateway_direct_target, gateway_ivr_enabled, gateway_ivr_sound, answer_announcement, answer_announcement_text, pre_ring_announcement, pre_ring_announcement_text, call_duration_rules, supervision_config, enabled, created_at, updated_at
		 FROM sip_endpoints WHERE username = ? LIMIT 1`, username)
	return scanSIPEndpoint(row)
}

// ListSIPEndpoints returns all endpoints for an account.
func (s *Store) ListSIPEndpoints(accountID string) ([]SIPEndpoint, error) {
	rows, err := s.db.Query(
		`SELECT id, account_id, extension, username, password, description, route_to, video_enabled, auto_answer, auto_answer_callers, auto_speaker, auto_speaker_callers, callback_bridge, callback_bridge_callers, callback_caller_auto_answer, callback_caller_auto_speaker, default_outbound, gateway_inbound_mode, gateway_direct_target, gateway_ivr_enabled, gateway_ivr_sound, answer_announcement, answer_announcement_text, pre_ring_announcement, pre_ring_announcement_text, call_duration_rules, supervision_config, enabled, created_at, updated_at
		 FROM sip_endpoints WHERE account_id = ? ORDER BY extension`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SIPEndpoint
	for rows.Next() {
		ep, err := scanSIPEndpointRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ep)
	}
	return out, rows.Err()
}

// ListAllSIPEndpoints returns every endpoint (used for config generation).
func (s *Store) ListAllSIPEndpoints() ([]SIPEndpoint, error) {
	rows, err := s.db.Query(
		`SELECT id, account_id, extension, username, password, description, route_to, video_enabled, auto_answer, auto_answer_callers, auto_speaker, auto_speaker_callers, callback_bridge, callback_bridge_callers, callback_caller_auto_answer, callback_caller_auto_speaker, default_outbound, gateway_inbound_mode, gateway_direct_target, gateway_ivr_enabled, gateway_ivr_sound, answer_announcement, answer_announcement_text, pre_ring_announcement, pre_ring_announcement_text, call_duration_rules, supervision_config, enabled, created_at, updated_at
		 FROM sip_endpoints ORDER BY account_id, extension`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SIPEndpoint
	for rows.Next() {
		ep, err := scanSIPEndpointRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ep)
	}
	return out, rows.Err()
}

// UpdateSIPEndpoint updates mutable fields of a SIP endpoint.
func (s *Store) UpdateSIPEndpoint(id, description, password, routeTo string, videoEnabled, autoAnswer bool, autoAnswerCallers string, autoSpeaker bool, autoSpeakerCallers string, callbackBridge bool, callbackBridgeCallers string, callbackCallerAutoAnswer bool, callbackCallerAutoSpeaker bool, defaultOutbound bool, enabled bool) error {
	_, err := s.db.Exec(
		`UPDATE sip_endpoints SET description = ?, password = ?, route_to = ?, video_enabled = ?, auto_answer = ?, auto_answer_callers = ?, auto_speaker = ?, auto_speaker_callers = ?, callback_bridge = ?, callback_bridge_callers = ?, callback_caller_auto_answer = ?, callback_caller_auto_speaker = ?, default_outbound = ?, enabled = ?,
		 updated_at = datetime('now') WHERE id = ?`,
		description, password, routeTo, boolInt(videoEnabled), boolInt(autoAnswer), autoAnswerCallers, boolInt(autoSpeaker), autoSpeakerCallers,
		boolInt(callbackBridge), callbackBridgeCallers, boolInt(callbackCallerAutoAnswer), boolInt(callbackCallerAutoSpeaker), boolInt(defaultOutbound), boolInt(enabled), id,
	)
	return err
}

// UpdateSIPEndpointGateway updates gateway-specific call handling fields.
func (s *Store) UpdateSIPEndpointGateway(id, inboundMode, directTarget string, ivrEnabled bool, ivrSound string) error {
	_, err := s.db.Exec(
		`UPDATE sip_endpoints SET gateway_inbound_mode = ?, gateway_direct_target = ?, gateway_ivr_enabled = ?, gateway_ivr_sound = ?,
		 updated_at = datetime('now') WHERE id = ?`,
		inboundMode, directTarget, boolInt(ivrEnabled), ivrSound, id,
	)
	return err
}

// UpdateSIPEndpointAnnouncement updates the called-party-only answer prompt.
func (s *Store) UpdateSIPEndpointAnnouncement(id, announcement, text string) error {
	_, err := s.db.Exec(
		`UPDATE sip_endpoints SET answer_announcement = ?, answer_announcement_text = ?, updated_at = datetime('now') WHERE id = ?`,
		announcement, text, id,
	)
	return err
}

// UpdateSIPEndpointCallBehavior atomically persists both prompt positions and
// exact source-to-target duration rules.
func (s *Store) UpdateSIPEndpointCallBehavior(id, answerSound, answerText, preRingSound, preRingText, durationRules string) error {
	_, err := s.db.Exec(
		`UPDATE sip_endpoints SET answer_announcement = ?, answer_announcement_text = ?,
		 pre_ring_announcement = ?, pre_ring_announcement_text = ?, call_duration_rules = ?,
		 updated_at = datetime('now') WHERE id = ?`,
		answerSound, answerText, preRingSound, preRingText, durationRules, id,
	)
	return err
}

// UpdateSIPEndpointSupervision atomically persists validated supervisor
// permissions without expanding the already large general endpoint update.
func (s *Store) UpdateSIPEndpointSupervision(id, config string) error {
	_, err := s.db.Exec(
		`UPDATE sip_endpoints SET supervision_config = ?, updated_at = datetime('now') WHERE id = ?`,
		config, id,
	)
	return err
}

// DeleteSIPEndpoint removes a SIP endpoint by ID.
func (s *Store) DeleteSIPEndpoint(id string) error {
	_, err := s.db.Exec(`DELETE FROM sip_endpoints WHERE id = ?`, id)
	return err
}

// ---- scan helpers -----------------------------------------------------------

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSIPEndpoint(row rowScanner) (*SIPEndpoint, error) {
	ep := &SIPEndpoint{}
	var videoEnabled, autoAnswer, autoSpeaker, callbackBridge, callbackCallerAutoAnswer, callbackCallerAutoSpeaker, defaultOutbound, gatewayIVREnabled, enabled int
	err := row.Scan(
		&ep.ID, &ep.AccountID, &ep.Extension, &ep.Username, &ep.Password,
		&ep.Description, &ep.RouteTo, &videoEnabled, &autoAnswer, &ep.AutoAnswerCallers, &autoSpeaker, &ep.AutoSpeakerCallers,
		&callbackBridge, &ep.CallbackBridgeCallers, &callbackCallerAutoAnswer, &callbackCallerAutoSpeaker,
		&defaultOutbound, &ep.GatewayInboundMode, &ep.GatewayDirectTarget, &gatewayIVREnabled, &ep.GatewayIVRSound, &ep.AnswerAnnouncement, &ep.AnswerAnnouncementText,
		&ep.PreRingAnnouncement, &ep.PreRingAnnouncementText, &ep.CallDurationRules, &ep.SupervisionConfig,
		&enabled, &ep.CreatedAt, &ep.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ep.Enabled = enabled == 1
	ep.VideoEnabled = videoEnabled == 1
	ep.AutoAnswer = autoAnswer == 1
	ep.AutoSpeaker = autoSpeaker == 1
	ep.CallbackBridge = callbackBridge == 1
	ep.CallbackCallerAutoAnswer = callbackCallerAutoAnswer == 1
	ep.CallbackCallerAutoSpeaker = callbackCallerAutoSpeaker == 1
	ep.DefaultOutbound = defaultOutbound == 1
	ep.GatewayIVREnabled = gatewayIVREnabled == 1
	return ep, nil
}

func scanSIPEndpointRow(rows *sql.Rows) (*SIPEndpoint, error) {
	ep := &SIPEndpoint{}
	var videoEnabled, autoAnswer, autoSpeaker, callbackBridge, callbackCallerAutoAnswer, callbackCallerAutoSpeaker, defaultOutbound, gatewayIVREnabled, enabled int
	err := rows.Scan(
		&ep.ID, &ep.AccountID, &ep.Extension, &ep.Username, &ep.Password,
		&ep.Description, &ep.RouteTo, &videoEnabled, &autoAnswer, &ep.AutoAnswerCallers, &autoSpeaker, &ep.AutoSpeakerCallers,
		&callbackBridge, &ep.CallbackBridgeCallers, &callbackCallerAutoAnswer, &callbackCallerAutoSpeaker,
		&defaultOutbound, &ep.GatewayInboundMode, &ep.GatewayDirectTarget, &gatewayIVREnabled, &ep.GatewayIVRSound, &ep.AnswerAnnouncement, &ep.AnswerAnnouncementText,
		&ep.PreRingAnnouncement, &ep.PreRingAnnouncementText, &ep.CallDurationRules, &ep.SupervisionConfig,
		&enabled, &ep.CreatedAt, &ep.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	ep.Enabled = enabled == 1
	ep.VideoEnabled = videoEnabled == 1
	ep.AutoAnswer = autoAnswer == 1
	ep.AutoSpeaker = autoSpeaker == 1
	ep.CallbackBridge = callbackBridge == 1
	ep.CallbackCallerAutoAnswer = callbackCallerAutoAnswer == 1
	ep.CallbackCallerAutoSpeaker = callbackCallerAutoSpeaker == 1
	ep.DefaultOutbound = defaultOutbound == 1
	ep.GatewayIVREnabled = gatewayIVREnabled == 1
	return ep, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
