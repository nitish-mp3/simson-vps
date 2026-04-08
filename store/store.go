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
	ID          string
	AccountID   string
	Extension   string // e.g. "1001"
	Username    string // SIP auth username (unique)
	Password    string // SIP auth password (stored in clear for pjsip.conf)
	Description string
	RouteTo     string // Simson node_id to ring; "" = ring all nodes in the account
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
			enabled     INTEGER NOT NULL DEFAULT 1,
			created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sip_account   ON sip_endpoints(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sip_extension ON sip_endpoints(extension)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sip_username ON sip_endpoints(username)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
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
		`INSERT INTO sip_endpoints (id, account_id, extension, username, password, description, route_to, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ep.ID, ep.AccountID, ep.Extension, ep.Username, ep.Password,
		ep.Description, ep.RouteTo, boolInt(ep.Enabled),
	)
	return err
}

// GetSIPEndpoint returns a single endpoint by ID, or nil.
func (s *Store) GetSIPEndpoint(id string) (*SIPEndpoint, error) {
	row := s.db.QueryRow(
		`SELECT id, account_id, extension, username, password, description, route_to, enabled, created_at, updated_at
		 FROM sip_endpoints WHERE id = ?`, id)
	return scanSIPEndpoint(row)
}

// GetSIPEndpointByExtension returns the first enabled endpoint with this extension, or nil.
func (s *Store) GetSIPEndpointByExtension(extension string) (*SIPEndpoint, error) {
	row := s.db.QueryRow(
		`SELECT id, account_id, extension, username, password, description, route_to, enabled, created_at, updated_at
		 FROM sip_endpoints WHERE extension = ? AND enabled = 1 LIMIT 1`, extension)
	return scanSIPEndpoint(row)
}

// ListSIPEndpoints returns all endpoints for an account.
func (s *Store) ListSIPEndpoints(accountID string) ([]SIPEndpoint, error) {
	rows, err := s.db.Query(
		`SELECT id, account_id, extension, username, password, description, route_to, enabled, created_at, updated_at
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
		`SELECT id, account_id, extension, username, password, description, route_to, enabled, created_at, updated_at
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
func (s *Store) UpdateSIPEndpoint(id, description, password, routeTo string, enabled bool) error {
	_, err := s.db.Exec(
		`UPDATE sip_endpoints SET description = ?, password = ?, route_to = ?, enabled = ?,
		 updated_at = datetime('now') WHERE id = ?`,
		description, password, routeTo, boolInt(enabled), id,
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
	var enabled int
	err := row.Scan(
		&ep.ID, &ep.AccountID, &ep.Extension, &ep.Username, &ep.Password,
		&ep.Description, &ep.RouteTo, &enabled, &ep.CreatedAt, &ep.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ep.Enabled = enabled == 1
	return ep, nil
}

func scanSIPEndpointRow(rows *sql.Rows) (*SIPEndpoint, error) {
	ep := &SIPEndpoint{}
	var enabled int
	err := rows.Scan(
		&ep.ID, &ep.AccountID, &ep.Extension, &ep.Username, &ep.Password,
		&ep.Description, &ep.RouteTo, &enabled, &ep.CreatedAt, &ep.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	ep.Enabled = enabled == 1
	return ep, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
