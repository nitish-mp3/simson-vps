package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RouteTarget is one destination in a parallel ring stage.
type RouteTarget struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"` // sip, haos, gateway, external
	Value   string `json:"value"`
	Trunk   string `json:"trunk,omitempty"`
	Label   string `json:"label,omitempty"`
	Role    string `json:"role,omitempty"` // hub or spoke for private_hub
	Enabled bool   `json:"enabled"`
}

// RouteStage is an ordered routing level. Targets inside a stage ring together.
type RouteStage struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	RingSeconds int           `json:"ring_seconds"`
	AnswerMode  string        `json:"answer_mode"` // first_answer, conference, private_hub
	MaxAnswered int           `json:"max_answered"`
	Targets     []RouteTarget `json:"targets"`
}

// AdvancedRoute is an account-scoped, ordered call route.
type AdvancedRoute struct {
	ID           string       `json:"id"`
	AccountID    string       `json:"account_id"`
	Name         string       `json:"name"`
	IngressKind  string       `json:"ingress_kind"` // gateway, sip, manual
	IngressValue string       `json:"ingress_value"`
	Stages       []RouteStage `json:"stages"`
	Enabled      bool         `json:"enabled"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

func (s *Store) CreateAdvancedRoute(route AdvancedRoute) error {
	stages, err := json.Marshal(route.Stages)
	if err != nil {
		return fmt.Errorf("encode advanced route stages: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO advanced_routes
		(id, account_id, name, ingress_kind, ingress_value, stages_json, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, route.ID, route.AccountID, route.Name,
		route.IngressKind, route.IngressValue, string(stages), route.Enabled)
	return err
}

func (s *Store) UpdateAdvancedRoute(route AdvancedRoute) error {
	stages, err := json.Marshal(route.Stages)
	if err != nil {
		return fmt.Errorf("encode advanced route stages: %w", err)
	}
	result, err := s.db.Exec(`UPDATE advanced_routes SET name=?, ingress_kind=?, ingress_value=?,
		stages_json=?, enabled=?, updated_at=datetime('now') WHERE id=? AND account_id=?`,
		route.Name, route.IngressKind, route.IngressValue, string(stages), route.Enabled,
		route.ID, route.AccountID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) GetAdvancedRoute(id string) (*AdvancedRoute, error) {
	return scanAdvancedRoute(s.db.QueryRow(`SELECT id, account_id, name, ingress_kind,
		ingress_value, stages_json, enabled, created_at, updated_at FROM advanced_routes WHERE id=?`, id))
}

func (s *Store) GetAdvancedRouteByIngress(accountID, kind, value string) (*AdvancedRoute, error) {
	return scanAdvancedRoute(s.db.QueryRow(`SELECT id, account_id, name, ingress_kind,
		ingress_value, stages_json, enabled, created_at, updated_at FROM advanced_routes
		WHERE account_id=? AND ingress_kind=? AND ingress_value=? AND enabled=1`,
		accountID, strings.ToLower(strings.TrimSpace(kind)), strings.TrimSpace(value)))
}

func (s *Store) ListAdvancedRoutes(accountID string) ([]AdvancedRoute, error) {
	rows, err := s.db.Query(`SELECT id, account_id, name, ingress_kind, ingress_value,
		stages_json, enabled, created_at, updated_at FROM advanced_routes
		WHERE account_id=? ORDER BY name, id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdvancedRoute{}
	for rows.Next() {
		route, err := scanAdvancedRoute(rows)
		if err != nil {
			return nil, err
		}
		if route != nil {
			out = append(out, *route)
		}
	}
	return out, rows.Err()
}

func (s *Store) DeleteAdvancedRoute(id, accountID string) error {
	result, err := s.db.Exec(`DELETE FROM advanced_routes WHERE id=? AND account_id=?`, id, accountID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanAdvancedRoute(row rowScanner) (*AdvancedRoute, error) {
	var route AdvancedRoute
	var stages string
	if err := row.Scan(&route.ID, &route.AccountID, &route.Name, &route.IngressKind,
		&route.IngressValue, &stages, &route.Enabled, &route.CreatedAt, &route.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(stages), &route.Stages); err != nil {
		return nil, fmt.Errorf("decode advanced route %s: %w", route.ID, err)
	}
	return &route, nil
}
