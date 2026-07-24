package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/nitish-mp3/simson-vps/store"
)

var advancedRouteToken = regexp.MustCompile(`^[A-Za-z0-9_.+*#-]{1,64}$`)

func (a *API) handleCreateAdvancedRoute(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("accountId"))
	if accountID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing accountId"})
		return
	}
	var route store.AdvancedRoute
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	route.ID = "route_" + uuid.NewString()
	route.AccountID = accountID
	if err := a.validateAdvancedRoute(&route); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := a.store.CreateAdvancedRoute(route); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "an advanced route already exists for this ingress"})
			return
		}
		a.log.Error("create advanced route failed", map[string]any{"account_id": accountID, "err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	a.store.WriteAudit(accountID, "admin", "advanced_route_created", "route="+route.ID, r.RemoteAddr)
	a.reconfigureAsterisk()
	created, _ := a.store.GetAdvancedRoute(route.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (a *API) handleListAdvancedRoutes(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("accountId"))
	routes, err := a.store.ListAdvancedRoutes(accountID)
	if err != nil {
		a.log.Error("list advanced routes failed", map[string]any{"account_id": accountID, "err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, routes)
}

func (a *API) handleGetAdvancedRoute(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("accountId"))
	route, err := a.store.GetAdvancedRoute(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if route == nil || route.AccountID != accountID {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
		return
	}
	writeJSON(w, http.StatusOK, route)
}

func (a *API) handleUpdateAdvancedRoute(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("accountId"))
	id := strings.TrimSpace(r.PathValue("id"))
	existing, err := a.store.GetAdvancedRoute(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if existing == nil || existing.AccountID != accountID {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
		return
	}
	var route store.AdvancedRoute
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	route.ID = id
	route.AccountID = existing.AccountID
	if err := a.validateAdvancedRoute(&route); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := a.store.UpdateAdvancedRoute(route); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "an advanced route already exists for this ingress"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	a.store.WriteAudit(existing.AccountID, "admin", "advanced_route_updated", "route="+id, r.RemoteAddr)
	a.reconfigureAsterisk()
	updated, _ := a.store.GetAdvancedRoute(id)
	writeJSON(w, http.StatusOK, updated)
}

func (a *API) handleDeleteAdvancedRoute(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(r.PathValue("accountId"))
	id := strings.TrimSpace(r.PathValue("id"))
	existing, err := a.store.GetAdvancedRoute(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if existing == nil || existing.AccountID != accountID {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
		return
	}
	if err := a.store.DeleteAdvancedRoute(id, existing.AccountID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	a.store.WriteAudit(existing.AccountID, "admin", "advanced_route_deleted", "route="+id, r.RemoteAddr)
	a.reconfigureAsterisk()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) validateAdvancedRoute(route *store.AdvancedRoute) error {
	route.Name = strings.TrimSpace(route.Name)
	route.IngressKind = strings.ToLower(strings.TrimSpace(route.IngressKind))
	route.IngressValue = strings.TrimSpace(route.IngressValue)
	if route.Name == "" || len(route.Name) > 80 {
		return fmt.Errorf("name is required and must be at most 80 characters")
	}
	if route.IngressKind != "gateway" && route.IngressKind != "sip" && route.IngressKind != "manual" {
		return fmt.Errorf("ingress_kind must be gateway, sip, or manual")
	}
	if route.IngressKind == "manual" && route.Enabled {
		return fmt.Errorf("manual ingress is reserved for a future authenticated trigger API; save this route disabled")
	}
	if !advancedRouteToken.MatchString(route.IngressValue) {
		return fmt.Errorf("ingress_value must be a valid SIP extension, gateway, or manual route key")
	}
	if route.IngressKind != "manual" {
		ep, err := a.store.GetSIPEndpointByAccountAndExtension(route.AccountID, route.IngressValue)
		if err != nil {
			return fmt.Errorf("could not validate ingress endpoint")
		}
		if ep == nil || ep.AccountID != route.AccountID {
			return fmt.Errorf("ingress endpoint does not belong to this account")
		}
		if !ep.Enabled {
			return fmt.Errorf("ingress endpoint is disabled")
		}
	}
	if len(route.Stages) == 0 || len(route.Stages) > 10 {
		return fmt.Errorf("a route must contain between 1 and 10 stages")
	}
	totalRing := 0
	seenRouteTargets := map[string]int{}
	for stageIndex := range route.Stages {
		stage := &route.Stages[stageIndex]
		stage.ID = strings.TrimSpace(stage.ID)
		if stage.ID == "" {
			stage.ID = fmt.Sprintf("stage_%d", stageIndex+1)
		}
		stage.Name = strings.TrimSpace(stage.Name)
		if stage.Name == "" {
			stage.Name = fmt.Sprintf("Stage %d", stageIndex+1)
		}
		if stage.RingSeconds < 3 || stage.RingSeconds > 300 {
			return fmt.Errorf("stage %d ring_seconds must be between 3 and 300", stageIndex+1)
		}
		if stage.MaxCallSeconds < 0 || stage.MaxCallSeconds > 86400 || (stage.MaxCallSeconds > 0 && stage.MaxCallSeconds < 10) {
			return fmt.Errorf("stage %d max_call_seconds must be 0 (unlimited) or between 10 and 86400", stageIndex+1)
		}
		totalRing += stage.RingSeconds
		stage.AnswerMode = strings.ToLower(strings.TrimSpace(stage.AnswerMode))
		if stage.AnswerMode == "" {
			stage.AnswerMode = "first_answer"
		}
		if stage.AnswerMode != "first_answer" && stage.AnswerMode != "conference" && stage.AnswerMode != "private_hub" {
			return fmt.Errorf("stage %d answer_mode is invalid", stageIndex+1)
		}
		if stage.AnswerMode == "private_hub" && route.Enabled {
			return fmt.Errorf("private_hub requires the isolated-media hub capability; save this route disabled until a HAOS browser hub is assigned")
		}
		if len(stage.Targets) == 0 || len(stage.Targets) > 20 {
			return fmt.Errorf("stage %d must contain between 1 and 20 targets", stageIndex+1)
		}
		if stage.AnswerMode == "first_answer" {
			stage.MaxAnswered = 1
		} else if stage.MaxAnswered < 1 || stage.MaxAnswered > 10 {
			return fmt.Errorf("stage %d max_answered must be between 1 and 10", stageIndex+1)
		}
		seen := map[string]bool{}
		enabledTargets := 0
		externalTargets := 0
		hubTargets := 0
		for targetIndex := range stage.Targets {
			target := &stage.Targets[targetIndex]
			target.ID = strings.TrimSpace(target.ID)
			if target.ID == "" {
				target.ID = fmt.Sprintf("target_%d_%d", stageIndex+1, targetIndex+1)
			}
			target.Kind = strings.ToLower(strings.TrimSpace(target.Kind))
			target.Value = strings.TrimSpace(target.Value)
			target.Trunk = strings.TrimSpace(target.Trunk)
			target.Label = strings.TrimSpace(target.Label)
			if !target.Enabled {
				continue
			}
			if route.IngressKind == "sip" && target.Kind == "sip" && target.Value == route.IngressValue && stageIndex != 0 {
				return fmt.Errorf("stage %d target %d: the landing SIP phone may appear only in stage 1", stageIndex+1, targetIndex+1)
			}
			enabledTargets++
			if target.Kind == "external" {
				externalTargets++
			}
			target.Role = strings.ToLower(strings.TrimSpace(target.Role))
			if stage.AnswerMode == "private_hub" {
				if target.Role != "hub" && target.Role != "spoke" {
					return fmt.Errorf("stage %d target %d: private hub role must be hub or spoke", stageIndex+1, targetIndex+1)
				}
				if target.Role == "hub" {
					hubTargets++
				}
			}
			key := target.Kind + ":" + target.Value + ":" + target.Trunk
			if target.Kind == "sip" || target.Kind == "gateway" {
				// SIP and gateway are UI roles for the same endpoint namespace.
				// Treating 1025 as two different destinations merely because one
				// stage labels it "sip" and another labels it "gateway" creates a
				// repeated-ring loop.
				key = "endpoint:" + target.Value
			}
			if seen[key] {
				return fmt.Errorf("stage %d contains duplicate target %s", stageIndex+1, target.Value)
			}
			seen[key] = true
			if previousStage, exists := seenRouteTargets[key]; exists {
				return fmt.Errorf(
					"target %s is repeated in stages %d and %d; each destination may appear only once per route",
					target.Value,
					previousStage,
					stageIndex+1,
				)
			}
			seenRouteTargets[key] = stageIndex + 1
			if err := a.validateAdvancedRouteTarget(route, stage, target); err != nil {
				return fmt.Errorf("stage %d target %d: %w", stageIndex+1, targetIndex+1, err)
			}
		}
		if enabledTargets == 0 {
			return fmt.Errorf("stage %d must have at least one active target", stageIndex+1)
		}
		if externalTargets > 0 {
			if enabledTargets != 1 || externalTargets != 1 {
				return fmt.Errorf("stage %d outside-number forwarding must be the only active target; gateway legs may answer before the remote number rings", stageIndex+1)
			}
			if stage.AnswerMode != "first_answer" {
				return fmt.Errorf("stage %d outside-number forwarding must use first_answer mode", stageIndex+1)
			}
		}
		if stage.AnswerMode == "private_hub" && (enabledTargets < 3 || hubTargets != 1) {
			return fmt.Errorf("stage %d private hub requires exactly one hub and at least two spokes", stageIndex+1)
		}
	}
	if totalRing > 900 {
		return fmt.Errorf("combined stage ring time cannot exceed 900 seconds")
	}
	return nil
}

func (a *API) validateAdvancedRouteTarget(route *store.AdvancedRoute, stage *store.RouteStage, target *store.RouteTarget) error {
	if !advancedRouteToken.MatchString(target.Value) {
		return fmt.Errorf("value is invalid")
	}
	switch target.Kind {
	case "sip", "gateway":
		ep, err := a.store.GetSIPEndpointByAccountAndExtension(route.AccountID, target.Value)
		if err != nil || ep == nil || ep.AccountID != route.AccountID || !ep.Enabled {
			return fmt.Errorf("SIP/gateway endpoint does not belong to this account or is disabled")
		}
		landingSIPTarget := route.IngressKind == "sip" && target.Kind == "sip" && target.Value == route.IngressValue
		if route.IngressKind != "manual" && target.Value == route.IngressValue && !landingSIPTarget {
			return fmt.Errorf("target loops back to the ingress endpoint")
		}
	case "haos":
		node, err := a.store.GetNode(target.Value)
		if err != nil || node == nil || node.AccountID != route.AccountID || !node.Enabled {
			return fmt.Errorf("HAOS node does not belong to this account or is disabled")
		}
		if stage.AnswerMode == "conference" {
			return fmt.Errorf("HAOS conference legs are not supported yet; use first_answer or SIP participants")
		}
	case "external":
		if target.Trunk == "" {
			return fmt.Errorf("external target requires a gateway trunk")
		}
		trunk, err := a.store.GetSIPEndpointByAccountAndExtension(route.AccountID, target.Trunk)
		if err != nil || trunk == nil || trunk.AccountID != route.AccountID || !trunk.Enabled {
			return fmt.Errorf("external target gateway does not belong to this account or is disabled")
		}
		if route.IngressKind == "gateway" && target.Trunk == route.IngressValue {
			return fmt.Errorf("outside-number forwarding cannot seize the same physical gateway that received the call")
		}
	default:
		return fmt.Errorf("kind must be sip, haos, gateway, or external")
	}
	return nil
}
