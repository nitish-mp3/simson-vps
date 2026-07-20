package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/nitish-mp3/simson-vps/store"
)

var accountFeatureCode = regexp.MustCompile(`^\*[0-9]{2,5}$`)

func (a *API) handleGetAccountCallFeatures(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("accountId")
	if account, err := a.store.GetAccount(accountID); err != nil || account == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "account not found"})
		return
	}
	features, err := a.store.GetAccountCallFeatures(accountID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, features)
}

func (a *API) handlePutAccountCallFeatures(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("accountId")
	if account, err := a.store.GetAccount(accountID); err != nil || account == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "account not found"})
		return
	}
	var body store.AccountCallFeatures
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	body.AccountID = accountID
	body.TransferCode = normalizeAccountFeatureCode(body.TransferCode)
	body.ConferenceCode = normalizeAccountFeatureCode(body.ConferenceCode)
	if err := a.validateAccountCallFeatures(body); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := a.store.UpsertAccountCallFeatures(body); err != nil {
		a.log.Error("call feature policy update failed", map[string]any{"account_id": accountID, "err": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	a.store.WriteAudit(accountID, "admin", "account_call_features_updated",
		fmt.Sprintf("transfer=%s conference=%s enabled=%t", body.TransferCode, body.ConferenceCode, body.Enabled), r.RemoteAddr)
	a.reconfigureAsterisk()
	features, _ := a.store.GetAccountCallFeatures(accountID)
	writeJSON(w, http.StatusOK, features)
}

func normalizeAccountFeatureCode(value string) string {
	value = strings.TrimSpace(value)
	if value != "" && !strings.HasPrefix(value, "*") {
		value = "*" + value
	}
	return value
}

func (a *API) validateAccountCallFeatures(features store.AccountCallFeatures) error {
	if !accountFeatureCode.MatchString(features.TransferCode) {
		return fmt.Errorf("transfer_code must be a star followed by 2 to 5 digits")
	}
	if !accountFeatureCode.MatchString(features.ConferenceCode) {
		return fmt.Errorf("conference_code must be a star followed by 2 to 5 digits")
	}
	if features.TransferCode == features.ConferenceCode {
		return fmt.Errorf("transfer and conference codes must be different")
	}
	if features.TransferCode == "*100" || features.ConferenceCode == "*100" {
		return fmt.Errorf("*100 is reserved for the HAOS card")
	}
	endpoints, err := a.store.ListSIPEndpoints(features.AccountID)
	if err != nil {
		return fmt.Errorf("could not validate existing SIP feature codes")
	}
	for _, ep := range endpoints {
		if !ep.Enabled || strings.TrimSpace(ep.SupervisionConfig) == "" {
			continue
		}
		var supervision map[string]any
		if json.Unmarshal([]byte(ep.SupervisionConfig), &supervision) != nil {
			continue
		}
		for _, key := range []string{"listen_key", "whisper_key", "barge_key"} {
			if existing, _ := supervision[key].(string); normalizeAccountFeatureCode(existing) == features.TransferCode || normalizeAccountFeatureCode(existing) == features.ConferenceCode {
				return fmt.Errorf("feature code conflicts with %s supervision on extension %s", key, ep.Extension)
			}
		}
	}
	return nil
}
