package asterisk

import (
	"sort"
	"strings"
)

func callCleanupChannels(output, callID string, tracked, prefixes []string) []string {
	known := make(map[string]bool, len(tracked))
	for _, channel := range tracked {
		known[normalizeChannel(channel)] = true
	}
	selected := make(map[string]bool)
	bridges := make(map[string]bool)
	rows := make([]conciseChannel, 0)
	anchored := false
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "!")
		if len(parts) >= 7 && (known[normalizeChannel(parts[0])] || callID != "" && parts[5] == "ConfBridge" && strings.Split(parts[6], ",")[0] == "bridge-"+strings.TrimPrefix(callID, "call_")) {
			anchored = true
			break
		}
	}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "!")
		if len(parts) < 7 {
			continue
		}
		row := conciseChannel{name: strings.TrimSpace(parts[0]), base: normalizeChannel(parts[0])}
		if len(parts) > 12 {
			row.bridgeID = strings.TrimSpace(parts[12])
		}
		rows = append(rows, row)
		match := known[row.base]
		for _, prefix := range prefixes {
			if !anchored && prefix != "" && strings.HasPrefix(row.name, prefix) {
				match = true
			}
		}
		if callID != "" && parts[5] == "ConfBridge" && strings.Split(parts[6], ",")[0] == "bridge-"+strings.TrimPrefix(callID, "call_") {
			match = true
		}
		if match {
			selected[row.base] = true
			if row.bridgeID != "" && row.bridgeID != "0" {
				bridges[row.bridgeID] = true
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, row := range rows {
			if !selected[row.base] && !bridges[row.bridgeID] {
				continue
			}
			if !selected[row.base] {
				selected[row.base] = true
				changed = true
			}
			if row.bridgeID != "" && row.bridgeID != "0" && !bridges[row.bridgeID] {
				bridges[row.bridgeID] = true
				changed = true
			}
		}
	}
	channels := make([]string, 0)
	for _, row := range rows {
		if selected[row.base] {
			channels = append(channels, row.name)
		}
	}
	sort.Strings(channels)
	return channels
}
