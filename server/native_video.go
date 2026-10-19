package server

import (
	"strings"

	"github.com/nitish-mp3/simson-vps/store"
)

func nativeVideoEndpoint(endpoint *store.SIPEndpoint) bool {
	if endpoint == nil || !endpoint.Enabled || !endpoint.VideoEnabled || isReservedGatewayExtension(endpoint.Extension) || endpoint.DefaultOutbound {
		return false
	}
	if endpoint.AutoAnswer || endpoint.AutoSpeaker || endpoint.CallbackBridge || endpoint.AnswerAnnouncement != "" || endpoint.PreRingAnnouncement != "" || endpoint.AnswerAnnouncementText != "" || endpoint.PreRingAnnouncementText != "" {
		return false
	}
	rules := strings.TrimSpace(endpoint.CallDurationRules)
	return rules == "" || rules == "{}" || rules == "null"
}
