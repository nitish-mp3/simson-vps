package server

import (
	"testing"

	"github.com/nitish-mp3/simson-vps/store"
)

func TestUnsafeExternalAdvancedStage(t *testing.T) {
	tests := []struct {
		name   string
		plan   store.AdvancedRoute
		stage  store.RouteStage
		unsafe bool
	}{
		{
			name: "separate inbound and outbound gateways are safe",
			plan: store.AdvancedRoute{IngressKind: "gateway", IngressValue: "7014"},
			stage: store.RouteStage{AnswerMode: "first_answer", Targets: []store.RouteTarget{
				{Kind: "external", Value: "919123208334", Trunk: "7009", Enabled: true},
			}},
		},
		{
			name: "same physical gateway is rejected",
			plan: store.AdvancedRoute{IngressKind: "gateway", IngressValue: "7014"},
			stage: store.RouteStage{AnswerMode: "first_answer", Targets: []store.RouteTarget{
				{Kind: "external", Value: "919123208334", Trunk: "7014", Enabled: true},
			}},
			unsafe: true,
		},
		{
			name: "outside leg cannot compete with a SIP phone",
			plan: store.AdvancedRoute{IngressKind: "gateway", IngressValue: "7014"},
			stage: store.RouteStage{AnswerMode: "first_answer", Targets: []store.RouteTarget{
				{Kind: "external", Value: "919123208334", Trunk: "7009", Enabled: true},
				{Kind: "sip", Value: "1027", Enabled: true},
			}},
			unsafe: true,
		},
		{
			name: "outside leg cannot be a conference",
			plan: store.AdvancedRoute{IngressKind: "gateway", IngressValue: "7014"},
			stage: store.RouteStage{AnswerMode: "conference", Targets: []store.RouteTarget{
				{Kind: "external", Value: "919123208334", Trunk: "7009", Enabled: true},
			}},
			unsafe: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := unsafeExternalAdvancedStage(test.plan, test.stage)
			if (got != "") != test.unsafe {
				t.Fatalf("unsafeExternalAdvancedStage() = %q, unsafe=%v", got, test.unsafe)
			}
		})
	}
}
