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

func TestAdvancedRouteStageWithLandingPhone(t *testing.T) {
	run := &advancedRouteRun{
		ingressExt: "1040",
		plan:       store.AdvancedRoute{IngressKind: "sip", IngressValue: "1040"},
	}
	stage := store.RouteStage{Targets: []store.RouteTarget{{Kind: "sip", Value: "1027", Enabled: true}}}

	got := advancedRouteStageWithLandingPhone(run, stage, 0, "1034")
	if len(got.Targets) != 2 || got.Targets[0].Value != "1040" || got.Targets[1].Value != "1027" {
		t.Fatalf("landing phone was not prepended to stage one: %#v", got.Targets)
	}
	if len(stage.Targets) != 1 {
		t.Fatalf("configured stage was mutated: %#v", stage.Targets)
	}

	explicit := store.RouteStage{Targets: []store.RouteTarget{{Kind: "sip", Value: "1040", Enabled: true}}}
	got = advancedRouteStageWithLandingPhone(run, explicit, 0, "1034")
	if len(got.Targets) != 1 {
		t.Fatalf("explicit landing phone was duplicated: %#v", got.Targets)
	}

	got = advancedRouteStageWithLandingPhone(run, stage, 1, "1034")
	if len(got.Targets) != 1 {
		t.Fatalf("landing phone was added outside stage one: %#v", got.Targets)
	}

	got = advancedRouteStageWithLandingPhone(run, stage, 0, "1040")
	if len(got.Targets) != 1 {
		t.Fatalf("caller was routed back to itself: %#v", got.Targets)
	}
}

func TestAdvancedRouteLandingCandidatesNeverUseCaller(t *testing.T) {
	got := advancedRouteLandingCandidates("1040", "1040", "1027", "1027")
	if len(got) != 1 || got[0] != "1040" {
		t.Fatalf("landing candidates = %#v, want only called extension 1040", got)
	}
}
