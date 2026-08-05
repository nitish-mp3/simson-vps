package server

import (
	"testing"

	"github.com/nitish-mp3/simson-vps/calls"
)

func TestShouldBroadcastCallStatusToAccount(t *testing.T) {
	tests := []struct {
		name string
		call *calls.Call
		want bool
	}{
		{
			name: "ordinary SIP extension call stays private",
			call: &calls.Call{
				AccountID: "site-a",
				CallType:  "sip",
				FromNode:  "sip:1027",
				ToNode:    "sip:1028",
			},
			want: false,
		},
		{
			name: "SIP media bridge is visible to HAOS",
			call: &calls.Call{
				AccountID:   "site-a",
				CallType:    "sip",
				FromNode:    "sip:7009",
				ToNode:      "haos-office",
				SIPBridgeID: "bridge-1",
			},
			want: true,
		},
		{
			name: "explicit HAOS invite is visible",
			call: &calls.Call{
				AccountID:   "site-a",
				CallType:    "sip",
				FromNode:    "sip:7009",
				ToNode:      "sip:100",
				InviteNodes: []string{"haos-office"},
			},
			want: true,
		},
		{
			name: "HAOS participant is visible without bridge metadata",
			call: &calls.Call{
				AccountID: "site-a",
				CallType:  "sip",
				FromNode:  "haos-office",
				ToNode:    "sip:1027",
			},
			want: true,
		},
		{
			name: "non SIP call is not account-wide SIP telemetry",
			call: &calls.Call{
				AccountID: "site-a",
				CallType:  "webrtc",
				FromNode:  "haos-a",
				ToNode:    "haos-b",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldBroadcastCallStatusToAccount(tt.call); got != tt.want {
				t.Fatalf("shouldBroadcastCallStatusToAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}
