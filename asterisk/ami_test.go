package asterisk

import "testing"

func TestBuildOriginateActionAddsCodecsOnlyWhenRequested(t *testing.T) {
	door := buildOriginateAction(
		"PJSIP/1602",
		"from-simson-door",
		"1601",
		"\"Door Station\" <1602>",
		30000,
		"door-action",
		map[string]string{"SIMSON_CALL_ID": "door-call"},
		"ulaw,alaw,h264",
	)
	if got := door["Codecs"]; got != "ulaw,alaw,h264" {
		t.Fatalf("door originate codecs = %q, want explicit audio and H.264 topology", got)
	}

	audioOnly := buildOriginateAction(
		"PJSIP/1025",
		"from-simson-extension",
		"bridge-test",
		"\"Test\" <100>",
		30000,
		"audio-action",
		nil,
		"",
	)
	if got := audioOnly["Codecs"]; got != "" {
		t.Fatalf("ordinary originate unexpectedly opts into codecs %q", got)
	}
	if _, exists := audioOnly["Codecs"]; exists {
		t.Fatal("ordinary originate unexpectedly includes a Codecs AMI field")
	}
}
