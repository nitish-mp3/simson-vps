package server

import "testing"

func TestNormalizeTransferCode(t *testing.T) {
	tests := map[string]string{
		"84":    "*84",
		" *84 ": "*84",
		"":      "",
		"*8A":   "",
		"*":     "",
	}
	for input, want := range tests {
		if got := normalizeTransferCode(input); got != want {
			t.Errorf("normalizeTransferCode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAdvanceGatewayTransferCapture(t *testing.T) {
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*85", "*86", "*87", "*88")}
	for _, digit := range []string{"*", "8", "4", "1", "0", "2", "6"} {
		target, completed, keep := advanceGatewayTransferCapture(capture, digit)
		if target != "" || completed || !keep {
			t.Fatalf("digit %q produced target=%q completed=%v keep=%v", digit, target, completed, keep)
		}
	}
	target, completed, keep := advanceGatewayTransferCapture(capture, "#")
	if target != "1026" || !completed || keep {
		t.Fatalf("terminator produced target=%q completed=%v keep=%v", target, completed, keep)
	}
	if capture.Action != gatewayBridgeTransfer {
		t.Fatalf("capture action = %q, want transfer", capture.Action)
	}
}

func TestAdvanceGatewayConferenceCaptureUsesSharedPrefix(t *testing.T) {
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*85", "*86", "*87", "*88")}
	for _, digit := range []string{"*", "8", "5", "1", "0", "4", "0"} {
		_, completed, keep := advanceGatewayTransferCapture(capture, digit)
		if completed || !keep {
			t.Fatalf("digit %q produced completed=%v keep=%v", digit, completed, keep)
		}
	}
	if capture.Action != gatewayBridgeConference || capture.Target != "1040" {
		t.Fatalf("capture action=%q target=%q, want conference/1040", capture.Action, capture.Target)
	}
}

func TestAdvanceGatewayConferenceCaptureUsesCustomPrefix(t *testing.T) {
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("", "*89", "*86", "*87", "*88")}
	for _, digit := range []string{"*", "8", "9", "1", "0", "2", "6"} {
		_, completed, keep := advanceGatewayTransferCapture(capture, digit)
		if completed || !keep {
			t.Fatalf("digit %q produced completed=%v keep=%v", digit, completed, keep)
		}
	}
	if capture.Action != gatewayBridgeConference || capture.Target != "1026" {
		t.Fatalf("capture action=%q target=%q, want conference/1026", capture.Action, capture.Target)
	}
}

func TestAdvanceGatewayInviteModes(t *testing.T) {
	tests := []struct {
		digits string
		want   gatewayBridgeFeatureAction
	}{
		{"*861026#", gatewayBridgeListen},
		{"*871026#", gatewayBridgeWhisper},
		{"*881026#", gatewayBridgeBarge},
	}
	for _, tc := range tests {
		capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*85", "*86", "*87", "*88")}
		var target string
		var completed bool
		for _, digit := range tc.digits {
			target, completed, _ = advanceGatewayTransferCapture(capture, string(digit))
		}
		if capture.Action != tc.want || target != "1026" || !completed {
			t.Fatalf("digits %q produced action=%q target=%q completed=%v", tc.digits, capture.Action, target, completed)
		}
	}
}

func TestAdvanceGatewayConferenceCaptureSupportsExplicitGateway(t *testing.T) {
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*85", "*86", "*87", "*88")}
	var target string
	var completed bool
	for _, digit := range "*85*7014*9123208334#" {
		target, completed, _ = advanceGatewayTransferCapture(capture, string(digit))
	}
	if capture.Action != gatewayBridgeConference || target != "*7014*9123208334" || !completed {
		t.Fatalf("explicit gateway produced action=%q target=%q completed=%v", capture.Action, target, completed)
	}
}

func TestAdvanceGatewayTransferCaptureSupportsExplicitGateway(t *testing.T) {
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*89", "*86", "*87", "*88")}
	var target string
	var completed bool
	for _, digit := range "*84*7014*9123208334#" {
		target, completed, _ = advanceGatewayTransferCapture(capture, string(digit))
	}
	if capture.Action != gatewayBridgeTransfer || target != "*7014*9123208334" || !completed {
		t.Fatalf("explicit gateway transfer produced action=%q target=%q completed=%v", capture.Action, target, completed)
	}
}

func TestAdvanceGatewayTransferCaptureRejectsMalformedSequence(t *testing.T) {
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*85", "*86", "*87", "*88")}
	_, _, _ = advanceGatewayTransferCapture(capture, "*")
	if target, completed, keep := advanceGatewayTransferCapture(capture, "9"); target != "" || completed || keep {
		t.Fatalf("malformed sequence produced target=%q completed=%v keep=%v", target, completed, keep)
	}
}
