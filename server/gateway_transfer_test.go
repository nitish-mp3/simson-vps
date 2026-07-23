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
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*85")}
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
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*85")}
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
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("", "*89")}
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

func TestAdvanceGatewayTransferCaptureRejectsMalformedSequence(t *testing.T) {
	capture := &gatewayTransferCapture{Codes: configuredGatewayBridgeFeatureCodes("*84", "*85")}
	_, _, _ = advanceGatewayTransferCapture(capture, "*")
	if target, completed, keep := advanceGatewayTransferCapture(capture, "9"); target != "" || completed || keep {
		t.Fatalf("malformed sequence produced target=%q completed=%v keep=%v", target, completed, keep)
	}
}
