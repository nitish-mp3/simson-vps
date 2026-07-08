package admin

import "testing"

func TestSafeSIPUsernameRejectsBrokenAORNames(t *testing.T) {
	valid := []string{"1034", "desk-1", "door.cam_2", "WP813A3"}
	for _, username := range valid {
		if !isSafeSIPUsername(username) {
			t.Fatalf("expected username %q to be accepted", username)
		}
	}

	invalid := []string{"", "1", "WP813 A3", "desk/1", "door@site", "नमस्ते"}
	for _, username := range invalid {
		if isSafeSIPUsername(username) {
			t.Fatalf("expected username %q to be rejected", username)
		}
	}
}
