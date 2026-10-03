package server

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestAnonymousRegisterSecurityFilterDoesNotMatchLegitimateAuthentication(t *testing.T) {
	content, err := os.ReadFile("../deploy/fail2ban/simson-anonymous.conf")
	if err != nil {
		t.Fatal(err)
	}
	var pattern string
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, `SecurityEvent="FailedACL"`) {
			pattern = strings.TrimSpace(line)
		}
	}
	if pattern == "" {
		t.Fatal("missing anonymous registration filter")
	}
	matcher, err := regexp.Compile(strings.ReplaceAll(pattern, "<HOST>", `(?P<host>[0-9a-fA-F:.]+)`))
	if err != nil {
		t.Fatal(err)
	}
	base := `[Oct  3 19:29:46] SECURITY[1606096] res_security_log.c: SecurityEvent="FailedACL",EventTV="2026-10-03T19:29:46.165+0000",Severity="Error",Service="PJSIP",EventVersion="1",AccountID="anonymous",SessionID="mock-session",LocalAddress="IPV4/UDP/10.0.0.83/5060",RemoteAddress="IPV4/UDP/203.0.113.99/5066",ACLName="registrar_attempt_without_configured_aors"`
	for _, line := range []string{base, strings.Replace(base, "IPV4/UDP/203.0.113.99/5066", "IPV6/TCP/2001:db8::99/5066", 1)} {
		if !matcher.MatchString(line) {
			t.Fatalf("rejected anonymous registration not matched: %s", line)
		}
	}
	for _, line := range []string{
		strings.Replace(base, `AccountID="anonymous"`, `AccountID="1701"`, 1),
		strings.Replace(base, `SecurityEvent="FailedACL"`, `SecurityEvent="SuccessfulAuth"`, 1),
		strings.Replace(base, `SecurityEvent="FailedACL"`, `SecurityEvent="ChallengeSent"`, 1),
		strings.Replace(base, "registrar_attempt_without_configured_aors", "registrar_invalid_uri_in_to_received", 1),
		strings.Replace(base, `SessionID="mock-session"`, `SessionID="spoof",RemoteAddress="IPV4/UDP/192.0.2.10/5066"`, 1),
	} {
		if matcher.MatchString(line) {
			t.Fatalf("unrelated or malformed security event matched: %s", line)
		}
	}
}
