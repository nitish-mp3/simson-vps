package asterisk

import (
	"os"
	"strings"
	"testing"
)

func TestBrowserExtensionOriginateDoesNotSeedVideoAsLegacyAudioFormat(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "func (r *Router) OriginateToExtension(")
	end := strings.Index(string(source)[start+1:], "\nfunc ")
	body := string(source)[start : start+1+end]
	if strings.Contains(body, "OriginateWithVarsAndCodecs") || !strings.Contains(body, "r.ami.OriginateWithVars(") {
		t.Fatal("legacy Local/ConfBridge originate must retain its audio format topology; mixed H264 causes invalid audio translator failures")
	}
}
