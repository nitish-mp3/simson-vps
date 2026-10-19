package asterisk

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNativeVideoOriginateAvoidsLocalAndTracksItsRealPJSIPLeg(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ami := &AMIClient{conn: client, connected: true, pending: make(map[string]chan map[string]string)}
	router := newTrackingOnlyRouter()
	router.ami = ami
	requests := make(chan string, 1)
	go func() {
		server.SetReadDeadline(time.Now().Add(time.Second))
		scanner := bufio.NewScanner(server)
		var lines []string
		var actionID string
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}
			lines = append(lines, line)
			if strings.HasPrefix(line, "ActionID: ") {
				actionID = strings.TrimPrefix(line, "ActionID: ")
			}
		}
		ami.pendingMu.Lock()
		response := ami.pending[actionID]
		ami.pendingMu.Unlock()
		if response != nil {
			response <- map[string]string{"Response": "Success"}
		}
		requests <- strings.Join(lines, "\n")
	}()
	if _, err := router.OriginateVideoToExtension("1604", "bridge-fixture", "100", "call-fixture", "office", 30); err != nil {
		t.Fatal(err)
	}
	action := <-requests
	for _, expected := range []string{"Channel: PJSIP/1604", "Context: from-simson-video-source", "Codecs: ulaw,alaw,h264", "Exten: bridge-fixture", "SIMSON_CALL_ID=call-fixture"} {
		if !strings.Contains(action, expected) {
			t.Fatalf("native originate missing %s", expected)
		}
	}
	if strings.Contains(action, "Local/") {
		t.Fatal("native video must never traverse the legacy Local channel")
	}
	if callID, found := router.CallIDForChannel("PJSIP/1604-0001"); !found || callID != "call-fixture" {
		t.Fatal("native PJSIP leg is not tracked for hangup cleanup")
	}
}
