package asterisk

import (
	"bufio"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nitish-mp3/simson-vps/logging"
)

func TestCallbackCleanupUsesRealLocalNamesAndDoesNotGroupEqualDurations(t *testing.T) {
	output := strings.Join([]string{
		"Local/3101@from-simson-callback-source-0001;1!from-simson-node!bridge-one!4!Up!ConfBridge!bridge-one,simson_bridge,simson_user!3101!!!3!612!room-a!1791.1",
		"Local/3101@from-simson-callback-source-0001;2!from-simson-callback-source!3101!6!Up!Dial!PJSIP/3101,30!3101!!!3!612!room-b!1791.2",
		"PJSIP/3101-0001!from-simson-sip!!1!Up!AppDial!(Outgoing Line)!3101!!!3!612!room-b!1791.3",
		"CBAnn/bridge-one-0001;2!default!s!1!Up!(None)!!3101!!!3!612!room-a!1791.4",
		"PJSIP/9999-0002!from-simson-sip!!1!Up!Dial!PJSIP/9998!9999!!!3!612!other-room!1792.1",
		"PJSIP/3101-9999!from-simson-sip!!1!Up!Dial!PJSIP/9998!3101!!!3!612!other-room!1792.2",
	}, "\n")
	got := callCleanupChannels(output, "call_one", []string{"Local/3101@from-simson-callback-source-0001"}, []string{"PJSIP/3101-"})
	want := []string{"CBAnn/bridge-one-0001;2", "Local/3101@from-simson-callback-source-0001;1", "Local/3101@from-simson-callback-source-0001;2", "PJSIP/3101-0001"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("call cleanup = %v, want %v", got, want)
	}
	got = endpointCleanupChannels(strings.Split(output, "\nPJSIP/3101-9999")[0], "3101")
	if len(got) != 4 || strings.Contains(strings.Join(got, ","), "9999") {
		t.Fatalf("endpoint cleanup crossed real call boundaries: %v", got)
	}
}

func TestOriginateCallbackCanRunAMIActionsWithoutBlockingReadLoop(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ami := &AMIClient{conn: clientConn, reader: bufio.NewReader(clientConn), connected: true,
		pending: make(map[string]chan map[string]string), log: logging.New("error")}
	router := NewRouter(ami, ami.log)
	router.actionIDToCallID["source-action"] = "call-one"
	done := make(chan error, 1)
	router.OnOriginateResult = func(callID string, ok bool, reason string) {
		_, err := ami.RunCommand("core show channels concise")
		done <- err
	}
	go ami.ReadLoop()
	go func() {
		fmt.Fprint(serverConn, "Event: OriginateResponse\r\nActionID: source-action\r\nResponse: Success\r\nChannel: Local/3101@from-simson-callback-source-0001;1\r\n\r\n")
		reader := bufio.NewReader(serverConn)
		var actionID string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "ActionID: ") {
				actionID = strings.TrimSpace(strings.TrimPrefix(line, "ActionID: "))
			}
			if line == "\r\n" {
				break
			}
		}
		fmt.Fprintf(serverConn, "Response: Follows\r\nActionID: %s\r\nOutput: --END COMMAND--\r\n\r\n", actionID)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("AMI callback blocked its own response reader")
	}
}
