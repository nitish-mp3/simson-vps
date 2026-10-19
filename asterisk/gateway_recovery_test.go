package asterisk

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestImmediateCleanupAddressesRealLocalHalvesWithoutAMIReply(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	router := newTrackingOnlyRouter()
	router.ami = &AMIClient{conn: client}
	router.TrackCall("call-one", "Local/3101@from-simson-callback-source-00000001;1")
	router.TrackCall("call-one", "PJSIP/1701-00000001")
	router.TrackCall("other-call", "PJSIP/3101-00000002")
	received := make(chan []string, 1)
	go func() {
		reader := bufio.NewReader(peer)
		peer.SetReadDeadline(time.Now().Add(time.Second))
		var channels []string
		for len(channels) < 3 {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.HasPrefix(line, "Channel: ") {
				channels = append(channels, strings.TrimSpace(strings.TrimPrefix(line, "Channel: ")))
			}
		}
		received <- channels
	}()
	if err := router.HangupTrackedCallNoWait("call-one", ""); err != nil {
		t.Fatal(err)
	}
	channels := <-received
	for _, required := range []string{"Local/3101@from-simson-callback-source-00000001;1", "Local/3101@from-simson-callback-source-00000001;2", "PJSIP/1701-00000001"} {
		if !strings.Contains(strings.Join(channels, ","), required) {
			t.Fatalf("missing real channel %s: %v", required, channels)
		}
	}
	if strings.Contains(strings.Join(channels, ","), "00000002") {
		t.Fatal("cleanup escaped call boundary")
	}
}

func TestCommandRejectionIsNotAnEmptyChannelSnapshot(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	ami := &AMIClient{conn: client, pending: make(map[string]chan map[string]string)}
	go func() {
		reader := bufio.NewReader(peer)
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
		ami.pendingMu.Lock()
		response := ami.pending[actionID]
		ami.pendingMu.Unlock()
		response <- map[string]string{"Response": "Error", "Message": "Permission denied"}
	}()
	if output, err := ami.RunCommand("core show channels concise"); err == nil || output != "" {
		t.Fatalf("AMI failure returned as successful empty snapshot: %q %v", output, err)
	}
}

func TestSnapshotCallOwnershipFollowsRoomAndLocalSiblingsNotEndpointPrefixes(t *testing.T) {
	router := newTrackingOnlyRouter()
	output := strings.Join([]string{
		"Local/0912@from-simson-out-00000001;1!node!s!1!Up!ConfBridge!bridge-one!100!!!3!12!a!1.1",
		"Local/0912@from-simson-out-00000001;2!out!s!1!Up!Dial!PJSIP/x!100!!!3!12!b!1.2",
		"PJSIP/1701-00000001!ctx!!1!Up!AppDial!x!100!!!3!12!b!1.3",
		"PJSIP/1701-00000002!ctx!!1!Up!AppDial!x!100!!!3!12!other!2.1",
	}, "\n")
	got := router.CallChannelsFromSnapshot(output, "call-one", "bridge-one")
	if len(got) != 3 || strings.Contains(fmt.Sprint(got), "00000002") {
		t.Fatalf("snapshot ownership escaped call: %v", got)
	}
}

func TestDelayedCleanupCannotHangupANewCallOnTheSameGateway(t *testing.T) {
	router := newTrackingOnlyRouter()
	router.TrackPendingPrefix("old-call", "PJSIP/1701-")
	router.TrackPendingPrefix("old-call", "PJSIP/3101-")
	router.TrackCall("old-call", "PJSIP/1701-00000001")
	output := strings.Join([]string{
		"PJSIP/1701-00000002!ctx!!1!Up!AppDial!x!100!!!3!12!new-room!2.1",
		"PJSIP/3101-00000003!ctx!!1!Up!AppDial!x!100!!!3!12!new-room!2.2",
	}, "\n")
	if channels := router.CallCleanupChannelsFromSnapshot(output, "old-call"); len(channels) != 0 {
		t.Fatalf("delayed cleanup selected new call's channels: %v", channels)
	}
}

func TestAMICommandPreservesOldAndNewCompletionMarkers(t *testing.T) {
	for _, marker := range []string{"--END COMMAND--", "Output: --END COMMAND--"} {
		ami := &AMIClient{reader: bufio.NewReader(strings.NewReader("Response: Follows\r\nOutput: a!b\r\n" + marker + "\r\n\r\n"))}
		block, err := ami.readBlock()
		if err != nil || block["Output"] != "a!b\n--END COMMAND--" {
			t.Fatalf("completion marker lost for %q: %v %v", marker, block, err)
		}
	}
}

func TestCommandCompletionFormatsProduceReliableSnapshots(t *testing.T) {
	for _, response := range []map[string]string{
		{"Response": "Follows", "Output": "channel!row"},
		{"Response": "Success", "Output": "channel!row"},
		{"Response": "Success", "Message": "Command output follows"},
		{"Response": "Follows", "Output": "--END COMMAND--"},
	} {
		client, peer := net.Pipe()
		ami := &AMIClient{conn: client, pending: make(map[string]chan map[string]string)}
		go func() {
			reader := bufio.NewReader(peer)
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
			ami.pendingMu.Lock()
			pending := ami.pending[actionID]
			ami.pendingMu.Unlock()
			pending <- response
		}()
		output, err := ami.RunCommand("core show channels concise")
		client.Close()
		peer.Close()
		if err != nil || !strings.HasSuffix(output, "--END COMMAND--") {
			t.Fatalf("complete command response not recognized: %v %q %v", response, output, err)
		}
	}
}
