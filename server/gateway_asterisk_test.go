package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nitish-mp3/simson-vps/asterisk"
	"github.com/nitish-mp3/simson-vps/calls"
	"github.com/nitish-mp3/simson-vps/config"
	"github.com/nitish-mp3/simson-vps/logging"
)

type gatewayProbePhone struct {
	connection *net.UDPConn
	mu         sync.Mutex
	headers    map[string]string
	peer       *net.UDPAddr
	answered   chan struct{}
	ended      chan struct{}
}

func newGatewayProbePhone(t *testing.T) *gatewayProbePhone {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	phone := &gatewayProbePhone{connection: connection, answered: make(chan struct{}, 4), ended: make(chan struct{}, 4)}
	t.Cleanup(func() { connection.Close() })
	go func() {
		buffer := make([]byte, 65536)
		for {
			count, peer, err := connection.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			message := string(buffer[:count])
			lines := strings.Split(message, "\r\n")
			headers := make(map[string]string)
			for _, line := range lines[1:] {
				key, value, ok := strings.Cut(line, ":")
				if ok {
					headers[strings.ToLower(key)] = strings.TrimSpace(value)
				}
			}
			method := strings.Fields(lines[0])[0]
			if method == "SIP/2.0" {
				continue
			}
			if method == "ACK" {
				select {
				case phone.answered <- struct{}{}:
				default:
				}
				continue
			}
			body := ""
			if method == "INVITE" {
				if !strings.Contains(headers["to"], ";tag=") {
					headers["to"] += ";tag=probe-local"
				}
				phone.mu.Lock()
				phone.headers, phone.peer = headers, peer
				phone.mu.Unlock()
				body = "v=0\r\no=probe 1 1 IN IP4 127.0.0.1\r\ns=probe\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 59998 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
			}
			response := fmt.Sprintf("SIP/2.0 200 OK\r\nVia: %s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %s\r\nContact: <sip:probe@%s>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", headers["via"], headers["from"], headers["to"], headers["call-id"], headers["cseq"], connection.LocalAddr(), len(body), body)
			connection.WriteToUDP([]byte(response), peer)
			if method == "BYE" {
				select {
				case phone.ended <- struct{}{}:
				default:
				}
			}
		}
	}()
	return phone
}

func (phone *gatewayProbePhone) hangup(t *testing.T) {
	t.Helper()
	phone.mu.Lock()
	defer phone.mu.Unlock()
	if phone.peer == nil {
		t.Fatal("dummy phone has no SIP dialog")
	}
	uri := strings.Trim(phone.headers["contact"], "<>")
	message := fmt.Sprintf("BYE %s SIP/2.0\r\nVia: SIP/2.0/UDP %s;branch=z9hG4bK-probe-bye;rport\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: 1 BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", uri, phone.connection.LocalAddr(), phone.headers["to"], phone.headers["from"], phone.headers["call-id"])
	if _, err := phone.connection.WriteToUDP([]byte(message), phone.peer); err != nil {
		t.Fatal(err)
	}
}

func gatewayProbePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func startGatewayAsteriskProbe(t *testing.T, source, gateway *gatewayProbePhone) int {
	t.Helper()
	root := t.TempDir()
	port := gatewayProbePort(t)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, directory := range []string{"run", "log", "lib", "spool", "keys"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write("asterisk.conf", fmt.Sprintf("[directories]\nastetcdir=%s\nastmoddir=/usr/lib/asterisk/modules\nastvarlibdir=%s/lib\nastdbdir=%s/lib\nastkeydir=%s/keys\nastdatadir=/usr/share/asterisk\nastagidir=%s/lib\nastspooldir=%s/spool\nastrundir=%s/run\nastlogdir=%s/log\n[options]\nverbose=0\ndebug=0\n", root, root, root, root, root, root, root, root))
	write("modules.conf", "[modules]\nautoload=yes\nnoload=chan_sip.so\nnoload=chan_iax2.so\nnoload=chan_mgcp.so\nnoload=chan_skinny.so\nnoload=chan_unistim.so\nnoload=pbx_dundi.so\nnoload=res_snmp.so\n")
	write("http.conf", "[general]\nenabled=no\n")
	write("logger.conf", "[general]\n[logfiles]\nfull=notice,warning,error\n")
	write("rtp.conf", "[general]\nrtpstart=59930\nrtpend=59950\n")
	write("manager.conf", fmt.Sprintf("[general]\nenabled=yes\nbindaddr=127.0.0.1\nport=%d\n[probe]\nsecret=fixture-only\nread=all\nwrite=all\n", port))
	write("confbridge.conf", "[simson_bridge]\ntype=bridge\ninternal_sample_rate=8000\n[simson_user]\ntype=user\nquiet=yes\nwait_marked=no\nend_marked=no\n")
	write("extensions.conf", "[from-simson-node]\nexten => _bridge-.,1,Answer()\nsame => n,ConfBridge(${EXTEN},simson_bridge,simson_user)\nsame => n,Hangup()\n[from-simson-callback-source]\nexten => _X.,1,Dial(PJSIP/${EXTEN},10,T)\nsame => n,Hangup()\n[from-simson-out]\nexten => _X.,1,Dial(PJSIP/${EXTEN}@${SIMSON_TRUNK},10,b(simson-outbound-mark^s^1(${SIMSON_CALL_ID})))\nsame => n,Hangup()\n[simson-outbound-mark]\nexten => s,1,Set(SIMSON_CALL_ID=${ARG1})\nsame => n,Return()\n")
	transport, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	transportAddress := transport.LocalAddr().String()
	transport.Close()
	endpoints := "[probe-udp]\ntype=transport\nprotocol=udp\nbind=" + transportAddress + "\n"
	for name, phone := range map[string]*gatewayProbePhone{"3101": source, "1701": gateway} {
		endpoints += fmt.Sprintf("[%s]\ntype=endpoint\ntransport=probe-udp\ncontext=from-simson-node\ndisallow=all\nallow=ulaw\naors=%s\ndirect_media=no\ntimers=no\n[%s]\ntype=aor\ncontact=sip:%s@%s\n", name, name, name, name, phone.connection.LocalAddr())
	}
	write("pjsip.conf", endpoints)
	logfile, err := os.Create(filepath.Join(root, "startup.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/sbin/asterisk", "-f", "-n", "-q", "-C", filepath.Join(root, "asterisk.conf"))
	command.Stdout, command.Stderr = logfile, logfile
	if err := command.Start(); err != nil {
		logfile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			for _, name := range []string{"startup.log", "log/full"} {
				data, _ := os.ReadFile(filepath.Join(root, name))
				if len(data) > 1800 {
					data = data[len(data)-1800:]
				}
				t.Logf("isolated %s: %s", name, data)
			}
		}
		command.Process.Kill()
		command.Wait()
		logfile.Close()
	})
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			connection.Close()
			output, _ := exec.Command("/usr/sbin/asterisk", "-C", filepath.Join(root, "asterisk.conf"), "-rx", "dialplan show from-simson-node").CombinedOutput()
			if strings.Contains(string(output), "ConfBridge") {
				endpoint, _ := exec.Command("/usr/sbin/asterisk", "-C", filepath.Join(root, "asterisk.conf"), "-rx", "pjsip show endpoint 3101").CombinedOutput()
				if strings.Contains(string(endpoint), "sip:3101@127.0.0.1:") {
					ready, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := exec.CommandContext(ready, "/usr/sbin/asterisk", "-C", filepath.Join(root, "asterisk.conf"), "-rx", "core waitfullybooted").Run(); err != nil {
						t.Fatal(err)
					}
					return port
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	data, _ := os.ReadFile(filepath.Join(root, "startup.log"))
	t.Fatalf("isolated Asterisk did not start: %s", data)
	return 0
}

func TestGatewayRealAsteriskDisconnectLifecycle(t *testing.T) {
	if os.Getenv("SIMSON_ASTERISK_TEST") != "1" || runtime.GOOS != "linux" {
		t.Skip("explicit isolated Linux Asterisk probe only; never uses production extensions")
	}
	for _, scenario := range []string{"gateway_bye", "source_bye", "gateway_event_missing", "all_events_missing", "late_answer_after_cancel"} {
		t.Run(scenario, func(t *testing.T) {
			source, gateway := newGatewayProbePhone(t), newGatewayProbePhone(t)
			port := startGatewayAsteriskProbe(t, source, gateway)
			configuration := config.DefaultConfig()
			server := New(configuration, nil, logging.New("error"))
			ami := asterisk.NewAMIClient("127.0.0.1", port, "probe", "fixture-only", logging.New("error"))
			router := asterisk.NewRouter(ami, logging.New("error"))
			server.asterisk = router
			results := make(chan bool, 4)
			router.OnOriginateResult = func(_ string, ok bool, _ string) { results <- ok }
			router.OnChannelHangup = func(info asterisk.ChannelHangup) {
				if scenario == "all_events_missing" || scenario == "gateway_event_missing" && strings.HasPrefix(info.Channel, "PJSIP/1701-") {
					return
				}
				server.handleSIPChannelHangup(info)
			}
			if err := router.Connect(); err != nil {
				t.Fatal(err)
			}
			router.Start()
			t.Cleanup(router.Disconnect)
			call := &calls.Call{ID: "call_probe", FromNode: "sip:3101", ToNode: "sip:9123208334", CallType: "sip", SIPBridgeID: "bridge-probe", GatewayTrunk: "1701", SourceExtension: "3101"}
			server.calls.Create(call)
			if _, err := router.OriginateCallbackToBridge("3101", "from-simson-node", call.SIPBridgeID, "100", call.ID, "", 10); err != nil {
				t.Fatal(err)
			}
			select {
			case ok := <-results:
				if !ok {
					t.Fatal("dummy source failed to answer")
				}
			case <-time.After(12 * time.Second):
				t.Fatal("dummy source timed out")
			}
			if _, err := router.OriginateToTrunk("9123208334", "1701", "from-simson-out", "from-simson-node", call.SIPBridgeID, "100", call.ID, call.FromNode, "", "", 10, 0); err != nil {
				t.Fatal(err)
			}
			select {
			case ok := <-results:
				if !ok {
					t.Fatal("dummy gateway failed to answer")
				}
			case <-time.After(12 * time.Second):
				t.Fatal("dummy gateway timed out")
			}
			server.calls.Accept(call.ID, "")
			time.Sleep(200 * time.Millisecond)
			initial, err := router.RunCommand("core show channels concise")
			if err != nil || !validGatewaySnapshot(initial) {
				t.Fatalf("incomplete real AMI channel snapshot: %q %v", initial, err)
			}
			server.sipGatewayPeerMissing = map[string]time.Time{call.ID: time.Now().Add(-time.Hour)}
			server.reconcileOutboundGatewayCalls()
			if server.calls.Snapshots()[0].State != calls.StateActive {
				t.Fatal("healthy silent call was cut off")
			}
			receiver := source
			if scenario == "late_answer_after_cancel" {
				server.calls.End(call.ID, "hangup")
				server.handleSIPOriginateResult(call.ID, true, "4")
			} else if scenario == "source_bye" {
				source.hangup(t)
				receiver = gateway
			} else {
				gateway.hangup(t)
			}
			if scenario == "all_events_missing" {
				time.Sleep(300 * time.Millisecond)
				server.gatewayTransferPending[call.ID] = &gatewayTransferPending{CallID: call.ID}
				server.reconcileOutboundGatewayCalls()
				if server.calls.Snapshots()[0].State != calls.StateActive {
					t.Fatal("watchdog interrupted a pending transfer")
				}
				delete(server.gatewayTransferPending, call.ID)
				server.reconcileOutboundGatewayCalls()
				if server.calls.Snapshots()[0].State != calls.StateActive {
					t.Fatal("missing-peer grace not respected")
				}
				server.sipGatewayCallbackMu.Lock()
				server.sipGatewayPeerMissing[call.ID] = time.Now().Add(-21 * time.Second)
				server.sipGatewayCallbackMu.Unlock()
				server.reconcileOutboundGatewayCalls()
			}
			select {
			case <-receiver.ended:
			case <-time.After(3 * time.Second):
				t.Fatal("other SIP phone never received automatic BYE")
			}
			deadline := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline) {
				output, err := router.RunCommand("core show channels concise")
				if err == nil && validGatewaySnapshot(output) && !strings.Contains(output, "PJSIP/") && !strings.Contains(output, "Local/") {
					if server.calls.Snapshots()[0].State != calls.StateEnded {
						t.Fatal("channels cleared but call still active")
					}
					t.Log("dummy peer received BYE; no Local or PJSIP channels remain")
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
			t.Fatal("isolated call channels did not clear")
		})
	}
}
