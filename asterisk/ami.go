// Package asterisk provides an Asterisk Manager Interface (AMI) client
// and VPS-side call-routing utilities for the Simson control plane.
package asterisk

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nitish-mp3/simson-vps/logging"
)

// Event is an AMI event pushed by Asterisk.
type Event struct {
	Name   string
	Fields map[string]string
}

// AMIClient manages a persistent TCP connection to the Asterisk Manager
// Interface (AMI). It is safe to use from multiple goroutines.
type AMIClient struct {
	host   string
	port   int
	user   string
	secret string
	log    *logging.Logger

	// write serialisation — guards conn writes and reader field
	writeMu sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader

	// event handlers
	handlersMu sync.RWMutex
	handlers   []func(Event)

	// action/response correlation
	pendingMu sync.Mutex
	pending   map[string]chan map[string]string

	// connection state
	connMu    sync.RWMutex
	connected bool
}

// NewAMIClient creates a new client. Call Connect before anything else.
func NewAMIClient(host string, port int, user, secret string, log *logging.Logger) *AMIClient {
	return &AMIClient{
		host:    host,
		port:    port,
		user:    user,
		secret:  secret,
		log:     log,
		pending: make(map[string]chan map[string]string),
	}
}

// OnEvent registers a handler that is called for every AMI event.
// Handlers run sequentially in the ReadLoop goroutine.
func (a *AMIClient) OnEvent(fn func(Event)) {
	a.handlersMu.Lock()
	a.handlers = append(a.handlers, fn)
	a.handlersMu.Unlock()
}

// Connected reports whether the client is currently authenticated.
func (a *AMIClient) Connected() bool {
	a.connMu.RLock()
	defer a.connMu.RUnlock()
	return a.connected
}

// Connect dials Asterisk, reads the banner, and logs in.
func (a *AMIClient) Connect() error {
	addr := net.JoinHostPort(a.host, fmt.Sprintf("%d", a.port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("ami dial %s: %w", addr, err)
	}

	reader := bufio.NewReaderSize(conn, 65536)

	// Read the Asterisk banner (single line), e.g.:
	// "Asterisk Call Manager/2.11.0\r\n"
	if _, err := reader.ReadString('\n'); err != nil {
		conn.Close()
		return fmt.Errorf("ami banner: %w", err)
	}

	a.writeMu.Lock()
	a.conn = conn
	a.reader = reader

	// Authenticate synchronously. ReadLoop is started only after Connect returns,
	// so sendAction() cannot be used here (it waits for ReadLoop to dispatch).
	actionID := uuid.NewString()
	login := "Action: Login\r\n" +
		"ActionID: " + actionID + "\r\n" +
		"Username: " + a.user + "\r\n" +
		"Secret: " + a.secret + "\r\n" +
		"Events: on\r\n\r\n"

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, writeErr := fmt.Fprint(conn, login)
	conn.SetWriteDeadline(time.Time{})
	a.writeMu.Unlock()
	if writeErr != nil {
		conn.Close()
		return fmt.Errorf("ami login write: %w", writeErr)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := a.readBlock()
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return fmt.Errorf("ami login read: %w", err)
	}
	if resp["Response"] != "Success" {
		conn.Close()
		return fmt.Errorf("ami auth failed: %s", resp["Message"])
	}

	a.connMu.Lock()
	a.connected = true
	a.connMu.Unlock()

	a.log.Info("asterisk ami connected", map[string]any{
		"host": a.host, "port": a.port,
	})
	return nil
}

// Disconnect closes the connection and marks the client as disconnected.
func (a *AMIClient) Disconnect() {
	a.writeMu.Lock()
	conn := a.conn
	a.conn = nil
	a.reader = nil
	a.writeMu.Unlock()

	if conn != nil {
		conn.Close()
	}

	a.connMu.Lock()
	a.connected = false
	a.connMu.Unlock()
}

// ReadLoop processes inbound messages until the connection drops.
// Run this in a goroutine; it returns when the connection is closed.
func (a *AMIClient) ReadLoop() {
	defer func() {
		a.connMu.Lock()
		a.connected = false
		a.connMu.Unlock()
		a.log.Warn("asterisk ami disconnected", nil)
		// Drain all pending action waits so callers don't block forever.
		a.pendingMu.Lock()
		for _, ch := range a.pending {
			select {
			case ch <- map[string]string{"Response": "Error", "Message": "disconnected"}:
			default:
			}
		}
		a.pendingMu.Unlock()
	}()

	for {
		block, err := a.readBlock()
		if err != nil {
			return
		}
		if len(block) == 0 {
			continue
		}

		// Is this the response to a pending action (has ActionID)?
		if actionID, hasID := block["ActionID"]; hasID {
			a.pendingMu.Lock()
			ch, exists := a.pending[actionID]
			a.pendingMu.Unlock()
			if exists {
				select {
				case ch <- block:
				default:
				}
				// If it also has an Event field, fall through to event dispatch.
				if _, isEvent := block["Event"]; !isEvent {
					continue
				}
			}
		}

		// Is this an event?
		if name, isEvent := block["Event"]; isEvent {
			ev := Event{Name: name, Fields: block}
			a.handlersMu.RLock()
			hs := a.handlers
			a.handlersMu.RUnlock()
			for _, h := range hs {
				h(ev)
			}
		}
	}
}

// Originate makes an outbound call to a SIP extension.
// Returns the ActionID so the caller can correlate the async OriginateResponse event.
func (a *AMIClient) Originate(channel, context, exten, callerID, callID, fromNode string, timeoutMs int) (string, error) {
	return a.OriginateWithActionID(channel, context, exten, callerID, callID, fromNode, timeoutMs, "")
}

// OriginateWithActionID is like Originate but allows a caller-provided ActionID.
// This is useful when the caller needs to register async tracking before sending
// the AMI action to avoid missing very fast OriginateResponse events.
func (a *AMIClient) OriginateWithActionID(channel, context, exten, callerID, callID, fromNode string, timeoutMs int, actionID string) (string, error) {
	actionID, resp, err := a.sendAction(map[string]string{
		"Action":   "Originate",
		"ActionID": actionID,
		"Channel":  channel,
		"Context":  context,
		"Exten":    exten,
		"Priority": "1",
		"CallerID": callerID,
		"Timeout":  fmt.Sprintf("%d", timeoutMs),
		// comma-joined variables — Asterisk Originate supports KEY=VAL,KEY2=VAL2
		"Variable": fmt.Sprintf("SIMSON_CALL_ID=%s,SIMSON_FROM_NODE=%s", callID, fromNode),
		"Async":    "true",
	})
	if err != nil {
		return "", err
	}
	if resp["Response"] != "Success" {
		return "", fmt.Errorf("originate failed: %s", resp["Message"])
	}
	return actionID, nil
}

// HangupChannel hangs up a specific Asterisk channel.
func (a *AMIClient) HangupChannel(channel string) error {
	_, resp, err := a.sendAction(map[string]string{
		"Action":  "Hangup",
		"Channel": channel,
		"Cause":   "16", // normal clearing
	})
	if err != nil {
		return err
	}
	if resp["Response"] != "Success" {
		return fmt.Errorf("hangup failed: %s", resp["Message"])
	}
	return nil
}

// BridgeChannels bridges two Asterisk channels together.
func (a *AMIClient) BridgeChannels(ch1, ch2 string) error {
	_, resp, err := a.sendAction(map[string]string{
		"Action":   "Bridge",
		"Channel1": ch1,
		"Channel2": ch2,
		"Tone":     "no",
	})
	if err != nil {
		return err
	}
	if resp["Response"] != "Success" {
		return fmt.Errorf("bridge failed: %s", resp["Message"])
	}
	return nil
}

// RunCommand sends an Asterisk CLI command and returns the output.
func (a *AMIClient) RunCommand(cmd string) (string, error) {
	_, resp, err := a.sendAction(map[string]string{
		"Action":  "Command",
		"Command": cmd,
	})
	if err != nil {
		return "", err
	}
	return resp["Output"] + resp["Message"], nil
}

// ---- internal ---------------------------------------------------------------

// sendAction writes an AMI action and waits for the correlated response.
// It assigns a new UUID ActionID unless fields["ActionID"] is already set.
// Returns (actionID, responseBlock, error).
func (a *AMIClient) sendAction(fields map[string]string) (string, map[string]string, error) {
	actionID := fields["ActionID"]
	if actionID == "" {
		actionID = uuid.NewString()
		fields["ActionID"] = actionID
	}

	ch := make(chan map[string]string, 1)
	a.pendingMu.Lock()
	a.pending[actionID] = ch
	a.pendingMu.Unlock()

	defer func() {
		a.pendingMu.Lock()
		delete(a.pending, actionID)
		a.pendingMu.Unlock()
	}()

	// Serialise the write.
	a.writeMu.Lock()
	conn := a.conn
	if conn == nil {
		a.writeMu.Unlock()
		return actionID, nil, fmt.Errorf("ami not connected")
	}

	var sb strings.Builder
	for k, v := range fields {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, writeErr := fmt.Fprint(conn, sb.String())
	conn.SetWriteDeadline(time.Time{})
	a.writeMu.Unlock()

	if writeErr != nil {
		return actionID, nil, fmt.Errorf("ami write: %w", writeErr)
	}

	select {
	case resp := <-ch:
		return actionID, resp, nil
	case <-time.After(10 * time.Second):
		return actionID, nil, fmt.Errorf("ami action timeout (action=%s)", fields["Action"])
	}
}

// readBlock reads one blank-line-terminated key:value block from the stream.
func (a *AMIClient) readBlock() (map[string]string, error) {
	a.writeMu.Lock()
	reader := a.reader
	a.writeMu.Unlock()

	if reader == nil {
		return nil, fmt.Errorf("no reader")
	}

	block := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if len(block) > 0 {
				return block, nil
			}
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// AMI "Command" responses emit one "Output" header per CLI output line.
		// Concatenate them so RunCommand() returns the full output.
		// For every other key, keep only the first occurrence.
		if key == "Output" {
			if prev, ok := block["Output"]; ok {
				block["Output"] = prev + "\n" + val
			} else {
				block["Output"] = val
			}
		} else if _, exists := block[key]; !exists {
			block[key] = val
		}
	}
}
