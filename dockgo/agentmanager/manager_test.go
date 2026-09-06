package agentmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"dockgo/agent"
	"dockgo/agentstore"

	"github.com/google/uuid"
)

// fakeConn is an in-memory Conn for testing.
type fakeConn struct {
	mu       sync.Mutex
	written  []agent.Envelope
	readCh   chan agent.Envelope
	closeCh  chan struct{}
	closeErr error
	closed   bool
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		written: make([]agent.Envelope, 0),
		readCh:  make(chan agent.Envelope, 64),
		closeCh: make(chan struct{}),
	}
}

func (f *fakeConn) Read(ctx context.Context) (agent.Envelope, error) {
	select {
	case env := <-f.readCh:
		return env, nil
	case <-ctx.Done():
		return agent.Envelope{}, ctx.Err()
	case <-f.closeCh:
		return agent.Envelope{}, errors.New("connection closed")
	}
}

func (f *fakeConn) Write(ctx context.Context, env agent.Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("connection closed")
	}
	f.written = append(f.written, env)
	return nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.closeCh)
	}
	return f.closeErr
}

func (f *fakeConn) writtenEnvelopes() []agent.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]agent.Envelope(nil), f.written...)
}

// deliver injects a message as if it arrived from the agent and routes it
// through the channel's read-loop dispatch.
func (f *fakeConn) deliver(env agent.Envelope, ac *AgentConn) {
	f.readCh <- env
	ac.RouteMessage(env)
}

func newTestManager(t *testing.T) (*Manager, *agentstore.Store) {
	t.Helper()
	store, err := agentstore.NewStore(t.TempDir() + "/agents.json")
	if err != nil {
		t.Fatalf("agentstore.NewStore() error = %v", err)
	}
	m, err := New(Config{
		Store:         store,
		JWTSecret:     "test-secret-that-is-long-enough",
		JWTTTL:        time.Hour,
		MaxConcurrent: 2,
	})
	if err != nil {
		t.Fatalf("agentmanager.New() error = %v", err)
	}
	return m, store
}

func TestJWTRoundTrip(t *testing.T) {
	m, _ := newTestManager(t)

	token, err := m.IssueJWT("agent-123")
	if err != nil {
		t.Fatalf("IssueJWT() error = %v", err)
	}

	agentID, err := m.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT() error = %v", err)
	}
	if agentID != "agent-123" {
		t.Fatalf("VerifyJWT() = %q, want agent-123", agentID)
	}

	if _, err := m.VerifyJWT("garbage-token"); err == nil {
		t.Fatal("VerifyJWT(garbage) = nil error, want failure")
	}

	// A token signed with a different secret must be rejected.
	other, err := New(Config{Store: m.Store(), JWTSecret: "different-secret"})
	if err != nil {
		t.Fatalf("New(other) error = %v", err)
	}
	if _, err := other.VerifyJWT(token); err == nil {
		t.Fatal("VerifyJWT() with wrong secret succeeded, want failure")
	}
}

func TestJWTTamperedClaimsRejected(t *testing.T) {
	m, _ := newTestManager(t)

	token, err := m.IssueJWT("agent-123")
	if err != nil {
		t.Fatalf("IssueJWT() error = %v", err)
	}

	// Flip a character in the payload segment to simulate tampering.
	parts := splitToken(token)
	payload := parts[1]
	flipped := []byte(payload)
	if len(flipped) > 0 {
		if flipped[0] == 'a' {
			flipped[0] = 'b'
		} else {
			flipped[0] = 'a'
		}
	}
	tampered := parts[0] + "." + string(flipped) + "." + parts[2]
	if _, err := m.VerifyJWT(tampered); err == nil {
		t.Fatal("VerifyJWT(tampered) succeeded, want failure")
	}
}

func TestRegisterAndDispatchCorrelation(t *testing.T) {
	m, _ := newTestManager(t)
	conn := newFakeConn()

	ac, err := m.Register("agent-1", "host-one", conn)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !m.IsOnline("agent-1") {
		t.Fatal("IsOnline(agent-1) = false after register")
	}

	progress := make(chan agent.Envelope, 8)
	ctx := context.Background()
	response, err := m.Dispatch(ctx, "agent-1", "req-1", agent.TypeContainersList, nil, progress)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	// Verify the request was written to the socket.
	written := conn.writtenEnvelopes()
	if len(written) != 1 {
		t.Fatalf("written envelope count = %d, want 1", len(written))
	}
	if written[0].Type != agent.TypeContainersList || written[0].RequestID != "req-1" {
		t.Fatalf("written envelope = %+v, want containers_list/req-1", written[0])
	}

	// Agent emits progress then a terminal result.
	progressEnv := agent.Envelope{
		Type:      agent.TypeProgress,
		RequestID: "req-1",
		Data:      mustJSON(agent.ProgressData{ProgressType: agent.ProgressScan}),
	}
	conn.deliver(progressEnv, ac)

	resultEnv := agent.Envelope{
		Type:      agent.TypeResult,
		RequestID: "req-1",
		Data:      mustJSON(agent.ResultData{Value: json.RawMessage(`[{"id":"c1"}]`)}),
	}
	conn.deliver(resultEnv, ac)

	select {
	case p := <-progress:
		if p.RequestID != "req-1" {
			t.Fatalf("progress request_id = %q, want req-1", p.RequestID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("progress event not routed")
	}

	select {
	case r := <-response:
		if r.Type != agent.TypeResult {
			t.Fatalf("response type = %q, want result", r.Type)
		}
		var rd agent.ResultData
		if err := r.Decode(&rd); err != nil {
			t.Fatalf("result decode error = %v", err)
		}
		if string(rd.Value) != `[{"id":"c1"}]` {
			t.Fatalf("result value = %s", rd.Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal result not correlated")
	}

	_ = ac
}

func TestDispatchOfflineAgent(t *testing.T) {
	m, _ := newTestManager(t)

	_, err := m.Dispatch(context.Background(), "nope", "req-1", agent.TypeContainersList, nil, nil)
	if err == nil {
		t.Fatal("Dispatch() to offline agent = nil error, want error")
	}
}

func TestConcurrencyCapRejectsOverLimit(t *testing.T) {
	m, _ := newTestManager(t)
	conn := newFakeConn()

	if _, err := m.Register("agent-2", "host-two", conn); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	ctx := context.Background()
	// MaxConcurrent is 2; the first two dispatches succeed.
	if _, err := m.Dispatch(ctx, "agent-2", "req-1", agent.TypeScan, nil, nil); err != nil {
		t.Fatalf("Dispatch(req-1) error = %v", err)
	}
	if _, err := m.Dispatch(ctx, "agent-2", "req-2", agent.TypeScan, nil, nil); err != nil {
		t.Fatalf("Dispatch(req-2) error = %v", err)
	}

	// The third must be rejected before anything hits the wire.
	_, err := m.Dispatch(ctx, "agent-2", "req-3", agent.TypeScan, nil, nil)
	if err == nil {
		t.Fatal("Dispatch(req-3) succeeded, want concurrency cap rejection")
	}

	// Completing one op frees a slot.
	ac := m.AgentConn("agent-2")
	conn.deliver(agent.Envelope{Type: agent.TypeResult, RequestID: "req-1", Data: mustJSON(agent.ResultData{})}, ac)
	time.Sleep(50 * time.Millisecond)

	if _, err := m.Dispatch(ctx, "agent-2", "req-3", agent.TypeScan, nil, nil); err != nil {
		t.Fatalf("Dispatch(req-3) after completion error = %v", err)
	}
}

func TestUnregisterFailsInflightOps(t *testing.T) {
	m, _ := newTestManager(t)
	conn := newFakeConn()

	if _, err := m.Register("agent-3", "host-three", conn); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	response, err := m.Dispatch(context.Background(), "agent-3", "req-1", agent.TypeScan, nil, nil)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	m.Unregister("agent-3", conn)

	select {
	case r := <-response:
		var rd agent.ResultData
		_ = r.Decode(&rd)
		if rd.Error == "" {
			t.Fatal("inflight op did not receive an error on disconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inflight op never completed after unregister")
	}
}

func TestCancelFreesInflightOp(t *testing.T) {
	m, _ := newTestManager(t)
	conn := newFakeConn()

	ac, err := m.Register("agent-7", "host-seven", conn)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	response, err := m.Dispatch(context.Background(), "agent-7", "req-cancel", agent.TypeScan, nil, nil)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	ac.Cancel("req-cancel")

	select {
	case r := <-response:
		var rd agent.ResultData
		_ = r.Decode(&rd)
		if rd.Error == "" {
			t.Fatal("cancelled op did not receive a terminal error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled op never completed")
	}

	// The concurrency slot must be freed: a second dispatch should succeed.
	if _, err := m.Dispatch(context.Background(), "agent-7", "req-after", agent.TypeScan, nil, nil); err != nil {
		t.Fatalf("Dispatch after cancel should succeed, got: %v", err)
	}
}

func TestDuplicateRegisterReplacesChannel(t *testing.T) {
	m, _ := newTestManager(t)
	conn1 := newFakeConn()
	conn2 := newFakeConn()

	if _, err := m.Register("agent-4", "host-four", conn1); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if _, err := m.Register("agent-4", "host-four", conn2); err != nil {
		t.Fatalf("Register(second) error = %v", err)
	}

	// Old channel must have been closed.
	select {
	case <-conn1.closeCh:
	case <-time.After(2 * time.Second):
		t.Fatal("previous channel was not closed on re-register")
	}

	// Dispatch should now reach conn2.
	ac := m.AgentConn("agent-4")
	if ac == nil || ac.conn != conn2 {
		t.Fatal("AgentConn() does not reference the newest channel")
	}
}

func TestStatusChangeCallback(t *testing.T) {
	m, _ := newTestManager(t)
	conn := newFakeConn()

	called := make(chan struct{}, 4)
	m.onStatusChange = func() {
		called <- struct{}{}
	}

	if _, err := m.Register("agent-5", "host-five", conn); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	select {
	case <-called:
	default:
		t.Fatal("onStatusChange not invoked on register")
	}

	m.Unregister("agent-5", conn)
	select {
	case <-called:
	default:
		t.Fatal("onStatusChange not invoked on unregister")
	}
}

func splitToken(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

func TestDispatchResultWithError(t *testing.T) {
	m, _ := newTestManager(t)
	conn := newFakeConn()

	if _, err := m.Register("agent-6", "host-six", conn); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	response, err := m.Dispatch(context.Background(), "agent-6", "req-1", agent.TypeScan, nil, nil)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	ac := m.AgentConn("agent-6")
	conn.deliver(agent.Envelope{
		Type:      agent.TypeResult,
		RequestID: "req-1",
		Data:      mustJSON(agent.ResultData{Error: "operation exploded"}),
	}, ac)

	select {
	case r := <-response:
		var rd agent.ResultData
		if err := r.Decode(&rd); err != nil {
			t.Fatalf("decode error = %v", err)
		}
		if rd.Error != "operation exploded" {
			t.Fatalf("result error = %q, want operation exploded", rd.Error)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal result not received")
	}
}

func TestAgentConnSendAndSendRaw(t *testing.T) {
	m, _ := newTestManager(t)
	conn := newFakeConn()

	ac, err := m.Register("agent-7", "host-seven", conn)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	ctx := context.Background()
	env, err := agent.NewEnvelope(agent.TypeHeartbeat, "", nil)
	if err != nil {
		t.Fatalf("NewEnvelope() error = %v", err)
	}
	if err := ac.SendRaw(ctx, env); err != nil {
		t.Fatalf("SendRaw() error = %v", err)
	}

	written := conn.writtenEnvelopes()
	if len(written) != 1 || written[0].Type != agent.TypeHeartbeat {
		t.Fatalf("SendRaw() written = %+v, want heartbeat", written)
	}

	// A second send from a different goroutine must be serialized safely.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			e, _ := agent.NewEnvelope(agent.TypeHeartbeat, fmt.Sprintf("hb-%d", n), nil)
			_ = ac.SendRaw(ctx, e)
		}(i)
	}
	wg.Wait()
	if got := len(conn.writtenEnvelopes()); got != 21 {
		t.Fatalf("written count after concurrent sends = %d, want 21", got)
	}
}

var _ = uuid.NewString
