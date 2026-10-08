package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dockgo/agent"

	"github.com/coder/websocket"
)

func TestAcquireAgentHandshakeSlotRejectsWhenBusy(t *testing.T) {
	srv := &Server{
		agentHandshakeSlots: make(chan struct{}, 1),
		agentHandshakeWait:  10 * time.Millisecond,
	}

	if !srv.acquireAgentHandshakeSlot(context.Background(), httptest.NewRecorder()) {
		t.Fatal("first acquireAgentHandshakeSlot() = false, want true")
	}
	defer srv.releaseAgentHandshakeSlot()

	rr := httptest.NewRecorder()
	if srv.acquireAgentHandshakeSlot(context.Background(), rr) {
		t.Fatal("second acquireAgentHandshakeSlot() = true, want false while the only slot is taken")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header missing on 503 response")
	}
}

func TestAcquireAgentHandshakeSlotReusesReleasedSlot(t *testing.T) {
	srv := &Server{
		agentHandshakeSlots: make(chan struct{}, 1),
		agentHandshakeWait:  10 * time.Millisecond,
	}

	if !srv.acquireAgentHandshakeSlot(context.Background(), httptest.NewRecorder()) {
		t.Fatal("first acquireAgentHandshakeSlot() = false, want true")
	}
	srv.releaseAgentHandshakeSlot()

	if !srv.acquireAgentHandshakeSlot(context.Background(), httptest.NewRecorder()) {
		t.Fatal("acquireAgentHandshakeSlot() = false after the slot was released")
	}
	srv.releaseAgentHandshakeSlot()
}

func TestAcquireAgentHandshakeSlotAbandonsOnCancelledRequest(t *testing.T) {
	srv := &Server{
		agentHandshakeSlots: make(chan struct{}, 1),
		agentHandshakeWait:  time.Minute,
	}

	if !srv.acquireAgentHandshakeSlot(context.Background(), httptest.NewRecorder()) {
		t.Fatal("first acquireAgentHandshakeSlot() = false, want true")
	}
	defer srv.releaseAgentHandshakeSlot()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if srv.acquireAgentHandshakeSlot(ctx, httptest.NewRecorder()) {
		t.Fatal("acquireAgentHandshakeSlot() = true, want false for a cancelled request")
	}
}

// TestAgentHandshakeCapRefusesExcessConnections exercises the cap through the
// real WebSocket path rather than by poking the slot channel directly.
func TestAgentHandshakeCapRefusesExcessConnections(t *testing.T) {
	srv := newAgentTestServer(t)
	srv.agentHandshakeSlots = make(chan struct{}, 1)
	srv.agentHandshakeWait = 50 * time.Millisecond

	wsURL := startAgentTestServer(t, srv)

	// The first connection takes the only slot and then stays silent, so its
	// handshake remains in flight and the slot stays held.
	holding := dialAgentWS(t, wsURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, resp, err := websocket.Dial(ctx, wsURL, nil)
	if err == nil {
		t.Fatal("second dial succeeded, want a 503 while the only handshake slot is held")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second dial status = %v, want %d", resp, http.StatusServiceUnavailable)
	}

	// A refusal must not consume a slot: the holding connection can still finish
	// its handshake once the server is no longer busy.
	rec, key, err := srv.AgentStore.Create("cap-host")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	reply := registerAgent(t, holding, agent.RegisterRequest{
		Key:      key,
		AgentID:  rec.ID,
		Hostname: "cap-host",
		Version:  "test",
		Name:     "cap-host",
	})
	if reply.Type != agent.TypeWelcome {
		t.Fatalf("register after refusal = %q, want %q", reply.Type, agent.TypeWelcome)
	}
}
