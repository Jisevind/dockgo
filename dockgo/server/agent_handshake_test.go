package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
