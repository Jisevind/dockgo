package agent

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestReconnectDelayIsJitteredWithinWindow(t *testing.T) {
	const backoff = 30 * time.Second

	seen := make(map[time.Duration]bool)
	for i := 0; i < 200; i++ {
		delay := reconnectDelay(backoff)
		if delay < time.Second || delay > backoff {
			t.Fatalf("reconnectDelay(%s) = %s, want within [1s, %s]", backoff, delay, backoff)
		}
		seen[delay] = true
	}

	// The point of the jitter is that agents which dropped together do not
	// retry together, so the delay must not be constant.
	if len(seen) < 2 {
		t.Fatalf("reconnectDelay(%s) returned %d distinct values, want jitter", backoff, len(seen))
	}
}

func TestReconnectDelayLeavesShortBackoffAlone(t *testing.T) {
	const backoff = 500 * time.Millisecond

	if got := reconnectDelay(backoff); got != backoff {
		t.Fatalf("reconnectDelay(%s) = %s, want %s", backoff, got, backoff)
	}
}

func TestRetryDelaySkipsWaitForRejectedToken(t *testing.T) {
	// A rejected token needs no wait: the agent already knows to use its key, so
	// burning a backoff interval on every expiry is pointless.
	if got := retryDelay(60*time.Second, errTokenRejected); got != 0 {
		t.Fatalf("retryDelay(rejected token) = %s, want 0", got)
	}

	// The rejection travels back through the connection loop, so a wrapped
	// error must still be recognised.
	wrapped := fmt.Errorf("handshake failed: %w", errTokenRejected)
	if got := retryDelay(60*time.Second, wrapped); got != 0 {
		t.Fatalf("retryDelay(wrapped rejected token) = %s, want 0", got)
	}
}

func TestRetryDelayBacksOffForRealFailures(t *testing.T) {
	const backoff = 30 * time.Second

	// Every other failure must still be spread across the backoff window, so a
	// server that is down is not hammered.
	for i := 0; i < 50; i++ {
		got := retryDelay(backoff, errors.New("dial refused"))
		if got < time.Second || got > backoff {
			t.Fatalf("retryDelay(other error) = %s, want within [1s, %s]", got, backoff)
		}
	}
}

func TestBackoffAfterSessionResetsOnlyAfterStableSession(t *testing.T) {
	a := &Agent{cfg: Config{
		ReconnectMin:         5 * time.Second,
		ReconnectStableAfter: 30 * time.Second,
	}}

	// A session that stayed up long enough proves the server is healthy.
	if got := a.backoffAfterSession(60*time.Second, 45*time.Second); got != 5*time.Second {
		t.Fatalf("backoffAfterSession(60s, 45s) = %s, want reset to 5s", got)
	}

	// A connection that dropped immediately must keep the accumulated backoff,
	// otherwise a flapping server becomes a hot reconnect loop.
	if got := a.backoffAfterSession(60*time.Second, time.Second); got != 60*time.Second {
		t.Fatalf("backoffAfterSession(60s, 1s) = %s, want 60s retained", got)
	}

	// Reaching the threshold exactly counts as stable.
	if got := a.backoffAfterSession(60*time.Second, 30*time.Second); got != 5*time.Second {
		t.Fatalf("backoffAfterSession(60s, 30s) = %s, want reset to 5s", got)
	}
}
