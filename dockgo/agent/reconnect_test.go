package agent

import (
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
