package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestVolumeSizeCacheScansOnce(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	fetch := func(context.Context) (map[string]int64, error) {
		calls.Add(1)
		<-release
		return map[string]int64{"v": 5}, nil
	}

	var c volumeSizeCache
	if got := c.get(fetch, nil); got != nil {
		t.Fatalf("first get = %v, want nil", got)
	}
	c.get(fetch, nil)
	c.get(fetch, nil)
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.get(fetch, nil); got["v"] == 5 {
			if n := calls.Load(); n != 1 {
				t.Fatalf("fetch calls = %d, want 1", n)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("sizes never populated")
}
