package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
)

func statsFor(ids []string) map[string]*container.StatsResponse {
	out := make(map[string]*container.StatsResponse, len(ids))
	for _, id := range ids {
		out[id] = &container.StatsResponse{}
	}
	return out
}

func TestContainerStatsCacheColdWaitReturnsFirstSample(t *testing.T) {
	var c containerStatsCache
	fetch := func(_ context.Context, ids []string) map[string]*container.StatsResponse {
		return statsFor(ids)
	}

	got := c.get(context.Background(), []string{"a", "b"}, fetch, time.Second)
	if got["a"] == nil || got["b"] == nil {
		t.Fatalf("cold get = %v, want samples for a and b", got)
	}
}

func TestContainerStatsCacheColdWaitIsBounded(t *testing.T) {
	var c containerStatsCache
	release := make(chan struct{})
	defer close(release)
	fetch := func(_ context.Context, ids []string) map[string]*container.StatsResponse {
		<-release
		return statsFor(ids)
	}

	start := time.Now()
	got := c.get(context.Background(), []string{"a"}, fetch, 50*time.Millisecond)
	if got != nil {
		t.Fatalf("get with slow refresh = %v, want nil", got)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cold wait took %v, want about 50ms", elapsed)
	}
}

func TestContainerStatsCacheColdWaitHonorsContext(t *testing.T) {
	var c containerStatsCache
	release := make(chan struct{})
	defer close(release)
	fetch := func(_ context.Context, ids []string) map[string]*container.StatsResponse {
		<-release
		return statsFor(ids)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	c.get(ctx, []string{"a"}, fetch, 5*time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("get ignored cancelled context, took %v", elapsed)
	}
}

func TestContainerStatsCacheSingleRefreshUnderConcurrency(t *testing.T) {
	var c containerStatsCache
	var calls atomic.Int32
	release := make(chan struct{})
	fetch := func(_ context.Context, ids []string) map[string]*container.StatsResponse {
		calls.Add(1)
		<-release
		return statsFor(ids)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.get(context.Background(), []string{"a"}, fetch, 20*time.Millisecond)
		}()
	}
	wg.Wait()
	close(release)

	waitForStats(t, &c, "a")
	if n := calls.Load(); n != 1 {
		t.Fatalf("fetch calls = %d, want 1", n)
	}
}

func TestContainerStatsCacheFreshServesWithoutFetch(t *testing.T) {
	var c containerStatsCache
	var calls atomic.Int32
	fetch := func(_ context.Context, ids []string) map[string]*container.StatsResponse {
		calls.Add(1)
		return statsFor(ids)
	}

	c.get(context.Background(), []string{"a"}, fetch, time.Second)
	for i := 0; i < 5; i++ {
		if got := c.get(context.Background(), []string{"a"}, fetch, time.Second); got["a"] == nil {
			t.Fatalf("fresh get missing sample")
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("fetch calls = %d, want 1", n)
	}
}

func TestContainerStatsCacheStaleRefreshesAndPrunes(t *testing.T) {
	var c containerStatsCache
	fetch := func(_ context.Context, ids []string) map[string]*container.StatsResponse {
		return statsFor(ids)
	}

	c.get(context.Background(), []string{"old", "kept"}, fetch, time.Second)

	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * containerStatsTTL)
	c.mu.Unlock()

	// A stale get serves the previous samples immediately.
	if got := c.get(context.Background(), []string{"kept", "new"}, fetch, time.Second); got["old"] == nil {
		t.Fatalf("stale get = %v, want previous samples", got)
	}

	got := waitForStats(t, &c, "new")
	if got["old"] != nil {
		t.Fatalf("removed container still cached: %v", got)
	}
	if got["kept"] == nil {
		t.Fatalf("running container lost its sample: %v", got)
	}
}

func waitForStats(t *testing.T, c *containerStatsCache, id string) map[string]*container.StatsResponse {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		stats, refreshing := c.stats, c.refreshing
		c.mu.Unlock()
		if !refreshing && stats[id] != nil {
			return stats
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("stats for %q never populated", id)
	return nil
}
