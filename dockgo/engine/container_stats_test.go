package engine

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
)

func statsFor(ids []string) map[string]*container.StatsResponse {
	out := make(map[string]*container.StatsResponse, len(ids))
	for _, id := range ids {
		out[id] = &container.StatsResponse{}
	}
	return out
}

// testBaselineGap keeps cold refreshes (baseline sample + real sample) fast.
const testBaselineGap = time.Millisecond

func TestContainerStatsCacheColdWaitReturnsFirstSample(t *testing.T) {
	c := containerStatsCache{baselineGap: testBaselineGap}
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
	c := containerStatsCache{baselineGap: testBaselineGap}
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
	// One refresh: a baseline sample plus the real sample.
	if n := calls.Load(); n != 2 {
		t.Fatalf("fetch calls = %d, want 2", n)
	}
}

func TestContainerStatsCacheFreshServesWithoutFetch(t *testing.T) {
	c := containerStatsCache{baselineGap: testBaselineGap}
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
	if n := calls.Load(); n != 2 {
		t.Fatalf("fetch calls = %d, want 2 (one cold refresh)", n)
	}
}

func TestContainerStatsCacheStaleRefreshesAndPrunes(t *testing.T) {
	c := containerStatsCache{baselineGap: testBaselineGap}
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

// cpuSample builds a stats sample with cumulative CPU counters at read.
func cpuSample(read time.Time, containerNs, systemNs uint64) *container.StatsResponse {
	sample := &container.StatsResponse{}
	sample.Read = read
	sample.CPUStats.CPUUsage.TotalUsage = containerNs
	sample.CPUStats.SystemUsage = systemNs
	sample.CPUStats.OnlineCPUs = 4
	return sample
}

func TestApplyContainerStatsNeedsBaseline(t *testing.T) {
	// A one-shot sample: lifetime counters and empty PreCPUStats.
	var row api.ContainerOverview
	applyContainerStats(&row, cpuSample(time.Now(), 28e9, 10e15))
	if row.CPUPercent != 0 {
		t.Fatalf("CPUPercent without baseline = %v, want 0", row.CPUPercent)
	}
}

func TestApplyContainerStatsUsesBaselineDelta(t *testing.T) {
	now := time.Now()
	baseline := cpuSample(now.Add(-5*time.Second), 10e9, 100e9)
	// 1s of container CPU over 4s of host CPU time on 4 CPUs is one full core.
	sample := cpuSample(now, 11e9, 104e9)
	applyCPUBaseline(sample, baseline)

	var row api.ContainerOverview
	applyContainerStats(&row, sample)
	if math.Abs(row.CPUPercent-100) > 1e-9 {
		t.Fatalf("CPUPercent = %v, want 100", row.CPUPercent)
	}
}

func TestApplyCPUBaselineRejectsUnusableBaselines(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name     string
		baseline *container.StatsResponse
	}{
		{"missing", nil},
		{"too old", cpuSample(now.Add(-2*containerStatsBaselineMaxAge), 10e9, 100e9)},
		{"not earlier", cpuSample(now, 10e9, 100e9)},
		{"container restarted", cpuSample(now.Add(-5*time.Second), 50e9, 100e9)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sample := cpuSample(now, 11e9, 104e9)
			// Docker one-shot PreCPUStats must never be trusted.
			sample.PreCPUStats.SystemUsage = 1
			applyCPUBaseline(sample, tc.baseline)
			if sample.PreCPUStats.SystemUsage != 0 {
				t.Fatalf("PreCPUStats = %+v, want empty", sample.PreCPUStats)
			}
		})
	}
}

func TestSampleContainerStatsTakesBaselineWhenCold(t *testing.T) {
	start := time.Now()
	var calls int
	fetch := func(_ context.Context, ids []string) map[string]*container.StatsResponse {
		calls++
		n := uint64(calls)
		return map[string]*container.StatsResponse{
			"a": cpuSample(start.Add(time.Duration(n)*time.Second), n*1e9, n*4e9),
		}
	}

	stats := sampleContainerStats(context.Background(), []string{"a"}, nil, testBaselineGap, fetch)
	if calls != 2 {
		t.Fatalf("fetch calls = %d, want 2 (baseline + sample)", calls)
	}
	if got := stats["a"].PreCPUStats.CPUUsage.TotalUsage; got != 1e9 {
		t.Fatalf("baseline usage = %d, want first sample's 1e9", got)
	}
}

func TestSampleContainerStatsReusesPreviousSample(t *testing.T) {
	now := time.Now()
	previous := map[string]*container.StatsResponse{"a": cpuSample(now.Add(-5*time.Second), 10e9, 100e9)}
	var calls int
	fetch := func(_ context.Context, ids []string) map[string]*container.StatsResponse {
		calls++
		return map[string]*container.StatsResponse{"a": cpuSample(now, 11e9, 104e9)}
	}

	stats := sampleContainerStats(context.Background(), []string{"a"}, previous, testBaselineGap, fetch)
	if calls != 1 {
		t.Fatalf("fetch calls = %d, want 1", calls)
	}
	if got := stats["a"].PreCPUStats.SystemUsage; got != 100e9 {
		t.Fatalf("baseline system usage = %d, want 100e9", got)
	}
}
