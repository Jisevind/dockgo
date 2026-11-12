package engine

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
)

// containerStatsTTL is how long stats samples are served before a background
// refresh is started. It stays below the UI's 10s poll so every poll sees a
// sample at most one refresh old.
const containerStatsTTL = 5 * time.Second

// containerStatsColdWait bounds how long a request waits for the very first
// stats refresh before returning rows without metrics.
const containerStatsColdWait = 2 * time.Second

// containerStatsRefreshTimeout bounds one full background refresh.
const containerStatsRefreshTimeout = time.Minute

// containerStatsBaselineMaxAge is the oldest previous sample still used as the
// CPU baseline. Older baselines would report an average over that whole gap
// rather than current usage, so a fresh baseline is sampled instead.
const containerStatsBaselineMaxAge = 30 * time.Second

// containerStatsBaselineGap is the wait between a fresh baseline sample and
// the sample it is compared against.
const containerStatsBaselineGap = time.Second

// containerStatsCache serves the last stats samples and refreshes them in the
// background, so listing container overviews never waits on per-container
// stats calls, which can be slow on busy or older Docker daemons.
type containerStatsCache struct {
	mu         sync.Mutex
	stats      map[string]*container.StatsResponse
	fetchedAt  time.Time
	refreshing bool
	// baselineGap overrides containerStatsBaselineGap when non-zero (tests).
	baselineGap time.Duration
	// done is closed when the in-flight refresh finishes.
	done chan struct{}
}

type containerStatsFetcher func(ctx context.Context, ids []string) map[string]*container.StatsResponse

// get returns the cached samples keyed by container ID and starts a single
// background refresh for ids when the data is missing or stale. Before the
// first refresh has ever completed it waits up to coldWait (or until ctx ends)
// so the first page load still has metrics on a responsive daemon.
//
// The returned map is never mutated after publication and is safe to read.
func (c *containerStatsCache) get(ctx context.Context, ids []string, fetch containerStatsFetcher, coldWait time.Duration) map[string]*container.StatsResponse {
	c.mu.Lock()
	if !c.refreshing && (c.stats == nil || time.Since(c.fetchedAt) > containerStatsTTL) {
		c.refreshing = true
		c.done = make(chan struct{})
		done := c.done
		pending := append([]string(nil), ids...)
		previous := c.stats
		gap := c.baselineGap
		if gap == 0 {
			gap = containerStatsBaselineGap
		}
		if time.Since(c.fetchedAt) > containerStatsBaselineMaxAge {
			previous = nil
		}
		go func() {
			defer close(done)
			refreshCtx, cancel := context.WithTimeout(context.Background(), containerStatsRefreshTimeout)
			defer cancel()
			stats := sampleContainerStats(refreshCtx, pending, previous, gap, fetch)

			c.mu.Lock()
			defer c.mu.Unlock()
			c.refreshing = false
			// Replacing the map drops samples for containers that are gone.
			c.stats = stats
			c.fetchedAt = time.Now()
		}()
	}
	stats, done := c.stats, c.done
	c.mu.Unlock()

	if stats != nil || done == nil || coldWait <= 0 {
		return stats
	}

	timer := time.NewTimer(coldWait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	case <-ctx.Done():
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// sampleContainerStats fetches stats for ids and fills each sample's CPU
// baseline (PreCPUStats). One-shot stats leave PreCPUStats empty, which would
// make CPU percent an average since the container started. The previous
// cached sample is the baseline; without a recent one, a baseline is sampled
// first and the real sample is taken gap later.
func sampleContainerStats(ctx context.Context, ids []string, previous map[string]*container.StatsResponse, gap time.Duration, fetch containerStatsFetcher) map[string]*container.StatsResponse {
	if previous == nil {
		previous = fetch(ctx, ids)
		timer := time.NewTimer(gap)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
	}

	stats := fetch(ctx, ids)
	if stats == nil {
		return map[string]*container.StatsResponse{}
	}
	for id, sample := range stats {
		applyCPUBaseline(sample, previous[id])
	}
	return stats
}

// applyCPUBaseline sets sample's PreCPUStats from an earlier sample of the
// same container when that sample is a usable baseline. A container that
// restarted in between (usage went backwards) or a baseline that is too old
// is ignored, leaving CPU percent at zero for this sample.
func applyCPUBaseline(sample, baseline *container.StatsResponse) {
	if sample == nil {
		return
	}
	// Never trust Docker's own one-shot PreCPUStats: they are empty.
	sample.PreCPUStats = container.CPUStats{}
	if baseline == nil {
		return
	}
	if !baseline.Read.Before(sample.Read) || sample.Read.Sub(baseline.Read) > containerStatsBaselineMaxAge {
		return
	}
	if baseline.CPUStats.CPUUsage.TotalUsage > sample.CPUStats.CPUUsage.TotalUsage ||
		baseline.CPUStats.SystemUsage > sample.CPUStats.SystemUsage {
		return
	}
	sample.PreCPUStats = baseline.CPUStats
	sample.PreRead = baseline.Read
}

// fetchContainerStats takes one-shot stats samples for the given containers
// with bounded concurrency. Containers whose sample fails are omitted.
func (d *DiscoveryEngine) fetchContainerStats(ctx context.Context, ids []string) map[string]*container.StatsResponse {
	result := make(map[string]*container.StatsResponse, len(ids))
	var mu sync.Mutex
	sem := make(chan struct{}, containerOverviewConcurrency)
	var wg sync.WaitGroup

	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			statsCtx, cancel := context.WithTimeout(ctx, containerStatsTimeout)
			defer cancel()
			reader, err := d.Client.ContainerStatsOneShot(statsCtx, id)
			if err != nil {
				return
			}
			var decoded container.StatsResponse
			decodeErr := json.NewDecoder(reader.Body).Decode(&decoded)
			_ = reader.Body.Close()
			if decodeErr != nil {
				return
			}

			mu.Lock()
			result[id] = &decoded
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return result
}
