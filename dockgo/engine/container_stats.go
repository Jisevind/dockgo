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

// containerStatsCache serves the last stats samples and refreshes them in the
// background, so listing container overviews never waits on per-container
// stats calls, which can be slow on busy or older Docker daemons.
type containerStatsCache struct {
	mu         sync.Mutex
	stats      map[string]*container.StatsResponse
	fetchedAt  time.Time
	refreshing bool
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
		go func() {
			defer close(done)
			refreshCtx, cancel := context.WithTimeout(context.Background(), containerStatsRefreshTimeout)
			defer cancel()
			stats := fetch(refreshCtx, pending)
			if stats == nil {
				stats = map[string]*container.StatsResponse{}
			}

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
