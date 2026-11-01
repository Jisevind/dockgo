package engine

import (
	"context"
	"sync"
	"time"
)

// volumeSizeTTL is how long scanned volume sizes are served before a background
// refresh is started. DiskUsage walks volume contents and can be very slow.
const volumeSizeTTL = time.Minute

// volumeSizeCache serves the last known volume sizes and refreshes them in the
// background, so listing volumes never waits on a disk-usage scan.
type volumeSizeCache struct {
	mu         sync.Mutex
	sizes      map[string]int64
	fetchedAt  time.Time
	refreshing bool
}

// get returns the cached sizes (nil before the first scan completes) and starts
// a single background refresh when the data is missing or stale.
func (c *volumeSizeCache) get(fetch func(context.Context) (map[string]int64, error), onError func(error)) map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.refreshing && (c.sizes == nil || time.Since(c.fetchedAt) > volumeSizeTTL) {
		c.refreshing = true
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			sizes, err := fetch(ctx)

			c.mu.Lock()
			defer c.mu.Unlock()
			c.refreshing = false
			if err != nil {
				if onError != nil {
					onError(err)
				}
				return
			}
			c.sizes = sizes
			c.fetchedAt = time.Now()
		}()
	}
	return c.sizes
}
