package engine

import (
	"context"
	"dockgo/api"
	"dockgo/logger"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Scan iterates over containers, checks for updates, and emits progress events.
// It returns a list of ContainerUpdates for those that have updates available (or all if requested? No, the original logic collected all).
// Actually, main.go collected all updates in a list.
// Scan iterates over containers, checks for updates, and emits progress events.
// It returns a list of ContainerUpdates for those that have updates available (or all if requested? No, the original logic collected all).
// Actually, main.go collected all updates in a list.
func Scan(ctx context.Context, discovery *DiscoveryEngine, registry *RegistryClient, filter string, onProgress func(api.ContainerUpdate, int, int)) ([]api.ContainerUpdate, error) {
	allContainers, err := discovery.ListContainers(ctx)
	if err != nil {
		return nil, err
	}

	// Filter and count

	totalToCheck := 0
	for _, c := range allContainers {
		cName := c.Names[0]
		if len(cName) > 0 && cName[0] == '/' {
			cName = cName[1:]
		}
		if filter != "" && filter != "all" && cName != filter {
			continue
		}
		totalToCheck++
	}

	var updates []api.ContainerUpdate
	var wg sync.WaitGroup
	var mu sync.Mutex
	var processedCount int32 = 0

	// Limit concurrency to avoid overwhelming registry or network
	sem := make(chan struct{}, 5)

	for _, c := range allContainers {
		// Clean name
		cName := c.Names[0]
		if len(cName) > 0 && cName[0] == '/' {
			cName = cName[1:]
		}

		// Filter
		if filter != "" && filter != "all" && cName != filter {
			continue
		}

		wg.Add(1)
		go func(name, image, id, state string, labels map[string]string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logger.Error("🔥 PANIC in scanner goroutine for %s: %v", name, r)
				}
			}()

			// Check context before starting work
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}: // Acquire semaphore
				// Continue
			}
			defer func() { <-sem }() // Release semaphore

			// Re-check context after acquiring semaphore
			if ctx.Err() != nil {
				return
			}

			upd := api.ContainerUpdate{
				ID:     id,
				Name:   name,
				Status: "checked",
				Labels: labels,
			}

			// Get local details first to resolve true image name (in case List returned SHA)
			resolvedName, _, repoDigests, _, _, err := discovery.GetContainerImageDetails(ctx, id)
			logger.Debug("[Scan] %s: Image=%s, Resolved=%s, RepoDigests=%d", name, image, resolvedName, len(repoDigests))

			// Check context again
			if ctx.Err() != nil {
				return
			}

			if err != nil {
				upd.Error = fmt.Sprintf("Inspect error: %v", err)
				upd.Status = "error"
				logger.Debug("[Scan] %s: Inspect error: %v", name, err)
			} else {
				if resolvedName != "" {
					upd.Image = resolvedName
				} else {
					upd.Image = image // Fallback
				}

				if len(repoDigests) > 0 {
					upd.LocalDigest = repoDigests[0]
				}

				// Now check registry with the resolved name
				var platform *v1.Platform

				// Check context before remote call
				if ctx.Err() != nil {
					return
				}

				// Fix for localhost registries when running in container
				imageToCheck := upd.Image
				if strings.HasPrefix(imageToCheck, "localhost:") || strings.HasPrefix(imageToCheck, "127.0.0.1:") {
					logger.Debug("Rewriting %s to use host.docker.internal", imageToCheck)
					imageToCheck = strings.Replace(imageToCheck, "localhost:", "host.docker.internal:", 1)
					imageToCheck = strings.Replace(imageToCheck, "127.0.0.1:", "host.docker.internal:", 1)
				}

				remoteDigest, err := registry.GetRemoteDigest(imageToCheck, platform)
				if err != nil {
					// Check if error is due to context cancellation
					if ctx.Err() != nil {
						return
					}
					upd.Error = fmt.Sprintf("Registry error: %v", err)
					upd.Status = "error"
					logger.Debug("[Scan] %s: Registry error: %v", name, err)
				} else {
					upd.RemoteDigest = remoteDigest
					logger.Debug("[Scan] %s: RemoteDigest=%s", name, remoteDigest)

					// Check if remote digest is in repoDigests
					found := false
					for _, rd := range repoDigests {
						parts := strings.Split(rd, "@")
						if len(parts) == 2 && parts[1] == remoteDigest {
							found = true
							break
						}
					}

					if !found {
						upd.UpdateAvailable = true
						logger.Debug("[Scan] %s: UpdateAvailable=TRUE (Local!=Remote)", name)
					} else {
						logger.Debug("[Scan] %s: Up to date.", name)
					}
				}
			}

			// Final context check before acquiring lock
			if ctx.Err() != nil {
				return
			}

			mu.Lock()
			updates = append(updates, upd)
			newCount := atomic.AddInt32(&processedCount, 1)
			mu.Unlock()

			if onProgress != nil {
				onProgress(upd, int(newCount), totalToCheck)
			}
		}(cName, c.Image, c.ID, c.State, c.Labels)
	}
	wg.Wait()

	return updates, nil
}
