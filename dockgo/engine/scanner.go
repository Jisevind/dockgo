package engine

import (
	"context"
	"dockgo/api"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

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

			upd := api.ContainerUpdate{
				ID:     id,
				Name:   name,
				Status: "checked",
				Labels: labels,
			}

			// Get local details first to resolve true image name (in case List returned SHA)
			resolvedName, _, repoDigests, osName, arch, err := discovery.GetContainerImageDetails(ctx, id)
			if err != nil {
				upd.Error = fmt.Sprintf("Inspect error: %v", err)
				upd.Status = "error"
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
				if osName != "" && arch != "" {
					platform = &v1.Platform{OS: osName, Architecture: arch}
				}
				remoteDigest, err := registry.GetRemoteDigest(upd.Image, platform)
				if err != nil {
					upd.Error = fmt.Sprintf("Registry error: %v", err)
					upd.Status = "error"
				} else {
					upd.RemoteDigest = remoteDigest

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
					}
				}
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
