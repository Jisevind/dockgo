package engine

import (
	"context"
	"dockgo/api"
	"dockgo/logger"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var scannerLog = logger.WithSubsystem("scanner")

// containerScanTimeout is the maximum time allowed to check a single container.
// It bounds the blast radius of slow or unreachable registries so that one
// container cannot stall the entire scan indefinitely.
const (
	containerScanTimeout = 10 * time.Second
)

// isContainerGone returns true if the error indicates the container no longer exists
// (e.g., was renamed or removed during a concurrent RecreateContainer).
func isContainerGone(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such container") ||
		strings.Contains(msg, "not found")
}

// emitSkipped appends a skipped update to the shared slice and fires onProgress,
// ensuring that processedCount always reaches totalToCheck even when a goroutine
// exits early (e.g., due to context cancellation or a per-container timeout).
func emitSkipped(name, id string, labels map[string]string, updates *[]api.ContainerUpdate, mu *sync.Mutex, processedCount *int32, totalToCheck int, onProgress func(api.ContainerUpdate, int, int)) {
	upd := api.ContainerUpdate{
		ID:     id,
		Name:   name,
		Status: "skipped",
		Labels: labels,
	}
	mu.Lock()
	*updates = append(*updates, upd)
	newCount := atomic.AddInt32(processedCount, 1)
	mu.Unlock()
	if onProgress != nil {
		onProgress(upd, int(newCount), totalToCheck)
	}
}

// Scan checks containers and reports available image updates.
func Scan(ctx context.Context, discovery *DiscoveryEngine, registry *RegistryClient, filter string, force bool, onProgress func(api.ContainerUpdate, int, int)) ([]api.ContainerUpdate, error) {
	allContainers, err := discovery.ListContainers(ctx)
	if err != nil {
		return nil, err
	}

	totalToCheck := 0
	for _, c := range allContainers {
		if len(c.Names) == 0 {
			continue
		}
		cName := c.Names[0]
		if len(cName) > 0 && cName[0] == '/' {
			cName = cName[1:]
		}
		if filter != "" && filter != "all" && cName != filter {
			continue
		}
		if strings.Contains(cName, "_old_") {
			continue
		}
		totalToCheck++
	}

	var updates []api.ContainerUpdate
	var wg sync.WaitGroup
	var mu sync.Mutex
	var processedCount int32 = 0

	sem := make(chan struct{}, 5)

	for _, c := range allContainers {
		if len(c.Names) == 0 {
			continue
		}

		cName := c.Names[0]
		if len(cName) > 0 && cName[0] == '/' {
			cName = cName[1:]
		}

		if filter != "" && filter != "all" && cName != filter {
			continue
		}
		if strings.Contains(cName, "_old_") {
			continue
		}

		wg.Add(1)
		go func(name, image, id, state string, labels map[string]string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					scannerLog.ErrorContext(ctx, "scanner goroutine panic",
						logger.String("container", name),
						logger.Any("panic", r),
						logger.String("stack", string(debug.Stack())),
					)
				}
			}()

			// Block waiting for semaphore slot, but bail immediately if the
			// parent context is already cancelled.
			select {
			case <-ctx.Done():
				emitSkipped(name, id, labels, &updates, &mu, &processedCount, totalToCheck, onProgress)
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			// Each container gets its own deadline so a slow/unreachable registry
			// cannot hold a semaphore slot (and stall the progress bar) indefinitely.
			containerCtx, containerCancel := context.WithTimeout(ctx, containerScanTimeout)
			defer containerCancel()

			upd := api.ContainerUpdate{
				ID:     id,
				Name:   name,
				Status: "checked",
				Labels: labels,
			}

			resolvedName, _, repoDigests, os, arch, err := discovery.GetContainerImageDetails(containerCtx, id)
			scannerLog.DebugContext(ctx, "container image details resolved",
				logger.String("container", name),
				logger.String("image", image),
				logger.String("resolved_name", resolvedName),
				logger.Int("repo_digests_count", len(repoDigests)),
			)

			if containerCtx.Err() != nil {
				scannerLog.DebugContext(ctx, "container scan cancelled after inspect",
					logger.String("container", name),
				)
				emitSkipped(name, id, labels, &updates, &mu, &processedCount, totalToCheck, onProgress)
				return
			}

			if err != nil {
				// Detect transitional state: container was renamed/deleted mid-scan
				// (e.g., during a concurrent RecreateContainer). Treat as "skipped"
				// rather than "error" so the cache is left untouched.
				if isContainerGone(err) {
					upd.Status = "skipped"
					scannerLog.DebugContext(ctx, "container skipped (likely mid-recreation)",
						logger.String("container", name),
						logger.Any("error", err),
					)
				} else {
					upd.Error = fmt.Sprintf("Inspect error: %v", err)
					upd.Status = "error"
					scannerLog.DebugContext(ctx, "container inspect error",
						logger.String("container", name),
						logger.Any("error", err),
					)
				}
			} else {
				if resolvedName != "" {
					upd.Image = resolvedName
				} else {
					upd.Image = image
				}

				if len(repoDigests) > 0 {
					upd.LocalDigest = repoDigests[0]
				}

				var platform *v1.Platform
				if os != "" && arch != "" {
					platform = &v1.Platform{
						OS:           os,
						Architecture: arch,
					}
					scannerLog.DebugContext(ctx, "platform resolution",
						logger.String("container", name),
						logger.String("os", os),
						logger.String("arch", arch),
					)
				}

				// Locally-built images (e.g. from a Compose "build:" directive) have
				// no RepoDigests because they were never pushed to or pulled from a
				// registry. There is nothing to compare against remotely, so skip the
				// registry round-trip immediately rather than burning the full
				// containerScanTimeout on a request that will always fail or time out.
				if len(repoDigests) == 0 {
					upd.Status = "local"
					scannerLog.DebugContext(ctx, "container is locally built, skipping registry check",
						logger.String("container", name),
						logger.String("image", upd.Image),
					)
					mu.Lock()
					updates = append(updates, upd)
					newCount := atomic.AddInt32(&processedCount, 1)
					mu.Unlock()
					if onProgress != nil {
						onProgress(upd, int(newCount), totalToCheck)
					}
					return
				}

				imageToCheck := upd.Image
				if strings.HasPrefix(imageToCheck, "localhost:") || strings.HasPrefix(imageToCheck, "127.0.0.1:") {
					scannerLog.DebugContext(ctx, "rewriting localhost image for Docker",
						logger.String("original", imageToCheck),
					)
					imageToCheck = strings.Replace(imageToCheck, "localhost:", "host.docker.internal:", 1)
					imageToCheck = strings.Replace(imageToCheck, "127.0.0.1:", "host.docker.internal:", 1)
				}

				// Pass containerCtx so the registry network call is bounded by the
				// per-container timeout and will be cancelled if the parent is cancelled.
				remoteDigest, err := registry.GetRemoteDigest(containerCtx, imageToCheck, nil, force)
				var platformDigest string
				platformErr := fmt.Errorf("platform check skipped")

				found := false
				if err == nil {
					for _, rd := range repoDigests {
						parts := strings.Split(rd, "@")
						if len(parts) == 2 && parts[1] == remoteDigest {
							found = true
							break
						}
					}
				}

				if !found && platform != nil {
					platformDigest, platformErr = registry.GetRemoteDigest(containerCtx, imageToCheck, platform, force)
					if platformErr == nil {
						remoteDigest = platformDigest
						err = nil
						for _, rd := range repoDigests {
							parts := strings.Split(rd, "@")
							if len(parts) == 2 && parts[1] == platformDigest {
								found = true
								break
							}
						}
					} else {
						scannerLog.DebugContext(ctx, "platform-specific remote digest check failed",
							logger.String("container", name),
							logger.Any("error", platformErr),
						)
					}
				}

				if err != nil && remoteDigest == "" {
					// If the per-container context expired, report as skipped rather
					// than error so the progress bar still advances.
					if containerCtx.Err() != nil {
						scannerLog.DebugContext(ctx, "container scan timed out during registry check",
							logger.String("container", name),
						)
						emitSkipped(name, id, labels, &updates, &mu, &processedCount, totalToCheck, onProgress)
						return
					}
					upd.Error = fmt.Sprintf("Registry error: %v", err)
					upd.Status = "error"
					scannerLog.DebugContext(ctx, "registry check error",
						logger.String("container", name),
						logger.Any("error", err),
					)
				} else {
					upd.RemoteDigest = remoteDigest
					if !found {
						upd.UpdateAvailable = true
						scannerLog.DebugContext(ctx, "update available",
							logger.String("container", name),
							logger.Bool("update_available", true),
						)
					} else {
						scannerLog.DebugContext(ctx, "container up to date",
							logger.String("container", name),
							logger.Bool("update_available", false),
						)
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

	// Second pass: re-list containers to catch any that appeared during the scan
	// (e.g., created by a concurrent RecreateContainer). Process only containers
	// not already in the results.
	recheckContainers, recheckErr := discovery.ListContainers(ctx)
	if recheckErr == nil {
		seenNames := make(map[string]bool, len(updates))
		for _, u := range updates {
			seenNames[u.Name] = true
		}

		for _, c := range recheckContainers {
			if len(c.Names) == 0 {
				continue
			}
			cName := c.Names[0]
			if len(cName) > 0 && cName[0] == '/' {
				cName = cName[1:]
			}
			if filter != "" && filter != "all" && cName != filter {
				continue
			}
			if seenNames[cName] {
				continue
			}

			// This container appeared during the scan. Do a quick inspect + registry
			// check synchronously (small expected count).
			recheckCtx, recheckCancel := context.WithTimeout(ctx, containerScanTimeout)
			resolvedName, _, repoDigests, cOs, cArch, inspectErr := discovery.GetContainerImageDetails(recheckCtx, c.ID)
			upd := api.ContainerUpdate{
				ID:     c.ID,
				Name:   cName,
				Status: "checked",
				Labels: c.Labels,
			}
			if inspectErr != nil {
				if isContainerGone(inspectErr) {
					upd.Status = "skipped"
				}
			} else {
				if resolvedName != "" {
					upd.Image = resolvedName
				} else {
					upd.Image = c.Image
				}
				if len(repoDigests) > 0 {
					upd.LocalDigest = repoDigests[0]
				}
				// Same local-image guard as in the main pass: no RepoDigests means
				// locally built, nothing to check remotely.
				if len(repoDigests) > 0 && cOs != "" && cArch != "" {
					imageToCheck := upd.Image
					remoteDigest, remoteErr := registry.GetRemoteDigest(recheckCtx, imageToCheck, nil, force)
					if remoteErr == nil {
						upd.RemoteDigest = remoteDigest
						found := false
						for _, rd := range repoDigests {
							parts := strings.Split(rd, "@")
							if len(parts) == 2 && parts[1] == remoteDigest {
								found = true
								break
							}
						}
						upd.UpdateAvailable = !found
					}
				} else if len(repoDigests) == 0 {
					upd.Status = "local"
				}
			}
			recheckCancel()

			mu.Lock()
			updates = append(updates, upd)
			mu.Unlock()

			if onProgress != nil {
				onProgress(upd, int(atomic.AddInt32(&processedCount, 1)), totalToCheck)
			}
		}
	}

	return updates, nil
}
