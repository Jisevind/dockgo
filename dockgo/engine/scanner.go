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

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var scannerLog = logger.WithSubsystem("scanner")

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
		totalToCheck++
	}

	var updates []api.ContainerUpdate
	var wg sync.WaitGroup
	var mu sync.Mutex
	var processedCount int32 = 0

	// Limit concurrency to avoid overwhelming registry or network
	sem := make(chan struct{}, 5)

	for _, c := range allContainers {
		if len(c.Names) == 0 {
			continue
		}

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
					scannerLog.ErrorContext(ctx, "scanner goroutine panic",
						logger.String("container", name),
						logger.Any("panic", r),
						logger.String("stack", string(debug.Stack())),
					)
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
			resolvedName, _, repoDigests, os, arch, err := discovery.GetContainerImageDetails(ctx, id)
			scannerLog.DebugContext(ctx, "container image details resolved",
				logger.String("container", name),
				logger.String("image", image),
				logger.String("resolved_name", resolvedName),
				logger.Int("repo_digests_count", len(repoDigests)),
			)

			// Check context again
			if ctx.Err() != nil {
				return
			}

			if err != nil {
				upd.Error = fmt.Sprintf("Inspect error: %v", err)
				upd.Status = "error"
				scannerLog.DebugContext(ctx, "container inspect error",
					logger.String("container", name),
					logger.Any("error", err),
				)
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

				// Check context before remote call
				if ctx.Err() != nil {
					return
				}

				// Fix for localhost registries when running in container
				imageToCheck := upd.Image
				if strings.HasPrefix(imageToCheck, "localhost:") || strings.HasPrefix(imageToCheck, "127.0.0.1:") {
					scannerLog.DebugContext(ctx, "rewriting localhost image for Docker",
						logger.String("original", imageToCheck),
					)
					imageToCheck = strings.Replace(imageToCheck, "localhost:", "host.docker.internal:", 1)
					imageToCheck = strings.Replace(imageToCheck, "127.0.0.1:", "host.docker.internal:", 1)
				}

				// First check the index digest (how most RepoDigests are stored)
				remoteDigest, err := registry.GetRemoteDigest(imageToCheck, nil, force)
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

				// If we didn't match the index AND we have a platform, fetch the platform digest
				// to ensure it's not a multi-arch false positive where local stores the child manifest.
				if !found && platform != nil {
					platformDigest, platformErr = registry.GetRemoteDigest(imageToCheck, platform, force)
					if platformErr == nil {
						remoteDigest = platformDigest // Fallback to platform remote digest for the UI
						for _, rd := range repoDigests {
							parts := strings.Split(rd, "@")
							if len(parts) == 2 && parts[1] == platformDigest {
								found = true
								break
							}
						}
					}
				}

				if err != nil && remoteDigest == "" {
					// Check if error is due to context cancellation
					if ctx.Err() != nil {
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
