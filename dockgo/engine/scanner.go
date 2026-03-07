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

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			upd := api.ContainerUpdate{
				ID:     id,
				Name:   name,
				Status: "checked",
				Labels: labels,
			}

			resolvedName, _, repoDigests, os, arch, err := discovery.GetContainerImageDetails(ctx, id)
			scannerLog.DebugContext(ctx, "container image details resolved",
				logger.String("container", name),
				logger.String("image", image),
				logger.String("resolved_name", resolvedName),
				logger.Int("repo_digests_count", len(repoDigests)),
			)

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

				if ctx.Err() != nil {
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

				if !found && platform != nil {
					platformDigest, platformErr = registry.GetRemoteDigest(imageToCheck, platform, force)
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
