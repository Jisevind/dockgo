package main

import (
	"context"
	"dockgo/api"
	"dockgo/engine"
	"dockgo/server"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	// Subcommand: serve
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "3131"
		}

		srv, err := server.NewServer(port)
		if err != nil {
			fatal("Failed to init server: %v", err)
		}

		// Start server (blocks)
		if err := srv.Start(); err != nil {
			fatal("Server error: %v", err)
		}
		return
	}

	checkOnly := flag.Bool("n", false, "Check for updates only (dry-run)")
	checkOnlyLong := flag.Bool("check-only", false, "Check for updates only (dry-run)")
	updateAll := flag.Bool("a", false, "Update all containers with available updates")
	updateName := flag.String("y", "", "Update specific container by name (e.g. 'update-me' or 'all')")
	updateSafe := flag.Bool("update-safe", false, "Download updates but do NOT restart running containers")
	updateForce := flag.Bool("update-force", false, "Force update and restart even if running")
	preserveNetwork := flag.Bool("preserve-network", false, "Preserve network settings (IP, MAC) during recreation")
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	streamOutput := flag.Bool("stream", false, "Output as a stream of JSON events")
	flag.Parse()

	// Consolidate checkOnly flags
	if *checkOnlyLong {
		*checkOnly = true
	}

	// Conflict check
	if *updateSafe && *updateForce {
		fatal("Cannot use both --update-safe and --update-force")
	}

	// Handle -y "name" logic
	targetContainer := *updateName
	if *updateAll {
		targetContainer = "all"
	}

	if targetContainer != "" && *checkOnly {
		// Just checking specific?
		// dockcheck.sh -n -y <name> isn't standard but valid logic.
		// We allow it.
	}

	ctx := context.Background()
	discovery, err := engine.NewDiscoveryEngine()
	if err != nil {
		fatal("Failed to init discovery: %v", err)
	}
	registry := engine.NewRegistryClient()

	allContainers, err := discovery.ListContainers(ctx)
	if err != nil {
		fatal("Failed to list containers: %v", err)
	}

	// Filter list if target specified
	// var containers []types.Container // Use types.Container from docker/api/types or just iterate allContainers
	// Since types import is tricky with aliasing in finding/replace, let's just loop and filter

	// We will just iterate allContainers and skip in loop

	var updates []api.ContainerUpdate
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Pre-calculate total for progress bar
	totalToCheck := 0
	for _, c := range allContainers {
		cName := c.Names[0]
		if len(cName) > 0 && cName[0] == '/' {
			cName = cName[1:]
		}
		if targetContainer != "" && targetContainer != "all" && cName != targetContainer {
			continue
		}
		totalToCheck++
	}

	if !*jsonOutput && !*streamOutput {
		if targetContainer != "" && targetContainer != "all" {
			fmt.Printf("Checking container %s...\n", targetContainer)
		} else {
			fmt.Printf("Checking %d containers...\n", totalToCheck)
		}
	}

	if *streamOutput {
		// Emit start event
		startEvt := api.ProgressEvent{
			Type:  "start",
			Total: totalToCheck,
		}
		json.NewEncoder(os.Stdout).Encode(startEvt)
	}

	var processedCount int32 = 0

	for _, c := range allContainers {
		// Clean name
		cName := c.Names[0]
		if len(cName) > 0 && cName[0] == '/' {
			cName = cName[1:]
		}

		// Filter
		if targetContainer != "" && targetContainer != "all" && cName != targetContainer {
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
			resolvedName, _, repoDigests, err := discovery.GetContainerImageDetails(ctx, id)
			if err != nil {
				upd.Error = fmt.Sprintf("Inspect error: %v", err)
				upd.Status = "error"
				// If we can't inspect, we can't check update.
				// But we might still have the Image from List.
				// Let's fallback to 'image' arg but it's likely broken if SHA.
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
				remoteDigest, err := registry.GetRemoteDigest(upd.Image)
				if err != nil {
					upd.Error = fmt.Sprintf("Registry error: %v", err)
					upd.Status = "error"
				} else {
					upd.RemoteDigest = remoteDigest

					// Check if remote digest is in repoDigests
					// operations: "index.docker.io/library/alpine@sha256:..."
					found := false
					for _, rd := range repoDigests {
						// rd is typically "image@sha256:..."
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

			// Emit progress event
			if *streamOutput {
				evt := api.ProgressEvent{
					Type:            "progress",
					Current:         int(newCount),
					Total:           totalToCheck,
					Container:       name,
					Status:          upd.Status,
					UpdateAvailable: upd.UpdateAvailable,
				}
				json.NewEncoder(os.Stdout).Encode(evt)
			} else if !*jsonOutput {
				// Print inside lock
				if upd.Status == "error" {
					fmt.Printf("❌ %s: %s\n", name, upd.Error)
				} else if upd.UpdateAvailable {
					fmt.Printf("⬆️  %s: Update available (%s...)\n", name, short(upd.RemoteDigest))
				} else {
					fmt.Printf("✅ %s: Up to date\n", name)
				}
			}
			mu.Unlock()
		}(cName, c.Image, c.ID, c.State, c.Labels)
	}
	wg.Wait()

	// Update Phase
	// Logic:
	// If checkOnly is true -> Skip
	// If targetContainer is set (including "all") -> Proceed
	//   BUT respect safe/force modes.

	if !*checkOnly && targetContainer != "" {
		for i := range updates {
			upd := &updates[i] // Pointer to element
			if upd.UpdateAvailable {
				// Check if this container is targeted
				if targetContainer != "all" && upd.Name != targetContainer {
					continue
				}

				if !*jsonOutput {
					fmt.Printf("Updating %s...\n", upd.Name)
				} else {
					// Update status in list for final JSON?
					// Streaming JSON events would be better but for now modifying the report.
				}

				// Check Safe Mode
				// If Safe Mode is ON and container is RUNNING, we only Pull, no Restart.
				// However, we need to know if it's running. We have 'c.State' from the loop but it wasn't passed to 'updates' struct directly,
				// wait, we passed (name, image, id, state, labels) to the goroutine, but 'api.ContainerUpdate' doesn't have State field.
				// We need to re-inspect or store state.
				// Simplest is to trust the 'upd' if we add State to it, or just re-inspect/use closure if we were in the loop.
				// We are in a new loop here iterating 'updates'. We don't have the original 'c' struct easily unless we map it.
				// Let's rely on 'discovery.GetContainerState' or similar if we had it, OR modify 'ContainerUpdate' to carry state.
				// For now, let's assume we can't easily get state without inspecting.
				// ... Wait, 'updates' is a list of 'api.ContainerUpdate'.
				// Let's inspect to be sure of current state.

				inspectState, err := discovery.GetContainerState(ctx, upd.ID)
				isRunning := false
				if err == nil && inspectState == "running" {
					isRunning = true
				}

				if *updateSafe && isRunning {
					if !*jsonOutput && !*streamOutput {
						fmt.Printf("🛡️  Safe Mode: Skipping restart of running container '%s'. Pulling only.\n", upd.Name)
					}
					// We still want to pull!
					// Fall through to Pull logic but SKIP Recreate/Up.
				}

				// Fallback or Standalone: Pull
				// (Also used for Safe Mode or Compose if we want to ensure pull first)
				// Actually, ComposeUpdate below handles pull internally usually.
				// BUT for Safe Mode we might want to *manually* pull for compose too if we skip 'up'?

				// Let's refactor slightly:
				// 1. Check Compose
				// 2. If Compose:
				//    If Safe+Running -> Compose Pull Only
				//    Else -> Compose Up (which builds/pulls)
				// 3. If Standalone:
				//    Pull
				//    If Safe+Running -> Stop here
				//    Else -> Recreate

				// Check for Compose
				var composeError error
				composeHandled := false

				if workingDir, ok := upd.Labels["com.docker.compose.project.working_dir"]; ok {
					serviceName := upd.Labels["com.docker.compose.service"]
					if serviceName != "" {
						if !*jsonOutput && !*streamOutput {
							fmt.Printf("ℹ️  Detected Compose project in '%s' (service: '%s')\n", workingDir, serviceName)
						}

						// Timeout for Compose operations
						ctxCompose, cancel := context.WithTimeout(ctx, 10*time.Minute)

						// Logger callback for streaming
						logger := func(line string) {
							if *streamOutput {
								// Emit log as status update
								json.NewEncoder(os.Stdout).Encode(api.ProgressEvent{
									Type:      "progress",
									Status:    line, // Reusing status field for log
									Container: upd.Name,
								})
							} else if !*jsonOutput {
								fmt.Println(line)
							}
						}

						var err error
						if *updateSafe && isRunning {
							// Compose Pull Only
							err = engine.ComposePull(ctxCompose, workingDir, serviceName, logger)
							if err == nil {
								upd.Status = "pulled_safe"
								if !*jsonOutput && !*streamOutput {
									fmt.Printf("✅ %s image pulled (no restart)\n", upd.Name)
								}
							}
						} else {
							// Standard Update (Up -d)
							err = engine.ComposeUpdate(ctxCompose, workingDir, serviceName, logger)
							if err == nil {
								upd.Status = "updated"
								if !*jsonOutput && !*streamOutput {
									fmt.Printf("✅ %s updated via Docker Compose\n", upd.Name)
								}
							}
						}

						cancel() // Clean up context

						if err == nil {
							composeHandled = true
						} else {
							composeError = err
							if !*jsonOutput && !*streamOutput {
								// Only warn if we really failed a requested action
								fmt.Printf("⚠️  Compose action failed: %v. Falling back to standalone logic...\n", err)
							}
						}
					}
				}

				if composeHandled {
					continue
				}

				// Fallback or Standalone: Pull
				// Always pull first in all modes for standalone
				err = discovery.PullImage(ctx, upd.Image, func(evt api.PullProgressEvent) {
					if *streamOutput {
						json.NewEncoder(os.Stdout).Encode(evt)
					} else if !*jsonOutput {
						// Text progress
						if evt.Status == "Downloading" || evt.Status == "Extracting" {
							if evt.Percent > 0 {
								fmt.Printf("\r%s %s: %.1f%%", evt.Status, evt.Container, evt.Percent)
							}
						} else {
							fmt.Printf("\n%s\n", evt.Status)
						}
					}
				})
				if err != nil {
					fmt.Printf("Failed to pull %s: %v\n", upd.Name, err)
					upd.Error = err.Error()
					if composeError != nil {
						upd.Error += fmt.Sprintf(" (Compose error: %v)", composeError)
					}
					continue
				}

				// Decide whether to Recreate
				if *updateSafe && isRunning {
					if !*jsonOutput && !*streamOutput {
						fmt.Printf("✅ %s checked/pulled (safe mode active, no restart)\n", upd.Name)
					}
					upd.Status = "pulled_safe"
					continue
				}

				// Recreate
				err = discovery.RecreateContainer(ctx, upd.ID, upd.Image, *preserveNetwork)
				if err != nil {
					fmt.Printf("Failed to recreate %s: %v\n", upd.Name, err)
					upd.Error = err.Error()
				} else {
					if !*jsonOutput && !*streamOutput {
						fmt.Printf("Successfully updated %s\n", upd.Name)
					}
					upd.Status = "updated"
				}
			}
		}
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(api.CheckReport{Containers: updates})
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
