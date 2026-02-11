package main

import (
	"context"
	"dockgo/api"
	"dockgo/engine"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
)

func main() {
	checkOnly := flag.Bool("n", false, "Check for updates only (dry-run)")
	updateAll := flag.Bool("a", false, "Update all containers with available updates")
	updateName := flag.String("y", "", "Update specific container by name (e.g. 'update-me' or 'all')")
	jsonOutput := flag.Bool("json", false, "Output in JSON format") // This name handles both formats but flag is boolean
	flag.Parse()

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

	if !*jsonOutput {
		if targetContainer != "" && targetContainer != "all" {
			fmt.Printf("Checking container %s...\n", targetContainer)
		} else {
			fmt.Printf("Checking %d containers...\n", len(allContainers))
		}
	}

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
		go func(name, image, id, state string) {
			defer wg.Done()

			upd := api.ContainerUpdate{
				ID:     id,
				Name:   name,
				Status: "checked",
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
						if strings.Contains(rd, remoteDigest) {
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

			// Print inside lock
			if !*jsonOutput {
				if upd.Status == "error" {
					fmt.Printf("❌ %s: %s\n", name, upd.Error)
				} else if upd.UpdateAvailable {
					fmt.Printf("⬆️  %s: Update available (%s...)\n", name, short(upd.RemoteDigest))
				} else {
					fmt.Printf("✅ %s: Up to date\n", name)
				}
			}
			mu.Unlock()
		}(cName, c.Image, c.ID, c.State)
	}
	wg.Wait()

	// Update Phase
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

				// Pull
				err := discovery.PullImage(ctx, upd.Image)
				if err != nil {
					fmt.Printf("Failed to pull %s: %v\n", upd.Name, err)
					upd.Error = err.Error()
					continue
				}

				// Recreate
				err = discovery.RecreateContainer(ctx, upd.ID, upd.Image)
				if err != nil {
					fmt.Printf("Failed to recreate %s: %v\n", upd.Name, err)
					upd.Error = err.Error()
				} else {
					if !*jsonOutput {
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
