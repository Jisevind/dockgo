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
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		help()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "serve":
		handleServe(args)
	case "check":
		handleCheck(args)
	case "update":
		handleUpdate(args)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		help()
		os.Exit(1)
	}
}

func help() {
	fmt.Println("Usage: dockgo <command> [flags]")
	fmt.Println("\nCommands:")
	fmt.Println("  serve   Start the web server")
	fmt.Println("  check   Check for updates (dry-run)")
	fmt.Println("  update  Update containers")
}

func handleServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.String("port", "", "Port to listen on (default: $PORT or 3131)")
	fs.Parse(args)

	p := *port
	if p == "" {
		p = os.Getenv("PORT")
	}
	if p == "" {
		p = "3131"
	}

	srv, err := server.NewServer(p)
	if err != nil {
		fatal("Failed to init server: %v", err)
	}

	if err := srv.Start(); err != nil {
		fatal("Server error: %v", err)
	}
}

func handleCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	streamOutput := fs.Bool("stream", false, "Output as a stream of JSON events")
	updateName := fs.String("y", "", "Check specific container by name (e.g. 'container-name' or 'all')")
	fs.Parse(args)

	runScan(true, *jsonOutput, *streamOutput, *updateName, false, false, false)
}

func handleUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	streamOutput := fs.Bool("stream", false, "Output as a stream of JSON events")
	updateName := fs.String("y", "", "Update specific container by name (e.g. 'container-name' or 'all')")
	updateAll := fs.Bool("a", false, "Update all containers with available updates")
	updateSafe := fs.Bool("safe", false, "Safe mode: Download updates but do NOT restart running containers") // Renamed from --update-safe
	updateForce := fs.Bool("force", false, "Force mode: Update and restart even if running")                  // Renamed from --update-force
	preserveNetwork := fs.Bool("preserve-network", false, "Preserve network settings (IP, MAC) during recreation")
	fs.Parse(args)

	target := *updateName
	if *updateAll {
		target = "all"
	}

	if *updateSafe && *updateForce {
		fatal("Cannot use both --safe and --force")
	}

	runScan(false, *jsonOutput, *streamOutput, target, *updateSafe, *updateForce, *preserveNetwork)
}

func runScan(checkOnly, jsonOutput, streamOutput bool, filter string, safe, force, preserveNetwork bool) {
	ctx := context.Background()
	discovery, err := engine.NewDiscoveryEngine()
	if err != nil {
		fatal("Failed to init discovery: %v", err)
	}
	registry := engine.NewRegistryClient()

	var mu sync.Mutex

	// Scan containers
	onProgress := func(u api.ContainerUpdate, current, total int) {
		if streamOutput {
			evt := api.ProgressEvent{
				Type:            "progress",
				Current:         current,
				Total:           total,
				Container:       u.Name,
				Status:          u.Status,
				UpdateAvailable: u.UpdateAvailable,
			}
			json.NewEncoder(os.Stdout).Encode(evt)
		} else if !jsonOutput {
			mu.Lock()
			defer mu.Unlock()

			if u.Status == "error" {
				fmt.Printf("❌ %s: %s\n", u.Name, u.Error)
			} else if u.UpdateAvailable {
				fmt.Printf("⬆️  %s: Update available (%s...)\n", u.Name, short(u.RemoteDigest))
			} else {
				fmt.Printf("✅ %s: Up to date\n", u.Name)
			}
		}
	}

	updates, err := engine.Scan(ctx, discovery, registry, filter, onProgress)
	if err != nil {
		fatal("Scan error: %v", err)
	}

	// Update Phase
	if checkOnly {
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(api.CheckReport{Containers: updates})
		}
		return
	}

	// EXECUTE UPDATES
	if filter != "" {
		for i := range updates {
			upd := &updates[i]

			if upd.UpdateAvailable {
				// Filter check (Scan already filters, but double check if specific name logic varies)
				// Actually engine.Scan filters by 'filter' argument if passed.
				// If 'filter' was "all" or specific, Scan returned matches.
				// So we iterate all returned updates.

				// BUT if filter was "all", Scan returns all.
				// If filter was specific, Scan returns specific.
				// So we interpret 'filter' logic:
				// If we are in 'update' mode, and Scan returned updates, we process them.
				// Wait, if I run `dockgo update`, filter is "". Scan returns ALL.
				// But we only update if user said `dockgo update -a` (all) or `dockgo update -y foo`.
				// If `dockgo update` (no args), what happens?
				// Original logic: `targetContainer` default was "".
				// `if !*checkOnly && targetContainer != ""` -> it required a target to update!
				// So `dockgo update` without args should probably DO NOTHING or show help?
				// Or check all and update none?
				// The user asked for "dockgo update". Ideally it updates all?
				// Or maybe matches usage `dockgo update` -> updates all?
				// No, safe default is: Check all, update none unless confirmed?
				// CLI usually asks or requires flag.
				// Let's stick to original logic: Requires target ("-y name" or "-a").

				// Wait, `handleUpdate` sets `target = "all"` if `-a` is set.
				// If neither `-a` nor `-y` is set, `target` is "".
				// So we need to Check `if filter == "" { return }`?
				// Original: `if !*checkOnly && targetContainer != ""`
				// Yes.

				// BUT I passed `filter` to `Scan`.
				// If `filter` is empty, Scan returns all.
				// Then we check if we should ACT.

				if filter == "" {
					fmt.Println("No target specified. Use -a for all or -y <name>.")
					return
				}

				if !jsonOutput {
					fmt.Printf("Updating %s...\n", upd.Name)
				}

				// Check Safe Mode
				inspectState, err := discovery.GetContainerState(ctx, upd.ID)
				isRunning := false
				if err == nil && inspectState == "running" {
					isRunning = true
				}

				if safe && isRunning {
					if !jsonOutput && !streamOutput {
						fmt.Printf("🛡️  Safe Mode: Skipping restart of running container '%s'. Pulling only.\n", upd.Name)
					}
					// Continue to pull
				}

				// Check for Compose and Logic... (Simulating original logic)
				// For brevity in this refactor, I will reuse the core logic but adapted.

				// ... (Compose Logic) ...
				var composeError error
				composeHandled := false
				project, hasProject := upd.Labels["com.docker.compose.project"]
				workingDir, hasWorkingDir := upd.Labels["com.docker.compose.project.working_dir"]
				serviceName, hasService := upd.Labels["com.docker.compose.service"]

				if hasWorkingDir && hasService {
					// ... Compose Update ...
					ctxCompose, cancel := context.WithTimeout(ctx, 10*time.Minute)
					logger := func(line string) {
						if streamOutput {
							json.NewEncoder(os.Stdout).Encode(api.ProgressEvent{
								Type: "progress", Status: line, Container: upd.Name,
							})
						} else if !jsonOutput {
							fmt.Println(line)
						}
					}
					var err error
					if safe && isRunning {
						err = engine.ComposePull(ctxCompose, workingDir, serviceName, logger)
						if err == nil {
							upd.Status = "pulled_safe"
							if !jsonOutput && !streamOutput {
								fmt.Printf("✅ %s image pulled (no restart)\n", upd.Name)
							}
						}
					} else {
						err = engine.ComposeUpdate(ctxCompose, workingDir, serviceName, logger)
						if err == nil {
							upd.Status = "updated"
							if !jsonOutput && !streamOutput {
								fmt.Printf("✅ %s updated via Docker Compose\n", upd.Name)
							}
						}
					}
					cancel()
					if err == nil {
						composeHandled = true
					} else {
						composeError = err
						if !jsonOutput && !streamOutput {
							fmt.Printf("⚠️  Compose action failed: %v. Falling back to standalone...\n", err)
						}
					}
				} else if hasProject {
					if !jsonOutput && !streamOutput {
						fmt.Printf("⚠️  Container %s appears to be a Compose service (project: %s) but matches no working directory. Falling back to standalone update.\n", upd.Name, project)
					}
				}

				if composeHandled {
					continue
				}

				// Standalone Pull
				err = discovery.PullImage(ctx, upd.Image, func(evt api.PullProgressEvent) {
					if streamOutput {
						json.NewEncoder(os.Stdout).Encode(evt)
					} else if !jsonOutput {
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

				if safe && isRunning {
					if !jsonOutput && !streamOutput {
						fmt.Printf("✅ %s checked/pulled (safe mode active)\n", upd.Name)
					}
					upd.Status = "pulled_safe"
					continue
				}

				// Recreate
				err = discovery.RecreateContainer(ctx, upd.ID, upd.Image, preserveNetwork)
				if err != nil {
					fmt.Printf("Failed to recreate %s: %v\n", upd.Name, err)
					upd.Error = err.Error()
				} else {
					if !jsonOutput && !streamOutput {
						fmt.Printf("Successfully updated %s\n", upd.Name)
					}
					upd.Status = "updated"
				}
			}
		}
	}

	if jsonOutput {
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
