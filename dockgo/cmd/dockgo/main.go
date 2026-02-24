package main

import (
	"context"
	"dockgo/api"
	"dockgo/engine"
	"dockgo/logger"
	"dockgo/server"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Setup Logger
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		logger.SetLevel(logLevel)
	}

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
	case "hash-password":
		handleHashPassword(args)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		help()
		os.Exit(1)
	}
}

func help() {
	fmt.Println("Usage: dockgo <command> [flags]")
	fmt.Println("\nCommands:")
	fmt.Println("  serve          Start the web server")
	fmt.Println("  check          Check for updates (dry-run)")
	fmt.Println("  update         Update containers")
	fmt.Println("  hash-password  Generate a bcrypt hash for AUTH_PASSWORD_HASH")
}

func handleServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.String("port", "", "Port to listen on (default: $PORT or 3131)")
	_ = fs.Parse(args)

	p := *port
	if p == "" {
		p = os.Getenv("PORT")
	}
	if p == "" {
		p = "3131"
	}

	srv, err := server.NewServer(p)
	if err != nil {
		fmt.Printf("Failed to initialize server: %v\n", err)
		os.Exit(1)
	}
	if err := srv.Start(); err != nil {
		fmt.Printf("Server failed: %v\n", err)
		os.Exit(1)
	}
}

func handleHashPassword(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: dockgo hash-password <password>")
		os.Exit(1)
	}

	password := args[0]
	costStr := os.Getenv("AUTH_BCRYPT_COST")
	bcryptCost := bcrypt.DefaultCost

	if costStr != "" {
		if c, err := strconv.Atoi(costStr); err == nil && c >= bcrypt.MinCost && c <= bcrypt.MaxCost {
			bcryptCost = c
		} else {
			fmt.Println("Warning: Invalid AUTH_BCRYPT_COST, falling back to default")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		fmt.Printf("Failed to generate hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", string(hash))
}

func handleCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	streamOutput := fs.Bool("stream", false, "Output as a stream of JSON events")
	updateName := fs.String("y", "", "Check specific container by name (e.g. 'container-name' or 'all')")
	_ = fs.Parse(args)

	runScan(true, *jsonOutput, *streamOutput, *updateName, false, false, false)
}

func handleUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	streamOutput := fs.Bool("stream", false, "Output as a stream of JSON events")
	updateName := fs.String("y", "", "Update specific container by name (e.g. 'container-name' or 'all')")
	updateAll := fs.Bool("a", false, "Update all containers with available updates")
	updateSafe := fs.Bool("safe", false, "Safe mode: Download updates but do NOT restart running containers")
	updateForce := fs.Bool("force", false, "Force mode: Update and restart even if running")
	preserveNetwork := fs.Bool("preserve-network", false, "Preserve network settings (IP, MAC) during recreation")
	_ = fs.Parse(args)

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
			_ = json.NewEncoder(os.Stdout).Encode(evt)
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

	updateCtx := logger.WithUpdateID(ctx, uuid.New().String())

	updates, err := engine.Scan(updateCtx, discovery, registry, filter, true, onProgress)
	if err != nil {
		fatal("Scan error: %v", err)
	}

	// Update Phase
	if checkOnly {
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(api.CheckReport{Containers: updates})
		}
		return
	}

	// EXECUTE UPDATES
	if filter != "" {
		for i := range updates {
			upd := &updates[i]

			if upd.UpdateAvailable {
				// Safety: The 'Scan' function returns all available updates if no filter is provided.
				// However, for the 'update' command, we require an explicit target
				// ('-a' for all or '-y' for specific) to prevent accidental bulk updates.
				// If no target was specified (filter is empty), we abort here.

				if filter == "" {
					fmt.Println("No target specified. Use -a for all or -y <name>.")
					return
				}

				if !jsonOutput {
					fmt.Printf("Updating %s...\n", upd.Name)
				}

				// Prepare callback for CLI formatting
				logCb := func(evt api.ProgressEvent) {
					if streamOutput {
						_ = json.NewEncoder(os.Stdout).Encode(evt)
					} else if !jsonOutput {
						// Format for terminal
						if evt.Type == "progress" {
							if evt.Percent > 0 {
								// \r is handled intrinsically or explicitly by the event if it's meant to overwrite
								fmt.Printf("%s\n", evt.Status)
							} else {
								fmt.Printf("%s\n", evt.Status)
							}
						} else if evt.Type == "error" {
							fmt.Printf("❌ %s\n", evt.Error)
						}
					}
				}

				opts := engine.UpdateOptions{
					Safe:            safe,
					PreserveNetwork: preserveNetwork,
					LogCallback:     logCb,
				}

				err = engine.PerformUpdate(updateCtx, discovery, upd, opts)
				if err != nil {
					if !jsonOutput && !streamOutput {
						fmt.Printf("Failed to update %s: %v\n", upd.Name, err)
					}
				}
			}
		}
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(api.CheckReport{Containers: updates})
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
