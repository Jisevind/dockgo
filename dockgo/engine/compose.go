package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ComposeConfig structure for parsing 'docker compose config --format json'
type ComposeConfig struct {
	Services map[string]ServiceConfig `json:"services"`
}

type ServiceConfig struct {
	Image string      `json:"image"`
	Build interface{} `json:"build"` // Can be string or object
}

// Logger is a function that handles log lines
type Logger func(string)

// ComposeUpdate handles updates using standard docker compose commands
// It detects whether to build or pull based on the service configuration.
func ComposeUpdate(ctx context.Context, workingDir string, serviceName string, log Logger) error {
	if log == nil {
		log = func(s string) { fmt.Println(s) }
	}

	// 1. Verify working directory exists
	info, err := os.Stat(workingDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("compose working directory does not exist: %s", workingDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("compose working directory is not a directory: %s", workingDir)
	}

	log(fmt.Sprintf("Executing Compose update for service '%s' in '%s'...", serviceName, workingDir))

	// 2. Inspect service configuration to decide Build vs Pull
	shouldBuild := false
	cmdConfig := exec.CommandContext(ctx, "docker", "compose", "config", "--format", "json")
	cmdConfig.Dir = workingDir
	output, err := cmdConfig.Output()
	if err != nil {
		log(fmt.Sprintf("⚠️ Failed to parse compose config: %v. Defaulting to 'pull'.", err))
	} else {
		var config ComposeConfig
		if err := json.Unmarshal(output, &config); err != nil {
			log(fmt.Sprintf("⚠️ Failed to decode compose config: %v. Defaulting to 'pull'.", err))
		} else {
			if svc, ok := config.Services[serviceName]; ok {
				if svc.Build != nil {
					shouldBuild = true
					log(fmt.Sprintf("ℹ️ Service '%s' has a build context. ensuring build...", serviceName))
				}
			}
		}
	}

	// 3. Execute Build or Pull
	if shouldBuild {
		err = streamCommand(ctx, workingDir, log, "docker", "compose", "build", serviceName)
		if err != nil {
			return fmt.Errorf("compose build failed: %w", err)
		}
	} else {
		err = streamCommand(ctx, workingDir, log, "docker", "compose", "pull", serviceName)
		if err != nil {
			return fmt.Errorf("compose pull failed: %w", err)
		}
	}

	// 4. Run 'docker compose up -d [service]'
	// This recreates the container if the image/build changed
	err = streamCommand(ctx, workingDir, log, "docker", "compose", "up", "-d", serviceName)
	if err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}

	log("✅ Compose update completed successfully.")
	return nil
}

// ComposePull handles 'docker compose pull' only
func ComposePull(ctx context.Context, workingDir string, serviceName string, log Logger) error {
	if log == nil {
		log = func(s string) { fmt.Println(s) }
	}

	log(fmt.Sprintf("⬇️  Pulling images for service '%s' in '%s' (Safe Mode)...", serviceName, workingDir))

	// In Safe Mode, we only pull the image to prepare for an update.
	// We do not build or restart the service.
	err := streamCommand(ctx, workingDir, log, "docker", "compose", "pull", serviceName)
	if err != nil {
		return fmt.Errorf("compose pull failed: %w", err)
	}

	log("✅ Compose pull completed successfully.")
	return nil
}

// streamCommand executes a command and streams stdout/stderr to the logger
func streamCommand(ctx context.Context, dir string, log Logger, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return err
	}

	// Use WaitGroup to wait for both scanners to finish
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream stdout
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			log(scanner.Text())
		}
	}()

	// Stream stderr (docker compose often outputs progress here)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			text := scanner.Text()
			// Docker Compose often uses carriage returns for progress bars.
			// Ideally we would parse this, but for now raw logging is sufficient.
			if strings.TrimSpace(text) != "" {
				log(text)
			}
		}
	}()

	wg.Wait()
	return cmd.Wait()
}
