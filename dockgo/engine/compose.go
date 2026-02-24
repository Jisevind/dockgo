package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// validateWorkingDir performs security checks on the working directory path
// to prevent path traversal and ensure it's within allowed paths.
func validateWorkingDir(workingDir string, allowedPaths []string) (string, error) {
	// 1. Clean the path to remove any . or .. components
	cleanDir := filepath.Clean(workingDir)

	// 2. Resolve symlinks to get the real path
	realDir, err := filepath.EvalSymlinks(cleanDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve working directory: %w", err)
	}

	// 3. Ensure it's an absolute path (prevent relative path tricks)
	if !filepath.IsAbs(realDir) {
		return "", fmt.Errorf("working directory must be an absolute path: %s", realDir)
	}

	// 4. Verify it's actually a directory
	info, err := os.Stat(realDir)
	if err != nil {
		return "", fmt.Errorf("compose working directory does not exist: %s", realDir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("compose working directory is not a directory: %s", realDir)
	}

	// 5. If allowed paths are configured, ensure the working dir is within them
	if len(allowedPaths) > 0 {
		allowed := false
		for _, allowedBase := range allowedPaths {
			// Clean and resolve the allowed base path
			cleanBase := filepath.Clean(allowedBase)
			realBase, err := filepath.EvalSymlinks(cleanBase)
			if err != nil {
				continue // Skip invalid allowed paths
			}

			// Check if realDir is within realBase or is realBase
			if realDir == realBase || strings.HasPrefix(realDir, realBase+string(filepath.Separator)) {
				allowed = true
				break
			}
		}

		if !allowed {
			return "", fmt.Errorf("working directory '%s' is not within allowed paths: %v", realDir, allowedPaths)
		}
	}

	return realDir, nil
}

// ComposeUpdate handles updates using standard docker compose commands
// It detects whether to build or pull based on the service configuration.
func ComposeUpdate(ctx context.Context, workingDir string, serviceName string, allowedPaths []string, log Logger) error {
	if log == nil {
		log = func(s string) { fmt.Println(s) }
	}

	// 1. Validate and sanitize working directory
	validatedDir, err := validateWorkingDir(workingDir, allowedPaths)
	if err != nil {
		return err
	}

	log(fmt.Sprintf("✅ Validated working directory: %s", validatedDir))

	log(fmt.Sprintf("Executing Compose update for service '%s' in '%s'...", serviceName, validatedDir))

	// 2. Inspect service configuration to decide Build vs Pull
	shouldBuild := false
	cmdConfig := exec.CommandContext(ctx, "docker", "compose", "config", "--format", "json")
	cmdConfig.Dir = validatedDir
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
		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "never", "build", "--progress", "plain", serviceName)
		if err != nil {
			return fmt.Errorf("compose build failed: %w", err)
		}
	} else {
		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "never", "pull", serviceName)
		if err != nil {
			return fmt.Errorf("compose pull failed: %w", err)
		}
	}

	// 4. Run 'docker compose up -d [service]'
	// This recreates the container if the image/build changed
	err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "never", "up", "-d", serviceName)
	if err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}

	log("✅ Compose update completed successfully.")
	return nil
}

// ComposePull handles 'docker compose pull' only
func ComposePull(ctx context.Context, workingDir string, serviceName string, allowedPaths []string, log Logger) error {
	if log == nil {
		log = func(s string) { fmt.Println(s) }
	}

	// 1. Validate and sanitize working directory
	validatedDir, err := validateWorkingDir(workingDir, allowedPaths)
	if err != nil {
		return err
	}

	log(fmt.Sprintf("⬇️  Pulling images for service '%s' in '%s' (Safe Mode)...", serviceName, validatedDir))

	// In Safe Mode, we only pull the image to prepare for an update.
	// We do not build or restart the service.
	err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "never", "pull", serviceName)
	if err != nil {
		return fmt.Errorf("compose pull failed: %w", err)
	}

	log("✅ Compose pull completed successfully.")
	return nil
}

// streamCommand executes a command and streams stdout/stderr to the logger
func streamCommand(ctx context.Context, dir string, log Logger, name string, args ...string) error {
	// #nosec G204 - 'name' and 'args' originate entirely from Docker labels, isolated from user inputs
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

	// Custom split function to handle both \n and \r as line delimiters
	splitFunc := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	}

	// Stream stdout
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		scanner.Split(splitFunc)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text != "" {
				log(text)
			}
		}
	}()

	// Stream stderr (docker compose often outputs progress here)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		scanner.Split(splitFunc)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text != "" {
				log(text)
			}
		}
	}()

	wg.Wait()
	return cmd.Wait()
}
