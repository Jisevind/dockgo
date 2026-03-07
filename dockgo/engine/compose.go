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

// ComposeConfig stores `docker compose config --format json` output.
type ComposeConfig struct {
	Services map[string]ServiceConfig `json:"services"`
}

type ServiceConfig struct {
	Image string      `json:"image"`
	Build interface{} `json:"build"`
}

// Logger handles streamed command output lines.
type Logger func(string)

func translateComposePath(workingDir string) string {
	mappingEnv := os.Getenv("COMPOSE_PATH_MAPPING")
	if mappingEnv == "" {
		return workingDir
	}

	mappings := strings.Split(mappingEnv, ",")
	for _, mapping := range mappings {
		lastColon := strings.LastIndex(mapping, ":")
		if lastColon > 0 {
			hostPath := strings.TrimSpace(mapping[:lastColon])
			containerPath := strings.TrimSpace(mapping[lastColon+1:])

			normalizedWorkingDir := strings.ReplaceAll(workingDir, "\\", "/")
			normalizedHostPath := strings.ReplaceAll(hostPath, "\\", "/")

			if strings.HasPrefix(strings.ToLower(normalizedWorkingDir), strings.ToLower(normalizedHostPath)) {
				remainder := normalizedWorkingDir[len(normalizedHostPath):]
				return containerPath + remainder
			}
		}
	}

	return workingDir
}

func validateWorkingDir(workingDir string, allowedPaths []string) (string, error) {
	translatedDir := translateComposePath(workingDir)

	cleanDir := filepath.Clean(translatedDir)

	realDir, err := filepath.EvalSymlinks(cleanDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve working directory: %w", err)
	}

	if !filepath.IsAbs(realDir) {
		return "", fmt.Errorf("working directory must be an absolute path: %s", realDir)
	}

	info, err := os.Stat(realDir)
	if err != nil {
		return "", fmt.Errorf("compose working directory does not exist: %s", realDir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("compose working directory is not a directory: %s", realDir)
	}

	if len(allowedPaths) > 0 {
		allowed := false
		for _, allowedBase := range allowedPaths {
			cleanBase := filepath.Clean(allowedBase)
			realBase, err := filepath.EvalSymlinks(cleanBase)
			if err != nil {
				continue
			}

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

// ComposeUpdate updates a Compose project or service.
func ComposeUpdate(ctx context.Context, workingDir string, serviceName string, allowedPaths []string, log Logger) error {
	if log == nil {
		log = func(s string) { fmt.Println(s) }
	}

	validatedDir, err := validateWorkingDir(workingDir, allowedPaths)
	if err != nil {
		return err
	}

	log(fmt.Sprintf("✅ Validated working directory: %s", validatedDir))

	if serviceName == "" {
		log(fmt.Sprintf("Executing Compose project-wide update in '%s'...", validatedDir))

		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "always", "pull")
		if err != nil {
			return fmt.Errorf("compose project pull failed: %w", err)
		}

		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "build", "--progress", "plain")
		if err != nil {
			return fmt.Errorf("compose project build failed: %w", err)
		}

		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "always", "up", "-d")
		if err != nil {
			return fmt.Errorf("compose project up failed: %w", err)
		}

		log("✅ Compose project update completed successfully.")
		return nil
	}

	log(fmt.Sprintf("Executing Compose update for service '%s' in '%s'...", serviceName, validatedDir))

	shouldBuild := false
	cmdConfig := exec.CommandContext(ctx, "docker", "compose", "config", "--format", "json")
	cmdConfig.Dir = validatedDir
	output, err := cmdConfig.Output()
	if err != nil {
		log(fmt.Sprintf("⚠️ Could not inspect compose config (%v). Assuming image-based service and proceeding with pull.", err))
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

	if shouldBuild {
		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "build", "--progress", "plain", serviceName)
		if err != nil {
			return fmt.Errorf("compose build failed: %w", err)
		}
	} else {
		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "always", "pull", serviceName)
		if err != nil {
			return fmt.Errorf("compose pull failed: %w", err)
		}
	}

	err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "always", "up", "-d", serviceName)
	if err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}

	log("✅ Compose service update completed successfully.")
	return nil
}

// ComposePull runs `docker compose pull`.
func ComposePull(ctx context.Context, workingDir string, serviceName string, allowedPaths []string, log Logger) error {
	if log == nil {
		log = func(s string) { fmt.Println(s) }
	}

	validatedDir, err := validateWorkingDir(workingDir, allowedPaths)
	if err != nil {
		return err
	}

	if serviceName == "" {
		log(fmt.Sprintf("⬇️  Pulling images for Compose project in '%s' (Safe Mode)...", validatedDir))
		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "always", "pull")
	} else {
		log(fmt.Sprintf("⬇️  Pulling images for service '%s' in '%s' (Safe Mode)...", serviceName, validatedDir))
		err = streamCommand(ctx, validatedDir, log, "docker", "compose", "--ansi", "always", "pull", serviceName)
	}

	if err != nil {
		return fmt.Errorf("compose pull failed: %w", err)
	}

	log("✅ Compose pull completed successfully.")
	return nil
}

func streamCommand(ctx context.Context, dir string, log Logger, name string, args ...string) error {
	// #nosec G204 - 'name' and 'args' originate entirely from Docker labels, isolated from user inputs
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)

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
