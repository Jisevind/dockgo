package stacks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func Validate(ctx context.Context, stack Stack) ValidationResult {
	result := ValidationResult{Valid: true}

	if strings.TrimSpace(stack.Name) == "" {
		result.Valid = false
		result.Issues = append(result.Issues, "stack name is required")
	}
	if strings.TrimSpace(stack.ProjectName) == "" {
		result.Valid = false
		result.Issues = append(result.Issues, "project_name is required")
	}
	if strings.TrimSpace(stack.WorkingDir) == "" {
		result.Valid = false
		result.Issues = append(result.Issues, "working_dir is required")
	}
	if len(stack.ComposeFiles) == 0 {
		result.Valid = false
		result.Issues = append(result.Issues, "at least one compose file is required")
	}
	if stack.PathMode != PathModeHostNative && stack.PathMode != PathModeMapped {
		result.Valid = false
		result.Issues = append(result.Issues, "path_mode must be 'host_native' or 'mapped'")
	}

	if !result.Valid {
		return result
	}

	if info, err := os.Stat(stack.WorkingDir); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("working_dir does not exist: %s", stack.WorkingDir))
	} else if !info.IsDir() {
		result.Valid = false
		result.Issues = append(result.Issues, "working_dir is not a directory")
	}

	for _, composeFile := range stack.ComposeFiles {
		if !filepath.IsAbs(composeFile) {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("compose file must be absolute: %s", composeFile))
			continue
		}
		if _, err := os.Stat(composeFile); err != nil {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("compose file does not exist: %s", composeFile))
		}
	}

	for _, envFile := range stack.EnvFiles {
		if !filepath.IsAbs(envFile) {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("env file must be absolute: %s", envFile))
			continue
		}
		if _, err := os.Stat(envFile); err != nil {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("env file does not exist: %s", envFile))
		}
	}

	if stack.PathMode == PathModeMapped && len(stack.PathMappings) == 0 {
		result.Warnings = append(result.Warnings, "mapped path mode is configured without explicit path_mappings")
	}

	if !result.Valid {
		return result
	}

	args := []string{"compose"}
	for _, composeFile := range stack.ComposeFiles {
		args = append(args, "-f", composeFile)
	}
	for _, envFile := range stack.EnvFiles {
		args = append(args, "--env-file", envFile)
	}
	args = append(args, "config", "--format", "json")

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = stack.WorkingDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("docker compose config failed: %s", strings.TrimSpace(string(output))))
		return result
	}

	var decoded map[string]any
	if err := json.Unmarshal(output, &decoded); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, "docker compose config returned invalid JSON")
	}

	return result
}
