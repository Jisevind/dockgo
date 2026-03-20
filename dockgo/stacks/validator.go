package stacks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
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

	if stack.PathMode == PathModeHostNative && runtime.GOOS != "windows" && isWindowsAbs(stack.WorkingDir) {
		result.Valid = false
		result.Issues = append(result.Issues, "host_native path mode cannot use Windows paths from a non-Windows DockGo runtime; use mapped mode with path_mappings")
	}
	if stack.PathMode == PathModeMapped {
		if issue := validateMappedPathResolution(stack.WorkingDir, stack); issue != "" {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("working_dir %s", issue))
		}
	}

	if !result.Valid {
		return result
	}

	if info, err := os.Stat(stack.WorkingDir); err != nil {
		resolvedDir := resolvePathForRuntime(stack, stack.WorkingDir)
		info, err = os.Stat(resolvedDir)
		if err == nil && info.IsDir() {
			goto workingDirOK
		}
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("working_dir does not exist: %s", stack.WorkingDir))
	} else if !info.IsDir() {
		result.Valid = false
		result.Issues = append(result.Issues, "working_dir is not a directory")
	}
workingDirOK:

	for _, composeFile := range stack.ComposeFiles {
		if !isAbsPath(composeFile) {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("compose file must be absolute: %s", composeFile))
			continue
		}
		if stack.PathMode == PathModeMapped {
			if issue := validateMappedPathResolution(composeFile, stack); issue != "" {
				result.Valid = false
				result.Issues = append(result.Issues, fmt.Sprintf("compose file %s", issue))
				continue
			}
		}
		resolvedComposeFile := resolvePathForRuntime(stack, composeFile)
		if _, err := os.Stat(resolvedComposeFile); err != nil {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("compose file does not exist: %s", composeFile))
		}
	}

	for _, envFile := range stack.EnvFiles {
		if !isAbsPath(envFile) {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("env file must be absolute: %s", envFile))
			continue
		}
		if stack.PathMode == PathModeMapped {
			if issue := validateMappedPathResolution(envFile, stack); issue != "" {
				result.Valid = false
				result.Issues = append(result.Issues, fmt.Sprintf("env file %s", issue))
				continue
			}
		}
		resolvedEnvFile := resolvePathForRuntime(stack, envFile)
		if _, err := os.Stat(resolvedEnvFile); err != nil {
			result.Valid = false
			result.Issues = append(result.Issues, fmt.Sprintf("env file does not exist: %s", envFile))
		}
	}

	if stack.PathMode == PathModeMapped && len(stack.PathMappings) == 0 {
		if len(defaultMappings()) == 0 {
			result.Warnings = append(result.Warnings, "mapped path mode is configured without explicit path_mappings")
			if isWindowsAbs(stack.WorkingDir) {
				result.Warnings = append(result.Warnings, "Windows host paths in mapped mode require COMPOSE_PATH_MAPPING or stack path_mappings to resolve inside DockGo")
			}
		}
	} else if stack.PathMode == PathModeMapped {
		resolvedDir := resolvePathForRuntime(stack, stack.WorkingDir)
		if resolvedDir == stack.WorkingDir {
			result.Warnings = append(result.Warnings, "working_dir did not change after path mapping resolution; verify host_path/container_path values")
		}
	}

	if !result.Valid {
		return result
	}

	output, err := composeConfigJSON(ctx, stack)
	if err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, err.Error())
		return result
	}

	var decoded map[string]any
	if err := json.Unmarshal(output, &decoded); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, "docker compose config returned invalid JSON")
	}

	return result
}

func validateMappedPathResolution(path string, stack Stack) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}

	resolvedPath := resolvePathForRuntime(stack, path)
	if resolvedPath == path && isWindowsAbs(path) && runtime.GOOS != "windows" {
		return fmt.Sprintf("cannot be resolved inside DockGo from Windows host path: %s", path)
	}

	return ""
}
