package stacks

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

func ResolvedComposeServices(ctx context.Context, stack Stack) ([]string, error) {
	output, err := composeConfigJSON(ctx, stack)
	if err != nil {
		return nil, err
	}

	var decoded struct {
		Services map[string]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(output, &decoded); err != nil {
		return nil, fmt.Errorf("failed to decode compose config services: %w", err)
	}

	services := make([]string, 0, len(decoded.Services))
	for service := range decoded.Services {
		services = append(services, service)
	}
	sort.Strings(services)
	return services, nil
}

func composeConfigJSON(ctx context.Context, stack Stack) ([]byte, error) {
	args := []string{"compose"}
	for _, composeFile := range stack.ComposeFiles {
		args = append(args, "-f", resolvePathForRuntime(stack, composeFile))
	}
	for _, envFile := range stack.EnvFiles {
		args = append(args, "--env-file", resolvePathForRuntime(stack, envFile))
	}
	args = append(args, "config", "--format", "json")

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = resolvePathForRuntime(stack, stack.WorkingDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker compose config failed: %s", strings.TrimSpace(string(output)))
	}
	return output, nil
}
