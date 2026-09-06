package stacks

import (
	"context"
	"strings"

	"github.com/docker/docker/api/types/container"
)

// ContainerInspector is the subset of the Docker API client needed to read a
// container's health state.
type ContainerInspector interface {
	ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error)
}

// ContainerMatchesStackProject reports whether a container's compose labels
// match the stack's discovery criteria: compose project, working directory, or
// declared service name.
func ContainerMatchesStackProject(stack Stack, labels map[string]string) bool {
	project := stack.Discovery.ComposeProject
	if project == "" {
		project = stack.ProjectName
	}
	if project == "" || labels["com.docker.compose.project"] != project {
		return false
	}

	workingDir := strings.TrimSpace(labels["com.docker.compose.project.working_dir"])
	if workingDir != "" {
		candidatePaths := []string{
			NormalizeComparePath(stack.WorkingDir),
			NormalizeComparePath(ResolvePathForRuntime(stack, stack.WorkingDir)),
		}
		labelPath := NormalizeComparePath(workingDir)
		for _, candidatePath := range candidatePaths {
			if candidatePath != "" && candidatePath == labelPath {
				return true
			}
		}
	}

	service := strings.TrimSpace(labels["com.docker.compose.service"])
	if service != "" {
		for _, serviceName := range stack.Discovery.ServiceNames {
			if strings.EqualFold(strings.TrimSpace(serviceName), service) {
				return true
			}
		}
	}

	return len(stack.Discovery.ServiceNames) == 0 && workingDir == ""
}

// ContainerMatchesStack reports whether a container belongs to a stack. An
// explicitly owned container ID always matches; otherwise the container's
// compose labels are matched via ContainerMatchesStackProject.
func ContainerMatchesStack(stack Stack, containerID string, labels map[string]string) bool {
	for _, ownedID := range stack.ManagedContainers {
		if ownedID == containerID {
			return true
		}
	}
	return ContainerMatchesStackProject(stack, labels)
}

// ContainerHealth returns the container's health status, or an empty string
// when the container has no healthcheck or cannot be inspected.
func ContainerHealth(ctx context.Context, cli ContainerInspector, containerID string) string {
	if cli == nil || containerID == "" {
		return ""
	}

	inspect, err := cli.ContainerInspect(ctx, containerID)
	if err != nil || inspect.State == nil || inspect.State.Health == nil {
		return ""
	}

	return inspect.State.Health.Status
}
