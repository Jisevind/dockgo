package stacks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// dockerCallTimeout is the maximum time a single Docker API call may take
// before being considered stalled. This prevents a slow daemon response
// (common right after container recreation) from consuming the entire
// verification budget.
const dockerCallTimeout = 30 * time.Second

func VerifyDeployment(ctx context.Context, stack Stack, log Logger) error {
	if log == nil {
		log = func(string) {}
	}

	timeoutSeconds := stack.HealthPolicy.WaitTimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 120
	}

	// Use context.Background so the verification gets its full timeout budget
	// regardless of how much time was consumed by prior phases (pull, deploy,
	// compose --wait). Parent cancellation is still respected by monitoring
	// ctx.Done() in the loop below.
	verifyCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client for verification: %w", err)
	}
	defer cli.Close()

	project := stack.Discovery.ComposeProject
	if project == "" {
		project = stack.ProjectName
	}
	if project == "" {
		return fmt.Errorf("cannot verify stack without compose project name")
	}

	log(fmt.Sprintf("Verifying stack containers for project '%s'...", project))

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastStateErr error
	for {
		containers, err := dockerContainerList(verifyCtx, cli, project)
		if err != nil {
			if isTransientDockerErr(err) {
				lastStateErr = fmt.Errorf("failed to list project containers: %w", err)
			} else {
				return fmt.Errorf("failed to list project containers: %w", err)
			}
		} else if len(containers) == 0 {
			lastStateErr = fmt.Errorf("no containers found for compose project %s", project)
		} else {
			allGood, detailErr := verifyContainersOnce(verifyCtx, cli, containers, stack)
			if detailErr != nil {
				if isTransientDockerErr(detailErr) {
					lastStateErr = detailErr
				} else {
					return fmt.Errorf("stack verification failed: %w", detailErr)
				}
			} else if allGood {
				log("Stack verification passed.")
				return nil
			}
		}

		select {
		case <-ctx.Done():
			// Parent context cancelled (e.g. client disconnected).
			return fmt.Errorf("stack verification cancelled")
		case <-verifyCtx.Done():
			if lastStateErr != nil {
				return fmt.Errorf("stack verification failed: %w", lastStateErr)
			}
			return fmt.Errorf("stack verification timed out")
		case <-ticker.C:
		}
	}
}

// dockerContainerList wraps cli.ContainerList with a per-call timeout so a
// single slow Docker daemon response does not consume the entire verification
// budget.
func dockerContainerList(ctx context.Context, cli *client.Client, project string) ([]container.Summary, error) {
	callCtx, callCancel := context.WithTimeout(ctx, dockerCallTimeout)
	defer callCancel()

	return cli.ContainerList(callCtx, container.ListOptions{
		All: true,
		Filters: labelFilter(map[string]string{
			"com.docker.compose.project": project,
		}),
	})
}

// dockerContainerInspect wraps cli.ContainerInspect with a per-call timeout.
func dockerContainerInspect(ctx context.Context, cli *client.Client, containerID string) (container.InspectResponse, error) {
	callCtx, callCancel := context.WithTimeout(ctx, dockerCallTimeout)
	defer callCancel()

	return cli.ContainerInspect(callCtx, containerID)
}

func verifyContainersOnce(ctx context.Context, cli *client.Client, containers []container.Summary, stack Stack) (bool, error) {
	graceSeconds := stack.HealthPolicy.StartupGrace
	if graceSeconds <= 0 {
		graceSeconds = 20
	}

	for _, c := range containers {
		inspect, err := dockerContainerInspect(ctx, cli, c.ID)
		if err != nil {
			return false, fmt.Errorf("failed to inspect container %s: %w", c.ID[:12], err)
		}

		if inspect.State == nil || !inspect.State.Running {
			return false, fmt.Errorf("container %s is not running", trimName(inspect.Name))
		}

		if inspect.State.Health != nil {
			switch inspect.State.Health.Status {
			case "healthy":
				continue
			case "unhealthy":
				return false, fmt.Errorf("container %s is unhealthy", trimName(inspect.Name))
			default:
				return false, nil
			}
		}

		// No healthcheck. Require the container to keep running across a short grace period.
		checkCtx, cancel := context.WithTimeout(ctx, time.Duration(graceSeconds)*time.Second)
		stable, err := waitRunning(checkCtx, cli, c.ID)
		cancel()
		if err != nil {
			return false, err
		}
		if !stable {
			return false, nil
		}
	}

	return true, nil
}

func waitRunning(ctx context.Context, cli *client.Client, containerID string) (bool, error) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return true, nil
		case <-ticker.C:
			inspect, err := dockerContainerInspect(ctx, cli, containerID)
			if err != nil {
				if isTransientDockerErr(err) {
					continue
				}
				return false, fmt.Errorf("failed to inspect container %s during stability wait: %w", containerID[:12], err)
			}
			if inspect.State == nil || !inspect.State.Running {
				return false, fmt.Errorf("container %s stopped during stability wait", trimName(inspect.Name))
			}
			if inspect.State.Health != nil && inspect.State.Health.Status == "unhealthy" {
				return false, fmt.Errorf("container %s became unhealthy during stability wait", trimName(inspect.Name))
			}
		}
	}
}

// isTransientDockerErr returns true for errors that are likely transient Docker
// daemon hiccups (socket contention, momentary overload after container
// recreation) and can be retried on the next ticker iteration.
func isTransientDockerErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "resource temporarily unavailable")
}

func trimName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		return name[1:]
	}
	return name
}
