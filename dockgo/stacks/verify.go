package stacks

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func VerifyDeployment(ctx context.Context, stack Stack, log Logger) error {
	if log == nil {
		log = func(string) {}
	}

	timeoutSeconds := stack.HealthPolicy.WaitTimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 120
	}
	verifyCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
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
		containers, err := cli.ContainerList(verifyCtx, container.ListOptions{
			All: true,
			Filters: labelFilter(map[string]string{
				"com.docker.compose.project": project,
			}),
		})
		if err != nil {
			lastStateErr = fmt.Errorf("failed to list project containers: %w", err)
		} else if len(containers) == 0 {
			lastStateErr = fmt.Errorf("no containers found for compose project %s", project)
		} else {
			allGood, detailErr := verifyContainersOnce(verifyCtx, cli, containers, stack)
			if detailErr != nil {
				lastStateErr = detailErr
			} else if allGood {
				log("Stack verification passed.")
				return nil
			}
		}

		select {
		case <-verifyCtx.Done():
			if lastStateErr != nil {
				return fmt.Errorf("stack verification failed: %w", lastStateErr)
			}
			return fmt.Errorf("stack verification timed out")
		case <-ticker.C:
		}
	}
}

func verifyContainersOnce(ctx context.Context, cli *client.Client, containers []container.Summary, stack Stack) (bool, error) {
	graceSeconds := stack.HealthPolicy.StartupGrace
	if graceSeconds <= 0 {
		graceSeconds = 20
	}

	for _, c := range containers {
		inspect, err := cli.ContainerInspect(ctx, c.ID)
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
			inspect, err := cli.ContainerInspect(ctx, containerID)
			if err != nil {
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

func trimName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		return name[1:]
	}
	return name
}
