package engine

import (
	"context"
	"fmt"

	"dockgo/api"
)

// ComposeProjectUpdate represents an entire Compose stack needing updates.
type ComposeProjectUpdate struct {
	Project    string
	WorkingDir string
	Containers []api.ContainerUpdate
}

// UpdatePlan organizes updates into distinct deterministic groups.
type UpdatePlan struct {
	Standalone      []api.ContainerUpdate
	ComposeProjects map[string]ComposeProjectUpdate
}

// BuildUpdatePlan parses raw scan results into a strictly organized
// orchestration plan that de-duplicates Compose project containers.
func BuildUpdatePlan(updates []api.ContainerUpdate) UpdatePlan {
	plan := UpdatePlan{
		Standalone:      make([]api.ContainerUpdate, 0),
		ComposeProjects: make(map[string]ComposeProjectUpdate),
	}

	for i := range updates {
		upd := updates[i]

		if upd.UpdateAvailable {
			orchestrator := DetectOrchestrator(upd.Labels)
			if orchestrator == OrchestratorCompose {
				project, hasProject := upd.Labels["com.docker.compose.project"]
				workingDir, _ := upd.Labels["com.docker.compose.project.working_dir"]

				if !hasProject {
					project = "unknown"
				}

				projUpdate, exists := plan.ComposeProjects[project]
				if !exists {
					projUpdate = ComposeProjectUpdate{
						Project:    project,
						WorkingDir: workingDir,
						Containers: make([]api.ContainerUpdate, 0),
					}
				}
				projUpdate.Containers = append(projUpdate.Containers, upd)
				plan.ComposeProjects[project] = projUpdate

			} else {
				plan.Standalone = append(plan.Standalone, upd)
			}
		}
	}

	return plan
}

// ExecutePlan runs a generated UpdatePlan securely and deterministically.
func ExecutePlan(ctx context.Context, discovery *DiscoveryEngine, plan UpdatePlan, opts UpdateOptions) error {
	var errs []error

	// Execute Standalone Containers iteration
	for _, upd := range plan.Standalone {
		if opts.LogCallback != nil {
			opts.LogCallback(api.ProgressEvent{
				Type:      "start",
				Status:    fmt.Sprintf("Updating standalone container %s...", upd.Name),
				Container: upd.Name,
			})
		}

		err := PerformUpdate(ctx, discovery, &upd, opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("standalone update failed for %s: %w", upd.Name, err))
			if opts.LogCallback != nil {
				opts.LogCallback(api.ProgressEvent{
					Type:      "error",
					Error:     fmt.Sprintf("Failed to update standalone container %s: %v", upd.Name, err),
					Container: upd.Name,
				})
			}
		}
	}

	// Execute Compose Projects iteration
	for project, projData := range plan.ComposeProjects {
		if len(projData.Containers) == 0 {
			continue
		}
		if opts.LogCallback != nil {
			var targetContainer string
			if len(projData.Containers) > 0 {
				targetContainer = projData.Containers[0].Name
			}

			opts.LogCallback(api.ProgressEvent{
				Type:      "start",
				Status:    fmt.Sprintf("Updating Compose project '%s'...", project),
				Container: targetContainer,
			})
		}

		err := PerformComposeProjectUpdate(ctx, projData, opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("compose update failed for project %s: %w", project, err))
			if opts.LogCallback != nil {
				var targetContainer string
				if len(projData.Containers) > 0 {
					targetContainer = projData.Containers[0].Name
				}
				opts.LogCallback(api.ProgressEvent{
					Type:      "error",
					Error:     fmt.Sprintf("Failed to update Compose project %s: %v", project, err),
					Container: targetContainer,
				})
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("ExecutePlan finished with %d errors. First error: %w", len(errs), errs[0])
	}

	return nil
}
