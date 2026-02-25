package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"dockgo/api"
)

// UpdateOptions contains the operational parameters for performing a container update.
type UpdateOptions struct {
	Safe            bool
	PreserveNetwork bool
	AllowedPaths    []string // Allowed base paths for Compose working directories
	// LogCallback is used to emit structured progress events synchronously.
	// Callers must ensure their own stream thread-safety bounded inside this callback.
	LogCallback func(api.ProgressEvent)
}

// PerformUpdate orchestrates the full lifecycle update of a Docker container.
// It detects and handles Compose/Swarm fences, checks safe mode invariants,
// and delegates to the appropriate underlying pull/recreate engine.
// Safe mode skips restart of running containers.
// All progress and status data are emitted strictly via the opts.LogCallback closure.
func PerformUpdate(ctx context.Context, discovery *DiscoveryEngine, upd *api.ContainerUpdate, opts UpdateOptions) error {
	// Initialize callback guard
	emitLog := opts.LogCallback
	if emitLog == nil {
		emitLog = func(api.ProgressEvent) {}
	}

	// 1. Check Safe Mode Pre-conditions
	inspectState, err := discovery.GetContainerState(ctx, upd.ID)
	isRunning := false
	if err == nil && inspectState == "running" {
		isRunning = true
	}

	if opts.Safe && isRunning {
		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    fmt.Sprintf("🛡️  Safe Mode: Skipping restart of running container '%s'. Pulling only.", upd.Name),
			Container: upd.Name,
		})
	}

	// 2. Discover Orchestration Details
	var composeError error
	composeHandled := false
	_, hasProject := upd.Labels["com.docker.compose.project"]
	workingDir, hasWorkingDir := upd.Labels["com.docker.compose.project.working_dir"]
	serviceName, hasService := upd.Labels["com.docker.compose.service"]

	isCompose := hasProject || hasService
	isSwarmStack := upd.Labels["com.docker.stack.namespace"] != ""
	isManaged := isCompose || isSwarmStack

	// 3. Attempt Native Compose Orchestration if Managed
	if hasWorkingDir && hasService {
		ctxCompose, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()

		composeLogger := func(line string) {
			emitLog(api.ProgressEvent{
				Type:      "progress",
				Status:    line,
				Container: upd.Name,
			})
		}

		if opts.Safe && isRunning {
			err = ComposePull(ctxCompose, workingDir, serviceName, opts.AllowedPaths, composeLogger)
			if err == nil {
				upd.Status = "pulled_safe"
				emitLog(api.ProgressEvent{
					Type:      "progress",
					Status:    fmt.Sprintf("✅ %s image pulled (no restart)", upd.Name),
					Container: upd.Name,
				})
			}
		} else {
			err = ComposeUpdate(ctxCompose, workingDir, serviceName, opts.AllowedPaths, composeLogger)
			if err == nil {
				upd.Status = "updated"
				emitLog(api.ProgressEvent{
					Type:      "progress",
					Status:    fmt.Sprintf("✅ %s updated via Docker Compose", upd.Name),
					Container: upd.Name,
				})
			}
		}

		if err == nil {
			composeHandled = true
			return nil
		} else {
			composeError = err
			emitLog(api.ProgressEvent{
				Type:      "progress",
				Status:    fmt.Sprintf("⚠️  Compose action failed: %v", err),
				Container: upd.Name,
			})
		}
	}

	// 4. Fallback verification for failed Compose executions
	if isManaged && !composeHandled {
		// Check if this is a Compose container with a working directory
		if hasWorkingDir && len(opts.AllowedPaths) > 0 {
			// Validate that the working directory is within allowed paths
			allowed := false
			for _, allowedBase := range opts.AllowedPaths {
				if workingDir == allowedBase || strings.HasPrefix(workingDir, allowedBase+string(filepath.Separator)) {
					allowed = true
					break
				}
			}
			if !allowed {
				err := fmt.Errorf("container %s is managed by Compose with working directory '%s' which is not within allowed paths: %v", upd.Name, workingDir, opts.AllowedPaths)
				upd.Error = err.Error()
				return err
			}
		}

		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    fmt.Sprintf("⚠️  Container %s is managed by Compose/Swarm but native orchestrator failed or lacks context. Falling back to standalone API update.", upd.Name),
			Container: upd.Name,
		})
	}

	if composeHandled {
		return nil
	}

	// 5. Standalone Image Pull
	err = discovery.PullImage(ctx, upd.Image, func(evt api.PullProgressEvent) {
		// Map generic pull progress event strings back to strict ProgressEvent API contract
		progressStatus := evt.Status
		if (evt.Status == "Downloading" || evt.Status == "Extracting") && evt.Percent > 0 {
			progressStatus = fmt.Sprintf("\r%s: %.1f%%", evt.Status, evt.Percent)
		}

		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    progressStatus,
			Container: evt.Container,
			Percent:   evt.Percent,
		})
	})
	if err != nil {
		extendedErr := fmt.Errorf("failed to pull image: %w", err)
		if composeError != nil {
			extendedErr = fmt.Errorf("%w (Compose fallback error: %v)", extendedErr, composeError)
		}
		upd.Error = extendedErr.Error()
		return extendedErr
	}

	if opts.Safe && isRunning {
		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    fmt.Sprintf("✅ %s checked/pulled (safe mode active)", upd.Name),
			Container: upd.Name,
		})
		upd.Status = "pulled_safe"
		return nil
	}

	// 6. Standalone Recreate Container
	err = discovery.RecreateContainer(ctx, upd.ID, upd.Image, opts.PreserveNetwork, func(msg string) {
		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    msg,
			Container: upd.Name,
		})
	})
	if err != nil {
		upd.Error = err.Error()
		return fmt.Errorf("failed to recreate container: %w", err)
	}

	emitLog(api.ProgressEvent{
		Type:      "progress",
		Status:    fmt.Sprintf("Successfully updated %s", upd.Name),
		Container: upd.Name,
	})
	upd.Status = "updated"

	return nil
}
