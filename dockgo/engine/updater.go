package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"dockgo/api"
	"dockgo/logger"
)

type OrchestratorType int

const (
	OrchestratorStandalone OrchestratorType = iota
	OrchestratorCompose
	OrchestratorSwarm
)

// UpdateOptions contains the operational parameters for performing a container update.
type UpdateOptions struct {
	Safe            bool
	PreserveNetwork bool
	AllowedPaths    []string
	LogCallback     func(api.ProgressEvent)
}

type lockEntry struct {
	sync.Mutex
	refs int
}

type LockManager struct {
	mu    sync.Mutex
	locks map[string]*lockEntry
}

// Lock acquires a keyed lock and returns an unlock function.
func (lm *LockManager) Lock(id string) func() {
	lm.mu.Lock()
	if lm.locks == nil {
		lm.locks = make(map[string]*lockEntry)
	}
	entry, exists := lm.locks[id]
	if !exists {
		entry = &lockEntry{}
		lm.locks[id] = entry
	}
	entry.refs++
	lm.mu.Unlock()

	entry.Lock()

	return func() {
		lm.mu.Lock()
		defer lm.mu.Unlock()
		entry.Unlock()
		entry.refs--
		if entry.refs == 0 {
			delete(lm.locks, id)
		}
	}
}

var globalLocks LockManager

func lockContainer(id string) func() {
	return globalLocks.Lock(id)
}

// DetectOrchestrator identifies the orchestrator managing a container based on its labels.
func DetectOrchestrator(labels map[string]string) OrchestratorType {
	if _, ok := labels["com.docker.stack.namespace"]; ok {
		return OrchestratorSwarm
	}
	if _, ok := labels["com.docker.compose.project"]; ok {
		return OrchestratorCompose
	}
	return OrchestratorStandalone
}

// PerformUpdate updates a container according to its orchestrator labels.
func PerformUpdate(ctx context.Context, discovery *DiscoveryEngine, upd *api.ContainerUpdate, opts UpdateOptions) error {
	if opts.LogCallback == nil {
		opts.LogCallback = func(api.ProgressEvent) {}
	}

	orchestrator := DetectOrchestrator(upd.Labels)

	switch orchestrator {
	case OrchestratorCompose:
		return updateCompose(ctx, discovery, upd, opts)
	case OrchestratorSwarm:
		unlock := lockContainer(upd.ID)
		defer unlock()
		return fmt.Errorf("swarm updates are not currently supported by DockGo")
	case OrchestratorStandalone:
		unlock := lockContainer(upd.ID)
		defer unlock()
		return updateStandalone(ctx, discovery, upd, opts)
	default:
		return fmt.Errorf("unknown orchestrator type")
	}
}

func updateCompose(ctx context.Context, discovery *DiscoveryEngine, upd *api.ContainerUpdate, opts UpdateOptions) error {
	project, _ := upd.Labels["com.docker.compose.project"]
	workingDir, hasWorkingDir := upd.Labels["com.docker.compose.project.working_dir"]
	_, hasService := upd.Labels["com.docker.compose.service"]

	if !hasWorkingDir || !hasService {
		err := fmt.Errorf("container %s is managed by Compose but metadata is incomplete; refusing unsafe update", upd.Name)
		upd.Error = err.Error()
		return err
	}

	projData := ComposeProjectUpdate{
		Project:    project,
		WorkingDir: workingDir,
		Containers: []api.ContainerUpdate{*upd},
	}

	err := PerformComposeProjectUpdate(ctx, projData, opts)
	if err != nil {
		extendedErr := fmt.Errorf("container %s is managed by Compose but native update failed: %w; refusing standalone fallback", upd.Name, err)
		if opts.LogCallback != nil {
			opts.LogCallback(api.ProgressEvent{
				Type:      "progress",
				Status:    fmt.Sprintf("⚠️  Compose action failed: %v", err),
				Container: upd.Name,
			})
		}

		engineLog.ErrorContext(ctx, "Compose project update failed natively",
			logger.String("container", upd.Name),
			logger.Any("error", err),
		)

		upd.Error = extendedErr.Error()
		return extendedErr
	}

	if opts.Safe {
		upd.Status = "pulled_safe"
	} else {
		upd.Status = "updated"
	}

	return nil
}

// PerformComposeProjectUpdate orchestrates a native Compose project update.
func PerformComposeProjectUpdate(ctx context.Context, projData ComposeProjectUpdate, opts UpdateOptions) error {
	if opts.LogCallback == nil {
		opts.LogCallback = func(api.ProgressEvent) {}
	}
	emitLog := opts.LogCallback

	unlock := lockContainer("compose:" + projData.Project)
	defer unlock()

	if len(opts.AllowedPaths) > 0 {
		validatedDir, err := validateWorkingDir(projData.WorkingDir, opts.AllowedPaths)
		if err != nil {
			return fmt.Errorf("compose project %s working directory validation failed: %w", projData.Project, err)
		}
		projData.WorkingDir = validatedDir
	}

	ctxCompose, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	engineLog.InfoContext(ctx, "Starting Compose project update",
		logger.String("project", projData.Project),
		logger.String("dir", projData.WorkingDir),
		logger.Bool("safe_mode", opts.Safe),
	)

	targetContainer := ""
	if len(projData.Containers) > 0 {
		targetContainer = projData.Containers[0].Name
	}

	composeLogger := func(line string) {
		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    line,
			Container: targetContainer,
		})
	}

	var err error
	if opts.Safe {
		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    fmt.Sprintf("🛡️  Safe Mode (Compose): Skipping project recreation in '%s'. Pulling only.", projData.WorkingDir),
			Container: targetContainer,
		})
		err = ComposePull(ctxCompose, projData.WorkingDir, "", opts.AllowedPaths, composeLogger)
		if err == nil {
			emitLog(api.ProgressEvent{
				Type:      "progress",
				Status:    "✅ Compose project images pulled (no restart)",
				Container: targetContainer,
			})
		}
	} else {
		err = ComposeUpdate(ctxCompose, projData.WorkingDir, "", opts.AllowedPaths, composeLogger)
		if err == nil {
			emitLog(api.ProgressEvent{
				Type:      "progress",
				Status:    fmt.Sprintf("✅ Compose project updated fully in %s", projData.WorkingDir),
				Container: targetContainer,
			})
		}
	}

	if err == nil {
		engineLog.InfoContext(ctx, "Compose project update completed successfully",
			logger.String("project", projData.Project),
		)
	}

	return err
}

func updateStandalone(ctx context.Context, discovery *DiscoveryEngine, upd *api.ContainerUpdate, opts UpdateOptions) error {
	emitLog := opts.LogCallback

	engineLog.InfoContext(ctx, "Starting standalone container update",
		logger.String("container", upd.Name),
		logger.String("image", upd.Image),
		logger.Bool("safe_mode", opts.Safe),
	)

	inspectState, err := discovery.GetContainerState(ctx, upd.ID)
	isRunning := err == nil && inspectState == "running"

	if opts.Safe && isRunning {
		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    fmt.Sprintf("🛡️  Safe Mode: Skipping restart of running container '%s'. Pulling only.", upd.Name),
			Container: upd.Name,
		})
	}

	err = discovery.PullImage(ctx, upd.Image, func(evt api.PullProgressEvent) {
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

		engineLog.ErrorContext(ctx, "Failed to pull image during standalone update",
			logger.String("container", upd.Name),
			logger.String("image", upd.Image),
			logger.Any("error", err),
		)

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

	err = discovery.RecreateContainer(ctx, upd.ID, upd.Image, opts.PreserveNetwork, func(msg string) {
		emitLog(api.ProgressEvent{
			Type:      "progress",
			Status:    msg,
			Container: upd.Name,
		})
	})
	if err != nil {

		engineLog.ErrorContext(ctx, "Failed to recreate container during standalone update",
			logger.String("container", upd.Name),
			logger.String("image", upd.Image),
			logger.Any("error", err),
		)

		upd.Error = err.Error()
		return fmt.Errorf("failed to recreate container: %w", err)
	}

	emitLog(api.ProgressEvent{
		Type:      "progress",
		Status:    fmt.Sprintf("Successfully updated %s", upd.Name),
		Container: upd.Name,
	})

	engineLog.InfoContext(ctx, "Standalone container update completed successfully",
		logger.String("container", upd.Name),
	)

	upd.Status = "updated"

	return nil
}
