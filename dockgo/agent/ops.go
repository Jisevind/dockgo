package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"dockgo/api"
	"dockgo/engine"
	"dockgo/stacks"

	"github.com/coder/websocket"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// opContainersList lists all containers in the same summary shape as the
// server's local endpoint.
func (a *Agent) opContainersList(ctx context.Context, conn *websocket.Conn, env Envelope) {
	containers, err := a.discovery.ListContainers(ctx)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	result := make([]map[string]any, 0, len(containers))
	visible := make([]container.Summary, 0, len(containers))
	for _, c := range containers {
		name := strings.TrimPrefix(c.Names[0], "/")
		if strings.Contains(name, "_old_") {
			continue
		}
		visible = append(visible, c)

		image := c.Image
		if strings.HasPrefix(image, "sha256:") {
			if resolved, _, _, _, _, err := a.discovery.GetContainerImageDetails(ctx, c.ID); err == nil && resolved != "" {
				image = resolved
			}
		}

		var tagName string
		if idx := strings.LastIndex(image, ":"); idx > -1 && !strings.Contains(image[idx:], "/") {
			tagName = image[idx+1:]
			if idxAt := strings.LastIndex(tagName, "@"); idxAt > -1 {
				tagName = tagName[:idxAt]
			}
		} else if strings.Contains(image, "@") {
			tagName = "(digest)"
		} else {
			tagName = "latest"
		}

		result = append(result, map[string]any{
			"id":                  c.ID,
			"name":                name,
			"image":               image,
			"tag":                 tagName,
			"state":               c.State,
			"status":              c.Status,
			"update_available":    false,
			"compose_project":     c.Labels["com.docker.compose.project"],
			"compose_service":     c.Labels["com.docker.compose.service"],
			"compose_working_dir": c.Labels["com.docker.compose.project.working_dir"],
			"stack_managed":       false,
			"stack_registered":    false,
			"stack_id":            "",
			"stack_name":          "",
		})
	}

	// Resolve stack ownership from the agent-local stack store.
	for i := range result {
		if stack, ok := a.resolveAgentContainerStack(visible[i]); ok {
			result[i]["stack_managed"] = true
			result[i]["stack_registered"] = true
			result[i]["stack_id"] = stack.ID
			result[i]["stack_name"] = stack.Name
		}
	}

	a.sendResult(ctx, conn, env.RequestID, result)
}

// opScan runs an update scan and streams progress events.
func (a *Agent) opScan(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req ScanRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	onProgress := func(u api.ContainerUpdate, current, total int) {
		a.sendProgress(ctx, conn, env.RequestID, ProgressData{
			ProgressType: ProgressScan,
			Progress: &api.ProgressEvent{
				Type:            "progress",
				Current:         current,
				Total:           total,
				Container:       u.Name,
				Status:          u.Status,
				UpdateAvailable: u.UpdateAvailable,
			},
		})
	}

	updates, err := engine.Scan(ctx, a.discovery, a.registry, req.Filter, req.Force, onProgress)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	a.sendResult(ctx, conn, env.RequestID, updates)
}

// opUpdate resolves a container and performs a standalone or compose update.
func (a *Agent) opUpdate(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req UpdateRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	if req.Name == "" {
		a.sendError(ctx, conn, env.RequestID, fmt.Errorf("container name required"))
		return
	}

	emit := func(evt api.ProgressEvent) {
		a.sendProgress(ctx, conn, env.RequestID, ProgressData{
			ProgressType: ProgressUpdate,
			Progress:     &evt,
		})
	}

	emit(api.ProgressEvent{Type: "start", Status: fmt.Sprintf("Starting update for %s...", req.Name), Container: req.Name})

	updates, err := engine.Scan(ctx, a.discovery, a.registry, req.Name, false, nil)
	if err != nil || len(updates) == 0 {
		if err == nil {
			err = fmt.Errorf("container not found or not running")
		}
		a.sendError(ctx, conn, env.RequestID, fmt.Errorf("failed to locate container: %w", err))
		return
	}
	target := &updates[0]

	opts := engine.UpdateOptions{
		Safe:            req.Safe,
		PreserveNetwork: req.PreserveNetwork,
		LogCallback:     emit,
		Registry:        a.registry,
	}

	project := target.Labels["com.docker.compose.project"]
	if project != "" {
		// Registered stack path (agent-local store).
		workingDir := target.Labels["com.docker.compose.project.working_dir"]
		service := target.Labels["com.docker.compose.service"]
		if stack, ok := a.store.FindForComposeTarget(project, workingDir, service); ok {
			emit(api.ProgressEvent{
				Type:      "progress",
				Status:    fmt.Sprintf("Using registered stack '%s' for project '%s'.", stack.Name, project),
				Container: req.Name,
			})
			err = a.executeAgentStackAction(ctx, conn, env.RequestID, stack, "deploy", emit)
		} else {
			err = engine.PerformUpdate(ctx, a.discovery, target, opts)
		}
	} else {
		err = engine.PerformUpdate(ctx, a.discovery, target, opts)
	}

	if err != nil {
		a.sendError(ctx, conn, env.RequestID, fmt.Errorf("update process failed: %w", err))
		return
	}

	// Refresh the registry cache for the updated image.
	if target.Image != "" {
		a.registry.InvalidateImage(target.Image)
	}

	a.sendResult(ctx, conn, env.RequestID, UpdateResult{Success: true, Message: fmt.Sprintf("Container %s updated successfully", req.Name)})
}

// opContainerAction performs start/stop/restart.
func (a *Agent) opContainerAction(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req ContainerActionRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	var actionErr error
	switch req.Action {
	case "start":
		actionErr = a.discovery.StartContainer(ctx, req.Name)
	case "stop":
		actionErr = a.discovery.StopContainer(ctx, req.Name)
	case "restart":
		actionErr = a.discovery.RestartContainer(ctx, req.Name)
	default:
		a.sendError(ctx, conn, env.RequestID, fmt.Errorf("invalid action: %s", req.Action))
		return
	}

	if actionErr != nil {
		a.sendError(ctx, conn, env.RequestID, actionErr)
		return
	}

	a.sendResult(ctx, conn, env.RequestID, ContainerActionResult{
		Success: true,
		Message: fmt.Sprintf("Successfully executed %s on %s", req.Action, req.Name),
	})
}

// opContainerLogs streams container logs as progress events.
func (a *Agent) opContainerLogs(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req ContainerLogsRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "200",
	}

	logsReader, err := a.discovery.Client.ContainerLogs(ctx, req.Name, options)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}
	defer logsReader.Close()

	emitLine := func(line string) {
		a.sendProgress(ctx, conn, env.RequestID, ProgressData{
			ProgressType: ProgressLog,
			Line:         line,
		})
	}

	emitLine("--- Connected to container logs ---")

	stdoutWriter := stacks.NewStreamWriter(emitLine)
	stderrWriter := stacks.NewStreamWriter(emitLine)

	_, err = stdcopy.StdCopy(stdoutWriter, stderrWriter, logsReader)
	if err != nil {
		emitLine(fmt.Sprintf("--- Stream interrupted: %v ---", err))
	} else {
		emitLine("--- Stream disconnected ---")
	}

	a.sendResult(ctx, conn, env.RequestID, LogsResult{Done: true})
}

// opServerStats returns host CPU/RAM/disk stats.
func (a *Agent) opServerStats(ctx context.Context, conn *websocket.Conn, env Envelope) {
	cpuPercent, _ := cpu.Percent(0, false)
	vMem, _ := mem.VirtualMemory()
	diskStat, _ := disk.Usage("/")

	var c float64
	if len(cpuPercent) > 0 {
		c = cpuPercent[0]
	}

	var dUsed, dTotal uint64
	if diskStat != nil {
		dUsed = diskStat.Used
		dTotal = diskStat.Total
	}

	var rUsed, rTotal uint64
	if vMem != nil {
		rUsed = vMem.Used
		rTotal = vMem.Total
	}

	a.sendResult(ctx, conn, env.RequestID, ServerStatsData{
		CPUPercent: c,
		RAMUsed:    rUsed,
		RAMTotal:   rTotal,
		DiskUsed:   dUsed,
		DiskTotal:  dTotal,
	})
}

// resolveAgentContainerStack looks up a container's stack in the agent store.
func (a *Agent) resolveAgentContainerStack(c container.Summary) (stacks.Stack, bool) {
	if a.store == nil {
		return stacks.Stack{}, false
	}
	if stack, ok := a.store.GetByManagedContainer(c.ID); ok {
		return stack, true
	}
	return stacks.Stack{}, false
}

// executeAgentStackAction runs a stack action against the agent-local store,
// streaming log lines as progress events.
func (a *Agent) executeAgentStackAction(ctx context.Context, conn *websocket.Conn, requestID string, stack stacks.Stack, action string, emit func(api.ProgressEvent)) error {
	run := map[string]func(context.Context, stacks.Stack, stacks.Logger) error{
		"deploy":  stacks.Deploy,
		"pull":    stacks.Pull,
		"restart": stacks.Restart,
		"stop":    stacks.Stop,
		"start":   stacks.Start,
		"down":    stacks.Down,
	}[action]
	if run == nil {
		return fmt.Errorf("unsupported stack action: %s", action)
	}

	logger := func(line string) {
		emit(api.ProgressEvent{Type: "progress", Status: line, Container: stack.Name})
	}

	return run(ctx, stack, logger)
}

// opStackValidate validates a stack on the agent host.
func (a *Agent) opStackValidate(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req StackRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	if req.Stack.Kind == stacks.KindGitRepo || (req.Stack.GitSource != nil && req.Stack.GitSource.RepoURL != "") {
		a.sendError(ctx, conn, env.RequestID, fmt.Errorf("git-kind stacks are not supported on remote agents"))
		return
	}

	result := stacks.Validate(ctx, req.Stack)
	a.sendResult(ctx, conn, env.RequestID, result)
}

// opStackContainers returns runtime containers associated with an agent stack.
func (a *Agent) opStackContainers(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req StackContainersRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	stack := req.Stack
	containers, err := a.discovery.ListContainers(ctx)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	result := make([]map[string]string, 0, len(containers))
	for _, c := range containers {
		if !stacks.ContainerMatchesStack(stack, c.ID, c.Labels) {
			continue
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		result = append(result, map[string]string{
			"id":      c.ID,
			"name":    name,
			"service": c.Labels["com.docker.compose.service"],
			"state":   c.State,
			"status":  c.Status,
			"health":  stacks.ContainerHealth(ctx, a.discovery.Client, c.ID),
		})
	}

	a.sendResult(ctx, conn, env.RequestID, result)
}

// opStackDiscover discovers compose projects on the agent host.
func (a *Agent) opStackDiscover(ctx context.Context, conn *websocket.Conn, env Envelope) {
	containers, err := a.discovery.ListContainers(ctx)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	grouped := make(map[string]*StackDiscoverCandidate)
	for _, c := range containers {
		project := c.Labels["com.docker.compose.project"]
		if project == "" {
			continue
		}
		entry, ok := grouped[project]
		if !ok {
			// Labels carry host paths (e.g. /root/docker/umami); translate them
			// through COMPOSE_PATH_MAPPING so the suggested paths are visible
			// inside the agent container (/compose/umami).
			workingDir := stacks.TranslatePathForRuntime(c.Labels["com.docker.compose.project.working_dir"])
			entry = &StackDiscoverCandidate{
				Project:     project,
				WorkingDir:  workingDir,
				ConfigFiles: translateAgentConfigFiles(agentSplitConfigFiles(c.Labels["com.docker.compose.project.config_files"])),
			}
			grouped[project] = entry
		}
		service := c.Labels["com.docker.compose.service"]
		if service != "" && !stacks.Contains(entry.Services, service) {
			entry.Services = append(entry.Services, service)
		}
	}

	out := make([]StackDiscoverCandidate, 0, len(grouped))
	for _, entry := range grouped {
		entry.ComposeFiles = agentSuggestComposeFiles(entry.WorkingDir, entry.ConfigFiles)
		entry.SuggestedComposeFile = stacks.FirstOrEmpty(entry.ComposeFiles)
		entry.SuggestedEnvFile = agentSuggestEnvFile(entry.WorkingDir)
		if a.store != nil {
			_, entry.Registered = a.store.FindForComposeTarget(entry.Project, entry.WorkingDir, stacks.FirstOrEmpty(entry.Services))
		}
		out = append(out, *entry)
	}

	a.sendResult(ctx, conn, env.RequestID, map[string]any{"candidates": out})
}

// Stack file operations. These run on the host that owns the files, so targets
// are resolved against THIS agent's allow-list: the server's list can differ,
// and a path the server accepts may not exist here at all.

// errGitStackUnsupported reports a git-backed stack, which has no local files
// for the agent to edit. The text matches every other agent stack op.
var errGitStackUnsupported = errors.New("git-kind stacks are not supported on remote agents")

// errStackFileInvalidSyntax reports a draft that failed the syntax check, which
// runs before anything touches the disk.
var errStackFileInvalidSyntax = errors.New("file has syntax errors")

// errStackFileValidationFailed reports a draft that was written and then
// rejected by docker, with the previous content already restored.
var errStackFileValidationFailed = errors.New("file failed compose validation")

// errStackFileRollbackFailed reports a draft that was rejected by docker AND
// whose previous content could not be restored. It is deliberately distinct
// from errStackFileValidationFailed: the rejected draft is still on disk, so
// this must never be reported as a successful save.
var errStackFileRollbackFailed = errors.New("file failed compose validation and the previous content could not be restored")

// agentStackFileValidationTimeout bounds the docker call a save makes while it
// holds the project lock. The server bounds the same call identically.
const agentStackFileValidationTimeout = 30 * time.Second

// opStackFileList lists the editable files of an agent-hosted stack.
func (a *Agent) opStackFileList(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req StackFileRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	result, err := a.agentStackFileList(req)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	a.sendResult(ctx, conn, env.RequestID, result)
}

// opStackFileRead returns the content of one editable file.
func (a *Agent) opStackFileRead(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req StackFileRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	result, err := a.agentStackFileRead(req)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	a.sendResult(ctx, conn, env.RequestID, result)
}

// opStackFileValidate syntax-checks draft content without writing it.
func (a *Agent) opStackFileValidate(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req StackFileWriteRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	result, err := a.agentStackFileValidate(req)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	a.sendResult(ctx, conn, env.RequestID, result)
}

// opStackFileWrite saves one editable file on the agent host.
func (a *Agent) opStackFileWrite(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req StackFileWriteRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	result, err := a.agentStackFileWrite(ctx, req)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	a.sendResult(ctx, conn, env.RequestID, result)
}

// agentStackFileTarget refuses git-backed stacks and resolves one of a stack's
// editable files through this agent's allow-list, so the guard runs before any
// read or write. Every file operation resolves through it.
func (a *Agent) agentStackFileTarget(stack stacks.Stack, kind string, index int) (stacks.FileTarget, error) {
	if err := agentRejectGitStack(stack); err != nil {
		return stacks.FileTarget{}, err
	}
	return stacks.ResolveFileTarget(stack, kind, index, a.cfg.AllowedPaths)
}

// agentRejectGitStack refuses git-backed stacks, which have no local files on
// this host.
func agentRejectGitStack(stack stacks.Stack) error {
	if stack.Kind == stacks.KindGitRepo || (stack.GitSource != nil && stack.GitSource.RepoURL != "") {
		return errGitStackUnsupported
	}
	return nil
}

// agentStackFileList reports the stack's editable files. It is read-only: no
// lock, no write. Targets outside this agent's allow-list are listed but
// reported as not editable, so the client can tell "not there" from "not
// allowed".
func (a *Agent) agentStackFileList(req StackFileRequest) (any, error) {
	if err := agentRejectGitStack(req.Stack); err != nil {
		return nil, err
	}
	return stacks.FileTargets(req.Stack, a.cfg.AllowedPaths), nil
}

// agentStackFileRead returns one file's content and the target it read. It is
// read-only: no lock, no write.
func (a *Agent) agentStackFileRead(req StackFileRequest) (any, error) {
	target, err := a.agentStackFileTarget(req.Stack, req.Kind, req.Index)
	if err != nil {
		return nil, err
	}

	content, err := stacks.ReadEditableFile(target.Path)
	if err != nil {
		return nil, err
	}

	return StackFileResult{Target: target, Content: content}, nil
}

// agentStackFileValidate syntax-checks draft content against one file kind. It
// resolves the target first so a draft for a file this agent may not edit is
// refused, then never touches the disk.
func (a *Agent) agentStackFileValidate(req StackFileWriteRequest) (any, error) {
	if _, err := a.agentStackFileTarget(req.Stack, req.Kind, req.Index); err != nil {
		return nil, err
	}
	return stacks.ValidateSyntax(req.Kind, req.Content), nil
}

// agentStackFileWrite saves one file and returns the same success payload the
// local server returns ({"target": ...}).
//
// The order is the safety property:
//  1. size cap, so an oversized draft cannot be written - the server's first
//     refusal too, so a draft that is both oversized and unparseable gets the
//     same answer on either host;
//  2. syntax check, so an unparseable draft never reaches the disk;
//  3. project lock, so a save cannot interleave with a deploy of the project;
//  4. backup read INSIDE the lock - a backup taken before the lock could race a
//     concurrent write and would then restore stale content;
//  5. atomic write;
//  6. semantic validation under a bounded context, because an unbounded docker
//     call would hold the project lock and stall every other op on it;
//  7. restore the backup when validation rejects the draft. A restore that
//     itself fails returns errStackFileRollbackFailed, never success: at that
//     point the rejected draft is what remains on disk.
func (a *Agent) agentStackFileWrite(ctx context.Context, req StackFileWriteRequest) (any, error) {
	target, err := a.agentStackFileTarget(req.Stack, req.Kind, req.Index)
	if err != nil {
		return nil, err
	}

	if len(req.Content) > stacks.MaxEditableFileBytes {
		return nil, fmt.Errorf("%w: content exceeds the %d byte limit", stacks.ErrFileTooLarge, stacks.MaxEditableFileBytes)
	}

	if syntax := stacks.ValidateSyntax(req.Kind, req.Content); !syntax.Valid {
		// ValidateSyntax appends at least one positioned error whenever it
		// reports a draft as invalid, so the first is what stopped this save.
		return nil, fmt.Errorf("%w: %s", errStackFileInvalidSyntax, syntax.Errors[0].Message)
	}

	unlock := engine.LockProject(stackProjectName(req.Stack))
	defer unlock()

	previous, err := stacks.ReadEditableFile(target.Path)
	if err != nil {
		return nil, err
	}

	if err := stacks.WriteFileAtomic(target.Path, req.Content); err != nil {
		return nil, err
	}

	// Validate reads the file back from disk, so it checks what was just
	// written rather than the draft in memory.
	validationCtx, cancel := context.WithTimeout(ctx, agentStackFileValidationTimeout)
	validation := stacks.Validate(validationCtx, req.Stack)
	cancel()

	if !validation.Valid {
		if restoreErr := stacks.WriteFileAtomic(target.Path, previous); restoreErr != nil {
			return nil, fmt.Errorf("%w: %v", errStackFileRollbackFailed, restoreErr)
		}
		return nil, fmt.Errorf("%w: %s", errStackFileValidationFailed, strings.Join(validation.Issues, "; "))
	}

	return map[string]any{"target": target}, nil
}

// opStackAction runs deploy/pull/restart/down on the agent host, streaming logs.
func (a *Agent) opStackAction(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var req StackActionRequest
	if err := env.Decode(&req); err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	stack := req.Stack
	if stack.Kind == stacks.KindGitRepo || (stack.GitSource != nil && stack.GitSource.RepoURL != "") {
		a.sendError(ctx, conn, env.RequestID, fmt.Errorf("git-kind stacks are not supported on remote agents"))
		return
	}

	emit := func(line string) {
		a.sendProgress(ctx, conn, env.RequestID, ProgressData{
			ProgressType: ProgressStack,
			Line:         line,
			Stack:        stack.Name,
			Action:       req.Action,
		})
	}

	var run func(context.Context, stacks.Stack, stacks.Logger) error
	switch req.Action {
	case "deploy":
		run = stacks.Deploy
	case "pull":
		run = stacks.Pull
	case "restart":
		run = stacks.Restart
	case "stop":
		run = stacks.Stop
	case "start":
		run = stacks.Start
	case "down":
		run = stacks.Down
	default:
		a.sendError(ctx, conn, env.RequestID, fmt.Errorf("unsupported stack action: %s", req.Action))
		return
	}

	unlock := engine.LockProject(stackProjectName(stack))
	defer unlock()

	err := run(ctx, stack, emit)
	if err != nil {
		a.sendError(ctx, conn, env.RequestID, err)
		return
	}

	a.sendResult(ctx, conn, env.RequestID, StackActionResult{Success: true, Action: req.Action})
}

// opStackList returns stacks hosted on this agent (from the server store).
func (a *Agent) opStackList(ctx context.Context, conn *websocket.Conn, env Envelope) {
	a.sendError(ctx, conn, env.RequestID, fmt.Errorf("stack listing is server-side"))
}

// opStackGet returns stack details from the agent store.
func (a *Agent) opStackGet(ctx context.Context, conn *websocket.Conn, env Envelope) {
	a.sendError(ctx, conn, env.RequestID, fmt.Errorf("stack details are server-side"))
}

// opStackCreate registers a stack in the agent store.
func (a *Agent) opStackCreate(ctx context.Context, conn *websocket.Conn, env Envelope) {
	a.sendError(ctx, conn, env.RequestID, fmt.Errorf("stack registration is server-side"))
}

// opStackUpdate updates a stack in the agent store.
func (a *Agent) opStackUpdate(ctx context.Context, conn *websocket.Conn, env Envelope) {
	a.sendError(ctx, conn, env.RequestID, fmt.Errorf("stack updates are server-side"))
}

// opStackDelete removes a stack from the agent store.
func (a *Agent) opStackDelete(ctx context.Context, conn *websocket.Conn, env Envelope) {
	a.sendError(ctx, conn, env.RequestID, fmt.Errorf("stack deletes are server-side"))
}

// opStackHistory returns stack history from the agent store.
func (a *Agent) opStackHistory(ctx context.Context, conn *websocket.Conn, env Envelope) {
	a.sendError(ctx, conn, env.RequestID, fmt.Errorf("stack history is server-side"))
}

func agentSuggestComposeFile(workingDir string) string {
	return stacks.FirstOrEmpty(agentSuggestComposeFiles(workingDir, nil))
}

// agentSuggestComposeFiles returns the compose file(s) actually used by a
// running project on the agent host. The authoritative source is the
// com.docker.compose.project.config_files label (comma-separated, present since
// Compose v2.20), which holds the exact paths even for unusual file names and is
// written by Compose on the daemon host. Label paths are trusted as-is and are
// NOT existence-checked here: the agent container only has its configured mounts
// (COMPOSE_PATH_MAPPING), so a valid host path like /root/docker/gotify may
// legitimately fail os.Stat inside the agent container. When the label is
// missing the helper falls back to probing the standard compose file names under
// workingDir, and returns an empty slice when nothing is found.
func agentSuggestComposeFiles(workingDir string, configFiles []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(configFiles))

	for _, rawPath := range configFiles {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}

	if len(result) > 0 {
		return result
	}

	if strings.TrimSpace(workingDir) == "" {
		return nil
	}

	for _, name := range []string{"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"} {
		p := agentJoinPath(workingDir, name)
		if _, err := os.Stat(p); err == nil {
			result = append(result, p)
		}
	}

	return result
}

// agentSplitConfigFiles splits the raw com.docker.compose.project.config_files
// label value into individual paths, trimming whitespace and dropping empties.
func agentSplitConfigFiles(rawValue string) []string {
	if strings.TrimSpace(rawValue) == "" {
		return nil
	}
	parts := strings.Split(rawValue, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// translateAgentConfigFiles maps host-side config file paths through
// COMPOSE_PATH_MAPPING so they resolve inside the agent container.
func translateAgentConfigFiles(configFiles []string) []string {
	if len(configFiles) == 0 {
		return nil
	}
	result := make([]string, 0, len(configFiles))
	for _, path := range configFiles {
		result = append(result, stacks.TranslatePathForRuntime(path))
	}
	return result
}

func agentSuggestEnvFile(workingDir string) string {
	if strings.TrimSpace(workingDir) == "" {
		return ""
	}
	p := agentJoinPath(workingDir, ".env")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func agentJoinPath(base, leaf string) string {
	if base == "" {
		return leaf
	}
	if strings.Contains(base, "\\") {
		return strings.TrimRight(base, "\\/") + `\` + strings.TrimLeft(leaf, "\\/")
	}
	if strings.HasSuffix(base, "/") {
		return base + leaf
	}
	return base + "/" + leaf
}

func stackProjectName(stack stacks.Stack) string {
	if stack.Discovery.ComposeProject != "" {
		return stack.Discovery.ComposeProject
	}
	if stack.ProjectName != "" {
		return stack.ProjectName
	}
	return stack.ID
}
