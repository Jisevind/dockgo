package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

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

	stdoutWriter := &streamWriter{cb: emitLine}
	stderrWriter := &streamWriter{cb: emitLine}

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

// streamWriter buffers bytes and emits complete lines.
type streamWriter struct {
	cb  func(string)
	buf []byte
}

func (sw *streamWriter) Write(p []byte) (n int, err error) {
	sw.buf = append(sw.buf, p...)

	for {
		idx := bytes.IndexByte(sw.buf, '\n')
		if idx == -1 {
			break
		}

		line := sw.buf[:idx]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		sw.cb(string(line))
		sw.buf = sw.buf[idx+1:]
	}

	return len(p), nil
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
		if !agentContainerMatchesStack(stack, c) {
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
			"health":  a.containerHealth(ctx, c.ID),
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
		if service != "" && !agentContains(entry.Services, service) {
			entry.Services = append(entry.Services, service)
		}
	}

	out := make([]StackDiscoverCandidate, 0, len(grouped))
	for _, entry := range grouped {
		entry.ComposeFiles = agentSuggestComposeFiles(entry.WorkingDir, entry.ConfigFiles)
		entry.SuggestedComposeFile = agentFirstOrEmpty(entry.ComposeFiles)
		entry.SuggestedEnvFile = agentSuggestEnvFile(entry.WorkingDir)
		if a.store != nil {
			_, entry.Registered = a.store.FindForComposeTarget(entry.Project, entry.WorkingDir, agentFirstOrEmpty(entry.Services))
		}
		out = append(out, *entry)
	}

	a.sendResult(ctx, conn, env.RequestID, map[string]any{"candidates": out})
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

func agentContainerMatchesStack(stack stacks.Stack, c container.Summary) bool {
	project := stack.Discovery.ComposeProject
	if project == "" {
		project = stack.ProjectName
	}
	if project == "" || c.Labels["com.docker.compose.project"] != project {
		return false
	}

	// Explicit ownership: the container ID is already recorded as managed.
	for _, ownedID := range stack.ManagedContainers {
		if ownedID == c.ID {
			return true
		}
	}

	// Discovery matching (mirrors the server's containerMatchesStackProject):
	// a container belongs to the stack if its compose project matches and its
	// working dir or service name matches the stack's. This allows reconcile
	// and ownership discovery to work for stacks with no managed containers yet.
	workingDir := strings.TrimSpace(c.Labels["com.docker.compose.project.working_dir"])
	if workingDir != "" {
		candidates := []string{
			normalizeComparePath(stack.WorkingDir),
			normalizeComparePath(stacks.ResolvePathForRuntime(stack, stack.WorkingDir)),
		}
		labelPath := normalizeComparePath(workingDir)
		for _, candidate := range candidates {
			if candidate != "" && candidate == labelPath {
				return true
			}
		}
	}

	service := strings.TrimSpace(c.Labels["com.docker.compose.service"])
	if service != "" {
		for _, serviceName := range stack.Discovery.ServiceNames {
			if strings.EqualFold(strings.TrimSpace(serviceName), service) {
				return true
			}
		}
	}

	return len(stack.Discovery.ServiceNames) == 0 && workingDir == ""
}

// normalizeComparePath normalizes a path for case-insensitive comparison,
// matching the server's normalizeComparePath helper.
func normalizeComparePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimRight(path, "/")
	return strings.ToLower(path)
}

func agentContains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func agentFirstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// agentSuggestComposeFile returns the first suggested compose file for a
// working dir, or empty when none is found. It never fabricates a path.
func agentSuggestComposeFile(workingDir string) string {
	return agentFirstOrEmpty(agentSuggestComposeFiles(workingDir, nil))
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

func (a *Agent) containerHealth(ctx context.Context, containerID string) string {
	if a.discovery == nil || a.discovery.Client == nil || containerID == "" {
		return ""
	}
	inspect, err := a.discovery.Client.ContainerInspect(ctx, containerID)
	if err != nil || inspect.State == nil || inspect.State.Health == nil {
		return ""
	}
	return inspect.State.Health.Status
}
