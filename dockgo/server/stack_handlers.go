package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"dockgo/stacks"

	"github.com/docker/docker/api/types"
)

type stackPayload struct {
	Name         string                   `json:"name"`
	ProjectName  string                   `json:"project_name"`
	Kind         stacks.Kind              `json:"kind"`
	ComposeFiles []string                 `json:"compose_files"`
	EnvFiles     []string                 `json:"env_files"`
	WorkingDir   string                   `json:"working_dir"`
	Profiles     []string                 `json:"profiles"`
	ProjectEnv   map[string]string        `json:"project_env"`
	PathMode     stacks.PathMode          `json:"path_mode"`
	PathMappings []stacks.PathMapping     `json:"path_mappings"`
	UpdatePolicy *stacks.UpdatePolicy     `json:"update_policy"`
	HealthPolicy *stacks.HealthPolicy     `json:"health_policy"`
	Discovery    stacks.DiscoverySelector `json:"discovery_selector"`
	GitSource    *stacks.GitSource        `json:"git_source"`
	Labels       map[string]string        `json:"labels"`
}

type stackDetailResponse struct {
	Stack          stacks.Stack             `json:"stack"`
	Validation     *stacks.ValidationResult `json:"validation,omitempty"`
	ResolvedPaths  map[string]any           `json:"resolved_paths,omitempty"`
	Containers     []map[string]string      `json:"containers,omitempty"`
	StatusSummary  map[string]any           `json:"status_summary,omitempty"`
	HistorySummary *stacks.HistorySummary   `json:"history_summary,omitempty"`
}

type stackDiscoverCandidate struct {
	Project              string   `json:"project"`
	WorkingDir           string   `json:"working_dir"`
	Services             []string `json:"services"`
	Registered           bool     `json:"registered"`
	SuggestedComposeFile string   `json:"suggested_compose_file,omitempty"`
	SuggestedEnvFile     string   `json:"suggested_env_file,omitempty"`
}

func (s *Server) handleStacks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		stackList := s.StackStore.List()
		type stackListItem struct {
			Stack          stacks.Stack          `json:"stack"`
			RecentHistory  []stacks.HistoryEntry `json:"recent_history"`
			StatusSummary  map[string]any        `json:"status_summary,omitempty"`
			HistorySummary stacks.HistorySummary `json:"history_summary"`
		}
		items := make([]stackListItem, 0, len(stackList))
		for _, stack := range stackList {
			items = append(items, stackListItem{
				Stack:          stack,
				RecentHistory:  s.StackHistory.ListByStack(stack.ID, 3),
				StatusSummary:  s.stackStatusSummary(r.Context(), stack),
				HistorySummary: s.StackHistory.SummarizeByStack(stack.ID),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"stacks": items,
		})
	case http.MethodPost:
		var payload stackPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		stack := stackFromPayload(stacks.Stack{}, payload)
		validation := s.validateStackWithRuntime(context.Background(), stack)
		if !validation.Valid {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":      "stack validation failed",
				"validation": validation,
			})
			return
		}

		saved, err := s.StackStore.Save(stack)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.recordStackHistory(saved, "register", "success", "stack registered")

		writeJSON(w, http.StatusCreated, stackDetailResponse{
			Stack:      saved,
			Validation: validationPtr(validation),
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleStackByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/stacks/")
	path = strings.Trim(path, "/")
	if path == "" {
		writeError(w, http.StatusNotFound, "stack id required")
		return
	}

	if path == "discover" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleStackDiscover(w, r)
		return
	}

	parts := strings.Split(path, "/")
	id := parts[0]

	stack, ok := s.StackStore.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "stack not found")
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			associatedContainers := s.stackAssociatedContainers(r.Context(), stack)
			validation := s.validateStackWithRuntime(r.Context(), stack)
			writeJSON(w, http.StatusOK, stackDetailResponse{
				Stack:      stack,
				Validation: validationPtr(validation),
				ResolvedPaths: map[string]any{
					"working_dir":         stack.WorkingDir,
					"runtime_working_dir": stacks.ResolvePathForRuntime(stack, stack.WorkingDir),
					"compose_files": mapPaths(stack.ComposeFiles, func(path string) string {
						return stacks.ResolvePathForRuntime(stack, path)
					}),
					"env_files": mapPaths(stack.EnvFiles, func(path string) string {
						return stacks.ResolvePathForRuntime(stack, path)
					}),
				},
				Containers:     associatedContainers,
				StatusSummary:  s.stackStatusSummary(r.Context(), stack),
				HistorySummary: validationHistorySummary(s.StackHistory, stack.ID),
			})
		case http.MethodPut:
			var payload stackPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			updatedInput := stackFromPayload(stack, payload)
			validation := s.validateStackWithRuntime(context.Background(), updatedInput)
			if !validation.Valid {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error":      "stack validation failed",
					"validation": validation,
				})
				return
			}

			updated, err := s.StackStore.Save(updatedInput)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.recordStackHistory(updated, "edit", "success", "stack updated")

			writeJSON(w, http.StatusOK, stackDetailResponse{
				Stack:      updated,
				Validation: validationPtr(validation),
			})
		case http.MethodDelete:
			if err := s.StackStore.Delete(id); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.recordStackHistory(stack, "delete", "success", "stack unregistered")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	if len(parts) == 2 && parts[1] == "validate" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		result := s.validateStackWithRuntime(ctx, stack)
		if result.Valid {
			s.recordStackHistory(stack, "validate", "success", "stack validation passed")
		} else {
			s.recordStackHistory(stack, "validate", "error", strings.Join(result.Issues, "; "), result.Issues)
		}
		writeJSON(w, http.StatusOK, result)
		return
	}

	if len(parts) == 2 && parts[1] == "deploy" {
		s.handleStackActionStream(w, r, stack, "deploy", "deployment", 10*time.Minute, stacks.Deploy)
		return
	}

	if len(parts) == 2 && parts[1] == "pull" {
		s.handleStackActionStream(w, r, stack, "pull", "image pull", 10*time.Minute, stacks.Pull)
		return
	}

	if len(parts) == 2 && parts[1] == "restart" {
		s.handleStackActionStream(w, r, stack, "restart", "restart", 5*time.Minute, stacks.Restart)
		return
	}

	if len(parts) == 2 && parts[1] == "down" {
		s.handleStackActionStream(w, r, stack, "down", "shutdown", 5*time.Minute, stacks.Down)
		return
	}

	if len(parts) == 2 && parts[1] == "reconcile" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		if err := s.syncStackManagedContainers(ctx, stack.ID); err != nil {
			s.recordStackHistory(stack, "reconcile", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}

		updated, ok := s.StackStore.Get(stack.ID)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "stack not found after reconcile"})
			return
		}

		s.recordStackHistory(updated, "reconcile", "success", "stack ownership reconciled")
		writeJSON(w, http.StatusOK, stackDetailResponse{
			Stack:          updated,
			Validation:     validationPtr(s.validateStackWithRuntime(ctx, updated)),
			Containers:     s.stackAssociatedContainers(ctx, updated),
			StatusSummary:  s.stackStatusSummary(ctx, updated),
			HistorySummary: validationHistorySummary(s.StackHistory, updated.ID),
		})
		return
	}

	if len(parts) == 2 && parts[1] == "history" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		limit := 20
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"entries": s.StackHistory.ListByStackFiltered(stack.ID, stacks.HistoryFilter{
				Action: strings.TrimSpace(r.URL.Query().Get("action")),
				Status: strings.TrimSpace(r.URL.Query().Get("status")),
				Source: strings.TrimSpace(r.URL.Query().Get("source")),
				Limit:  limit,
			}),
		})
		return
	}

	writeError(w, http.StatusNotFound, "route not found")
}

func (s *Server) handleStackDiscover(w http.ResponseWriter, r *http.Request) {
	containers, err := s.Discovery.ListContainers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"candidates": buildStackDiscoverCandidates(containers, s.StackStore, s.suggestComposeFile, s.suggestEnvFile),
	})
}

func buildStackDiscoverCandidates(
	containers []types.Container,
	store *stacks.Store,
	suggestComposeFile func(string) string,
	suggestEnvFile func(string) string,
) []stackDiscoverCandidate {
	grouped := make(map[string]*stackDiscoverCandidate)

	for _, c := range containers {
		project := c.Labels["com.docker.compose.project"]
		if project == "" {
			continue
		}

		entry, ok := grouped[project]
		if !ok {
			entry = &stackDiscoverCandidate{
				Project:    project,
				WorkingDir: c.Labels["com.docker.compose.project.working_dir"],
			}
			grouped[project] = entry
		}

		service := c.Labels["com.docker.compose.service"]
		if service != "" && !contains(entry.Services, service) {
			entry.Services = append(entry.Services, service)
		}
	}

	out := make([]stackDiscoverCandidate, 0, len(grouped))
	for _, entry := range grouped {
		entry.SuggestedComposeFile = suggestComposeFile(entry.WorkingDir)
		entry.SuggestedEnvFile = suggestEnvFile(entry.WorkingDir)
		if store != nil {
			_, entry.Registered = store.FindForComposeTarget(entry.Project, entry.WorkingDir, firstOrEmpty(entry.Services))
		}
		out = append(out, *entry)
	}

	return out
}

func stackFromPayload(existing stacks.Stack, payload stackPayload) stacks.Stack {
	stack := existing
	stack.Name = payload.Name
	stack.ProjectName = payload.ProjectName
	stack.Kind = payload.Kind
	stack.ComposeFiles = payload.ComposeFiles
	stack.EnvFiles = payload.EnvFiles
	stack.WorkingDir = payload.WorkingDir
	stack.Profiles = payload.Profiles
	stack.ProjectEnv = payload.ProjectEnv
	stack.PathMode = payload.PathMode
	stack.PathMappings = payload.PathMappings
	stack.Discovery = payload.Discovery
	stack.GitSource = payload.GitSource
	stack.Labels = payload.Labels

	if payload.UpdatePolicy != nil {
		stack.UpdatePolicy = *payload.UpdatePolicy
	}
	if payload.HealthPolicy != nil {
		stack.HealthPolicy = *payload.HealthPolicy
	}

	if stack.Kind == "" {
		stack.Kind = stacks.KindComposeFiles
	}
	if stack.PathMode == "" {
		stack.PathMode = stacks.PathModeHostNative
	}
	if stack.UpdatePolicy == (stacks.UpdatePolicy{}) {
		stack.UpdatePolicy = stacks.DefaultUpdatePolicy()
	}
	if stack.HealthPolicy == (stacks.HealthPolicy{}) {
		stack.HealthPolicy = stacks.DefaultHealthPolicy()
	}

	return stack
}

func validationPtr(result stacks.ValidationResult) *stacks.ValidationResult {
	return &result
}

func validationHistorySummary(store *stacks.HistoryStore, stackID string) *stacks.HistorySummary {
	if store == nil {
		return nil
	}
	summary := store.SummarizeByStack(stackID)
	return &summary
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func normalizeComparePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimRight(path, "/")
	return strings.ToLower(path)
}

func (s *Server) suggestComposeFile(workingDir string) string {
	if strings.TrimSpace(workingDir) == "" {
		return ""
	}

	candidates := []string{
		"compose.yml",
		"compose.yaml",
		"docker-compose.yml",
		"docker-compose.yaml",
	}

	for _, name := range candidates {
		hostPath := joinPathForDiscovery(workingDir, name)
		if discoveryPathExists(hostPath) {
			return hostPath
		}
	}

	return joinPathForDiscovery(workingDir, "docker-compose.yml")
}

func (s *Server) suggestEnvFile(workingDir string) string {
	if strings.TrimSpace(workingDir) == "" {
		return ""
	}

	envPath := joinPathForDiscovery(workingDir, ".env")
	if discoveryPathExists(envPath) {
		return envPath
	}
	return ""
}

func joinPathForDiscovery(basePath string, leaf string) string {
	if basePath == "" {
		return leaf
	}

	if strings.Contains(basePath, "\\") {
		return strings.TrimRight(basePath, "\\/") + `\` + strings.TrimLeft(leaf, "\\/")
	}

	return filepath.Clean(filepath.Join(basePath, leaf))
}

func discoveryPathExists(path string) bool {
	if path == "" {
		return false
	}
	if _, err := os.Stat(path); err == nil {
		return true
	}

	pathMode := stacks.PathModeHostNative
	if looksLikeWindowsPath(path) {
		pathMode = stacks.PathModeMapped
	}

	resolvedPath := stacks.ResolvePathForRuntime(stacks.Stack{PathMode: pathMode}, path)
	if resolvedPath == path {
		return false
	}

	_, err := os.Stat(resolvedPath)
	return err == nil
}

func looksLikeWindowsPath(path string) bool {
	return len(path) >= 3 &&
		((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
		path[1] == ':' &&
		(path[2] == '\\' || path[2] == '/')
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) handleStackActionStream(
	w http.ResponseWriter,
	r *http.Request,
	stack stacks.Stack,
	action string,
	actionLabel string,
	timeout time.Duration,
	run func(context.Context, stacks.Stack, stacks.Logger) error,
) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	statusSummary := s.stackStatusSummary(r.Context(), stack)
	if blocked, reason := blockedStackActionReason(statusSummary, action); blocked {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":          reason,
			"status_summary": statusSummary,
		})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	startBytes, _ := json.Marshal(map[string]any{
		"type":    "start",
		"message": fmt.Sprintf("Starting stack %s...", actionLabel),
		"stack":   stack.Name,
		"action":  action,
	})
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(startBytes)
	_, _ = w.Write([]byte("\n\n"))
	flusher.Flush()

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	var writeMu sync.Mutex
	emit := func(payload map[string]any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		bytes, _ := json.Marshal(payload)
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(bytes)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
	}

	err := s.executeStackAction(ctx, stack, action, "stacks_view", run, func(line string) {
		emit(map[string]any{
			"type":   "progress",
			"status": line,
			"stack":  stack.Name,
			"action": action,
		})
	})
	if err != nil {
		emit(map[string]any{
			"type":   "error",
			"error":  err.Error(),
			"stack":  stack.Name,
			"action": action,
		})
		return
	}

	emit(map[string]any{
		"type":    "done",
		"success": true,
		"stack":   stack.Name,
		"action":  action,
	})
}

func blockedStackActionReason(statusSummary map[string]any, action string) (bool, string) {
	if statusSummary == nil {
		return false, ""
	}

	state, _ := statusSummary["state"].(string)
	if state != "drifted" && state != "unbound" {
		return false, ""
	}

	switch action {
	case "pull", "restart", "down":
		return true, fmt.Sprintf("stack action '%s' is blocked while the stack is %s; deploy or reconcile the stack first", action, state)
	default:
		return false, ""
	}
}

func (s *Server) executeStackAction(
	ctx context.Context,
	stack stacks.Stack,
	action string,
	source string,
	run func(context.Context, stacks.Stack, stacks.Logger) error,
	onLine func(string),
) error {
	startedAt := time.Now().UTC()
	lines := make([]string, 0, 50)
	logger := func(line string) {
		if len(lines) < 50 {
			lines = append(lines, line)
		}
		if onLine != nil {
			onLine(line)
		}
	}

	err := run(ctx, stack, logger)
	completedAt := time.Now().UTC()
	if err != nil {
		if action == "deploy" && s.StackStore != nil {
			_ = s.StackStore.RecordDeployStatus(stack.ID, "error", time.Now().UTC())
		}
		s.recordStackHistoryEntry(stacks.HistoryEntry{
			StackID:     stack.ID,
			StackName:   stack.Name,
			Action:      action,
			Status:      "error",
			Source:      source,
			Message:     err.Error(),
			Details:     lines,
			StartedAt:   startedAt,
			CompletedAt: completedAt,
		})
		return err
	}

	if action == "deploy" && s.StackStore != nil {
		_ = s.StackStore.RecordDeployStatus(stack.ID, "success", time.Now().UTC())
		_ = s.syncStackManagedContainers(ctx, stack.ID)
	}
	s.recordStackHistoryEntry(stacks.HistoryEntry{
		StackID:     stack.ID,
		StackName:   stack.Name,
		Action:      action,
		Status:      "success",
		Source:      source,
		Message:     fmt.Sprintf("stack %s completed", action),
		Details:     lines,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
	})
	return nil
}

func (s *Server) syncStackManagedContainers(ctx context.Context, stackID string) error {
	if s.StackStore == nil || s.Discovery == nil {
		return nil
	}

	stack, ok := s.StackStore.Get(stackID)
	if !ok {
		return fmt.Errorf("stack not found")
	}

	containers, err := s.Discovery.ListContainers(ctx)
	if err != nil {
		return err
	}

	containerIDs := make([]string, 0)
	for _, c := range containers {
		if containerMatchesStackProject(stack, c) {
			containerIDs = append(containerIDs, c.ID)
		}
	}

	return s.StackStore.RecordManagedContainers(stackID, containerIDs, time.Now().UTC())
}

func (s *Server) validateStackWithRuntime(ctx context.Context, stack stacks.Stack) stacks.ValidationResult {
	result := stacks.Validate(ctx, stack)
	result.Warnings = append(result.Warnings, s.stackDriftWarnings(ctx, stack)...)
	return result
}

func (s *Server) stackDriftWarnings(ctx context.Context, stack stacks.Stack) []string {
	if s.Discovery == nil {
		return nil
	}

	project := stack.Discovery.ComposeProject
	if project == "" {
		project = stack.ProjectName
	}
	if project == "" {
		return nil
	}

	containers, err := s.Discovery.ListContainers(ctx)
	if err != nil {
		return []string{fmt.Sprintf("runtime drift check failed to list containers: %v", err)}
	}

	runtimeServices := make(map[string]struct{})
	runtimeWorkingDirs := make(map[string]struct{})
	for _, c := range containers {
		if c.Labels["com.docker.compose.project"] != project {
			continue
		}
		if service := strings.TrimSpace(c.Labels["com.docker.compose.service"]); service != "" {
			runtimeServices[service] = struct{}{}
		}
		if workingDir := strings.TrimSpace(c.Labels["com.docker.compose.project.working_dir"]); workingDir != "" {
			runtimeWorkingDirs[normalizeComparePath(workingDir)] = struct{}{}
		}
	}

	if len(runtimeServices) == 0 && len(runtimeWorkingDirs) == 0 {
		return nil
	}

	savedServices, err := stacks.ResolvedComposeServices(ctx, stack)
	if err != nil {
		warnings := compareStackRuntimeState(stack.WorkingDir, runtimeWorkingDirs, nil, runtimeServices)
		warnings = append(warnings, fmt.Sprintf("runtime drift check could not resolve saved compose services: %v", err))
		return warnings
	}

	return compareStackRuntimeState(stack.WorkingDir, runtimeWorkingDirs, savedServices, runtimeServices)
}

func compareStackRuntimeState(
	registeredWorkingDir string,
	runtimeWorkingDirs map[string]struct{},
	savedServices []string,
	runtimeServices map[string]struct{},
) []string {
	warnings := make([]string, 0)

	if len(runtimeWorkingDirs) > 1 {
		warnings = append(warnings, "runtime compose project reports multiple working directories; project labels may be inconsistent")
	} else if len(runtimeWorkingDirs) == 1 {
		for runtimeWorkingDir := range runtimeWorkingDirs {
			if runtimeWorkingDir != normalizeComparePath(registeredWorkingDir) {
				warnings = append(warnings, fmt.Sprintf("runtime working directory differs from registered stack: %s", registeredWorkingDir))
			}
		}
	}

	if len(savedServices) == 0 || len(runtimeServices) == 0 {
		return warnings
	}

	savedServiceSet := make(map[string]struct{}, len(savedServices))
	for _, service := range savedServices {
		savedServiceSet[strings.TrimSpace(service)] = struct{}{}
	}

	for runtimeService := range runtimeServices {
		if _, ok := savedServiceSet[runtimeService]; !ok {
			warnings = append(warnings, fmt.Sprintf("runtime service '%s' is not present in the saved compose config", runtimeService))
		}
	}

	for _, savedService := range savedServices {
		if _, ok := runtimeServices[savedService]; !ok {
			warnings = append(warnings, fmt.Sprintf("saved compose service '%s' is not present among current runtime containers", savedService))
		}
	}

	return warnings
}

func (s *Server) recordStackHistory(stack stacks.Stack, action string, status string, message string, details ...[]string) {
	var detailLines []string
	if len(details) > 0 {
		detailLines = details[0]
	}
	s.recordStackHistoryEntry(stacks.HistoryEntry{
		StackID:   stack.ID,
		StackName: stack.Name,
		Action:    action,
		Status:    status,
		Source:    "system",
		Message:   message,
		Details:   detailLines,
	})
}

func (s *Server) recordStackHistoryEntry(entry stacks.HistoryEntry) {
	if s.StackHistory == nil {
		return
	}
	_ = s.StackHistory.Append(entry)
}

func (s *Server) stackAssociatedContainers(ctx context.Context, stack stacks.Stack) []map[string]string {
	if s.Discovery == nil {
		return nil
	}

	ownedContainers, _, _, err := s.stackRuntimeOwnership(ctx, stack)
	if err != nil {
		return nil
	}

	result := make([]map[string]string, 0)
	for _, c := range ownedContainers {
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
			"health":  s.containerHealthState(ctx, c.ID),
		})
	}

	return result
}

func containerMatchesStackProject(stack stacks.Stack, c types.Container) bool {
	project := stack.Discovery.ComposeProject
	if project == "" {
		project = stack.ProjectName
	}
	if project == "" || c.Labels["com.docker.compose.project"] != project {
		return false
	}

	workingDir := strings.TrimSpace(c.Labels["com.docker.compose.project.working_dir"])
	if workingDir != "" {
		candidatePaths := []string{
			normalizeComparePath(stack.WorkingDir),
			normalizeComparePath(stacks.ResolvePathForRuntime(stack, stack.WorkingDir)),
		}
		labelPath := normalizeComparePath(workingDir)
		for _, candidatePath := range candidatePaths {
			if candidatePath != "" && candidatePath == labelPath {
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

func containerMatchesStackOwnership(stack stacks.Stack, c types.Container) bool {
	for _, ownedID := range stack.ManagedContainers {
		if ownedID == c.ID {
			return true
		}
	}
	return false
}

func (s *Server) resolveContainerStack(c types.Container) (stacks.Stack, bool) {
	if s.StackStore == nil {
		return stacks.Stack{}, false
	}

	if stack, ok := s.StackStore.GetByManagedContainer(c.ID); ok {
		return stack, true
	}
	return stacks.Stack{}, false
}

func (s *Server) stackStatusSummary(ctx context.Context, stack stacks.Stack) map[string]any {
	ownedContainers, extraContainers, missingOwnedIDs, err := s.stackRuntimeOwnership(ctx, stack)
	containers := summarizeContainers(ctx, s, ownedContainers)
	summary := map[string]any{
		"state":              "unknown",
		"message":            "No associated containers found.",
		"total":              len(containers),
		"running":            0,
		"healthy":            0,
		"unhealthy":          0,
		"stopped":            0,
		"degraded":           0,
		"containers":         containers,
		"ownership_mode":     "unbound",
		"managed_total":      len(stack.ManagedContainers),
		"missing_containers": missingOwnedIDs,
		"extra_containers":   summarizeContainers(ctx, s, extraContainers),
		"issues":             []string{},
	}
	if len(stack.ManagedContainers) > 0 {
		summary["ownership_mode"] = "managed"
	}
	if err != nil {
		summary["state"] = "unknown"
		summary["message"] = "Failed to inspect stack runtime state."
		summary["issues"] = []string{fmt.Sprintf("runtime inspection failed: %v", err)}
		return summary
	}

	if len(stack.ManagedContainers) == 0 {
		summary["state"] = "unbound"
		summary["message"] = "Stack has no managed containers yet. Deploy or reconcile to establish ownership."
		summary["issues"] = []string{"No managed containers are recorded for this stack."}
		return summary
	}

	if len(containers) == 0 {
		if len(missingOwnedIDs) > 0 {
			summary["state"] = "drifted"
			summary["message"] = "Stack ownership drift detected."
			summary["issues"] = stackOwnershipIssues(missingOwnedIDs, extraContainers)
		}
		return summary
	}

	running := 0
	healthy := 0
	unhealthy := 0
	stopped := 0
	degraded := 0

	for _, container := range containers {
		state := container["state"]
		health := container["health"]

		if state == "running" {
			running++
		} else {
			stopped++
		}

		switch health {
		case "healthy":
			healthy++
		case "unhealthy":
			unhealthy++
		case "starting":
			degraded++
		}
	}

	summary["running"] = running
	summary["healthy"] = healthy
	summary["unhealthy"] = unhealthy
	summary["stopped"] = stopped
	summary["degraded"] = degraded

	switch {
	case len(missingOwnedIDs) > 0 || len(extraContainers) > 0:
		summary["state"] = "drifted"
		summary["message"] = "Stack ownership drift detected."
	case running == 0:
		summary["state"] = "down"
		summary["message"] = "All stack containers are stopped."
	case stopped > 0 || unhealthy > 0:
		summary["state"] = "degraded"
		summary["message"] = "Some stack containers are stopped or unhealthy."
	case degraded > 0:
		summary["state"] = "starting"
		summary["message"] = "Stack containers are starting or waiting for healthchecks."
	default:
		summary["state"] = "running"
		if healthy > 0 {
			summary["message"] = "All stack containers are running and healthy."
		} else {
			summary["message"] = "All stack containers are running."
		}
	}

	summary["issues"] = stackOwnershipIssues(missingOwnedIDs, extraContainers)

	return summary
}

func (s *Server) stackRuntimeOwnership(ctx context.Context, stack stacks.Stack) ([]types.Container, []types.Container, []string, error) {
	if s.Discovery == nil {
		return nil, nil, nil, nil
	}

	containers, err := s.Discovery.ListContainers(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(stack.ManagedContainers) == 0 {
		return nil, nil, nil, nil
	}

	ownedByID := make(map[string]types.Container, len(stack.ManagedContainers))
	for _, c := range containers {
		ownedByID[c.ID] = c
	}

	owned := make([]types.Container, 0, len(stack.ManagedContainers))
	missing := make([]string, 0)
	for _, containerID := range stack.ManagedContainers {
		if c, ok := ownedByID[containerID]; ok {
			owned = append(owned, c)
		} else {
			missing = append(missing, containerID)
		}
	}

	extra := make([]types.Container, 0)
	for _, c := range containers {
		if containsString(stack.ManagedContainers, c.ID) {
			continue
		}
		if containerMatchesStackProject(stack, c) {
			extra = append(extra, c)
		}
	}

	return owned, extra, missing, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func summarizeContainers(ctx context.Context, s *Server, containers []types.Container) []map[string]string {
	result := make([]map[string]string, 0, len(containers))
	for _, c := range containers {
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
			"health":  s.containerHealthState(ctx, c.ID),
		})
	}
	return result
}

func stackOwnershipIssues(missingOwnedIDs []string, extraContainers []types.Container) []string {
	issues := make([]string, 0, len(missingOwnedIDs)+len(extraContainers))
	for _, missingID := range missingOwnedIDs {
		issues = append(issues, fmt.Sprintf("Managed container missing: %s", missingID))
	}
	for _, c := range extraContainers {
		name := c.ID
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		issues = append(issues, fmt.Sprintf("Runtime container not managed by this stack: %s", name))
	}
	return issues
}

func (s *Server) containerHealthState(ctx context.Context, containerID string) string {
	if s.Discovery == nil || s.Discovery.Client == nil || containerID == "" {
		return ""
	}

	inspect, err := s.Discovery.Client.ContainerInspect(ctx, containerID)
	if err != nil || inspect.State == nil || inspect.State.Health == nil {
		return ""
	}

	return inspect.State.Health.Status
}

func mapPaths(values []string, mapper func(string) string) []map[string]string {
	if len(values) == 0 {
		return nil
	}

	result := make([]map[string]string, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]string{
			"host":    value,
			"runtime": mapper(value),
		})
	}
	return result
}
