package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"dockgo/agent"
	"dockgo/stacks"

	"github.com/google/uuid"
)

// handleAgentStacksRoute proxies stack operations for stacks assigned to a
// remote agent. The server store remains the single source of truth; the agent
// executes compose/validation against its local filesystem.
func (s *Server) handleAgentStacksRoute(w http.ResponseWriter, r *http.Request) {
	agentID, ok := agentQueryAgentID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "agent id required")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/stacks/")
	if path == r.URL.Path {
		// No trailing slash: this is the collection route (/api/stacks or
		// /api/agent/:id/stacks).
		path = ""
	}
	path = strings.Trim(path, "/")

	// Discovery happens on the agent host.
	if path == "discover" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.dispatchAgentStackDiscover(w, r, agentID)
		return
	}

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			// List agent-hosted stacks from the central store.
			s.handleAgentStackList(w, r, agentID)
		case http.MethodPost:
			s.handleAgentStackCreate(w, r, agentID)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	parts := strings.Split(path, "/")
	stackID := parts[0]

	stack, ok := s.StackStore.Get(stackID)
	if !ok {
		writeError(w, http.StatusNotFound, "stack not found")
		return
	}
	if stack.AgentID != "" && stack.AgentID != agentID {
		writeError(w, http.StatusNotFound, "stack not found on this agent")
		return
	}

	// A stack with no AgentID is local-only; proxy only agent-hosted stacks.
	if stack.AgentID == "" {
		writeError(w, http.StatusNotFound, "stack is not hosted on an agent")
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.handleAgentStackGet(w, r, agentID, stack)
		case http.MethodPut:
			s.handleAgentStackUpdate(w, r, agentID, stack)
		case http.MethodDelete:
			s.handleAgentStackDelete(w, r, agentID, stack)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	switch parts[1] {
	case "validate":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleAgentStackValidate(w, r, agentID, stack)
	case "deploy", "pull", "restart", "down":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleAgentStackActionStream(w, r, agentID, stack, parts[1])
	case "reconcile":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleAgentStackReconcile(w, r, agentID, stack)
	case "history":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleAgentStackHistory(w, r, agentID, stack)
	default:
		writeError(w, http.StatusNotFound, "route not found")
	}
}

func (s *Server) handleAgentStackList(w http.ResponseWriter, r *http.Request, agentID string) {
	type stackListItem struct {
		Stack          stacks.Stack          `json:"stack"`
		RecentHistory  []stacks.HistoryEntry `json:"recent_history"`
		StatusSummary  map[string]any        `json:"status_summary,omitempty"`
		HistorySummary stacks.HistorySummary `json:"history_summary"`
	}

	items := make([]stackListItem, 0)
	for _, stack := range s.StackStore.List() {
		if stack.AgentID != agentID {
			continue
		}
		statusSummary := s.agentStackStatusSummary(r.Context(), agentID, stack)
		items = append(items, stackListItem{
			Stack:          stack,
			RecentHistory:  s.StackHistory.ListByStack(stack.ID, 3),
			StatusSummary:  statusSummary,
			HistorySummary: s.StackHistory.SummarizeByStack(stack.ID),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"stacks": items})
}

func (s *Server) handleAgentStackCreate(w http.ResponseWriter, r *http.Request, agentID string) {
	var payload stackPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Git-kind stacks are not supported on remote agents.
	if payload.Kind == stacks.KindGitRepo || (payload.GitSource != nil && payload.GitSource.RepoURL != "") {
		writeError(w, http.StatusBadRequest, "git-kind stacks are not supported on remote agents")
		return
	}

	stack := stackFromPayload(stacks.Stack{}, payload)
	stack.AgentID = agentID

	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()
	validation := s.agentValidateStack(ctx, agentID, stack)
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

	// Bind ownership immediately if matching containers are already running on
	// the agent, mirroring the local registration path. Without this, a freshly
	// registered stack stays unbound until the first deploy/reconcile.
	syncCtx, syncCancel := context.WithTimeout(r.Context(), agentOpTimeout)
	s.syncAgentStackManagedContainers(syncCtx, agentID, saved.ID)
	syncCancel()
	if refreshed, ok := s.StackStore.Get(saved.ID); ok {
		saved = refreshed
	}

	s.recordStackHistory(saved, "register", "success", "stack registered on agent "+agentID)
	writeJSON(w, http.StatusCreated, stackDetailResponse{
		Stack:      saved,
		Validation: &validation,
	})
}

func (s *Server) handleAgentStackGet(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	containers := s.agentStackContainers(ctx, agentID, stack)
	validation := s.agentValidateStack(ctx, agentID, stack)

	writeJSON(w, http.StatusOK, stackDetailResponse{
		Stack:      stack,
		Validation: &validation,
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
		Containers:     containers,
		StatusSummary:  s.agentStackStatusSummary(ctx, agentID, stack),
		HistorySummary: validationHistorySummary(s.StackHistory, stack.ID),
	})
}

func (s *Server) handleAgentStackUpdate(w http.ResponseWriter, r *http.Request, agentID string, existing stacks.Stack) {
	var payload stackPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if payload.Kind == stacks.KindGitRepo || (payload.GitSource != nil && payload.GitSource.RepoURL != "") {
		writeError(w, http.StatusBadRequest, "git-kind stacks are not supported on remote agents")
		return
	}

	updated := stackFromPayload(existing, payload)
	updated.AgentID = agentID

	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()
	validation := s.agentValidateStack(ctx, agentID, updated)
	if !validation.Valid {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":      "stack validation failed",
			"validation": validation,
		})
		return
	}

	saved, err := s.StackStore.Save(updated)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.recordStackHistory(saved, "edit", "success", "stack updated")
	writeJSON(w, http.StatusOK, stackDetailResponse{
		Stack:      saved,
		Validation: &validation,
	})
}

func (s *Server) handleAgentStackDelete(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	if err := s.StackStore.Delete(stack.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordStackHistory(stack, "delete", "success", "stack unregistered")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAgentStackValidate(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	result := s.agentValidateStack(ctx, agentID, stack)
	if result.Valid {
		s.recordStackHistory(stack, "validate", "success", "stack validation passed")
	} else {
		s.recordStackHistory(stack, "validate", "error", strings.Join(result.Issues, "; "), result.Issues)
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAgentStackActionStream(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack, action string) {
	actionLabel := action
	switch action {
	case "deploy":
		actionLabel = "deployment"
	case "pull":
		actionLabel = "image pull"
	case "restart":
		actionLabel = "restart"
	case "down":
		actionLabel = "shutdown"
	}

	statusSummary := s.agentStackStatusSummary(r.Context(), agentID, stack)
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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	var writeMu sync.Mutex
	emit := func(payload map[string]any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		bytes, _ := json.Marshal(payload)
		_, _ = w.Write(append(append([]byte("data: "), bytes...), []byte("\n\n")...))
		flusher.Flush()
	}

	doneChan := make(chan struct{})
	var heartbeatWg sync.WaitGroup
	defer func() {
		close(doneChan)
		heartbeatWg.Wait()
	}()

	startSSEHeartbeat(ctx, &writeMu, w, cancel, doneChan, &heartbeatWg)

	req := agent.StackActionRequest{Stack: stack, Action: action}

	onProgress := func(env agent.Envelope) {
		var pd agent.ProgressData
		if err := env.Decode(&pd); err != nil {
			return
		}
		if pd.Line == "" && pd.Progress == nil {
			return
		}
		payload := map[string]any{
			"type":   "progress",
			"stack":  stack.Name,
			"action": action,
		}
		if pd.Line != "" {
			payload["status"] = pd.Line
		} else if pd.Progress != nil {
			payload["status"] = pd.Progress.Status
		}
		emit(payload)
	}

	response, stopRelay, err := s.dispatchToAgent(ctx, agentID, agent.TypeStackAction, req, onProgress)
	if err != nil {
		emit(map[string]any{"type": "error", "error": err.Error(), "stack": stack.Name, "action": action})
		return
	}
	defer stopRelay()

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			emit(map[string]any{"type": "error", "error": "invalid agent response", "stack": stack.Name, "action": action})
			return
		}
		if rd.Error != "" {
			s.recordStackHistory(stack, action, "error", rd.Error)
			emit(map[string]any{"type": "error", "error": rd.Error, "stack": stack.Name, "action": action})
			return
		}

		if action == "deploy" {
			_ = s.StackStore.RecordDeployStatus(stack.ID, "success", time.Now().UTC())
			// Bind the newly deployed containers so the stack is not left
			// unbound after a successful deploy.
			s.syncAgentStackManagedContainers(r.Context(), agentID, stack.ID)
		}
		s.recordStackHistory(stack, action, "success", fmt.Sprintf("stack %s completed", action))
		emit(map[string]any{"type": "done", "success": true, "stack": stack.Name, "action": action})
	case <-ctx.Done():
		s.recordStackHistory(stack, action, "error", "stack action timed out")
		emit(map[string]any{"type": "error", "error": "stack action timed out", "stack": stack.Name, "action": action})
	}
}

// syncAgentStackManagedContainers asks the agent which containers belong to a
// stack and records them as managed, binding ownership. Mirrors the server's
// local syncStackManagedContainers for agent-hosted stacks.
func (s *Server) syncAgentStackManagedContainers(ctx context.Context, agentID string, stackID string) {
	stack, ok := s.StackStore.Get(stackID)
	if !ok {
		return
	}

	req := agent.StackContainersRequest{Stack: stack}
	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeStackContainers, req, nil)
	if err != nil {
		return
	}

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil || rd.Error != "" || rd.Value == nil {
			return
		}
		var containers []map[string]string
		if err := json.Unmarshal(rd.Value, &containers); err != nil {
			return
		}

		ids := make([]string, 0, len(containers))
		for _, c := range containers {
			if id := c["id"]; id != "" {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			return
		}
		if err := s.StackStore.RecordManagedContainers(stackID, ids, time.Now().UTC()); err == nil {
			if updated, ok := s.StackStore.Get(stackID); ok {
				s.recordStackHistory(updated, "reconcile", "success", "stack ownership established from runtime containers")
			}
		}
	case <-ctx.Done():
	}
}

func (s *Server) handleAgentStackReconcile(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	req := agent.StackContainersRequest{Stack: stack}
	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeStackContainers, req, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid agent response")
			return
		}
		if rd.Error != "" {
			writeError(w, http.StatusInternalServerError, rd.Error)
			return
		}

		var containers []map[string]string
		if err := json.Unmarshal(rd.Value, &containers); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid agent containers response")
			return
		}

		ids := make([]string, 0, len(containers))
		for _, c := range containers {
			if id := c["id"]; id != "" {
				ids = append(ids, id)
			}
		}

		if err := s.StackStore.RecordManagedContainers(stack.ID, ids, time.Now().UTC()); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		updated, ok := s.StackStore.Get(stack.ID)
		if !ok {
			writeError(w, http.StatusInternalServerError, "stack not found after reconcile")
			return
		}

		s.recordStackHistory(updated, "reconcile", "success", "stack ownership reconciled")
		writeJSON(w, http.StatusOK, stackDetailResponse{
			Stack:          updated,
			Validation:     validationPtr(s.agentValidateStack(ctx, agentID, updated)),
			Containers:     containers,
			StatusSummary:  s.agentStackStatusSummary(ctx, agentID, updated),
			HistorySummary: validationHistorySummary(s.StackHistory, updated.ID),
		})
	case <-ctx.Done():
		writeError(w, http.StatusGatewayTimeout, "agent request timed out")
	}
}

func (s *Server) handleAgentStackHistory(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	limit := 20
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": s.StackHistory.ListByStackFiltered(stack.ID, stacks.HistoryFilter{
			Action: strings.TrimSpace(r.URL.Query().Get("action")),
			Status: strings.TrimSpace(r.URL.Query().Get("status")),
			Source: strings.TrimSpace(r.URL.Query().Get("source")),
			Limit:  limit,
		}),
	})
}

// agentValidateStack runs stack validation on the agent host.
func (s *Server) agentValidateStack(ctx context.Context, agentID string, stack stacks.Stack) stacks.ValidationResult {
	req := agent.StackRequest{Stack: stack}
	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeStackValidate, req, nil)
	if err != nil {
		return stacks.ValidationResult{
			Valid:  false,
			Issues: []string{fmt.Sprintf("agent unavailable: %v", err)},
		}
	}

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			return stacks.ValidationResult{Valid: false, Issues: []string{"invalid agent response"}}
		}
		if rd.Error != "" {
			return stacks.ValidationResult{Valid: false, Issues: []string{rd.Error}}
		}
		var vr stacks.ValidationResult
		if err := json.Unmarshal(rd.Value, &vr); err != nil {
			return stacks.ValidationResult{Valid: false, Issues: []string{"invalid validation response"}}
		}
		return vr
	case <-ctx.Done():
		return stacks.ValidationResult{Valid: false, Issues: []string{"agent validation timed out"}}
	}
}

// agentStackContainers fetches runtime containers for an agent-hosted stack.
func (s *Server) agentStackContainers(ctx context.Context, agentID string, stack stacks.Stack) []map[string]string {
	req := agent.StackContainersRequest{Stack: stack}
	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeStackContainers, req, nil)
	if err != nil {
		return nil
	}

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			return nil
		}
		if rd.Error != "" || rd.Value == nil {
			return nil
		}
		var containers []map[string]string
		if err := json.Unmarshal(rd.Value, &containers); err != nil {
			return nil
		}
		return containers
	case <-ctx.Done():
		return nil
	}
}

// agentStackStatusSummary computes a status summary for an agent-hosted stack.
func (s *Server) agentStackStatusSummary(ctx context.Context, agentID string, stack stacks.Stack) map[string]any {
	if len(stack.ManagedContainers) == 0 {
		return map[string]any{
			"state":              "unbound",
			"message":            "Stack has no managed containers yet. Deploy or reconcile to establish ownership.",
			"total":              0,
			"running":            0,
			"healthy":            0,
			"unhealthy":          0,
			"stopped":            0,
			"degraded":           0,
			"containers":         []map[string]string{},
			"ownership_mode":     "unbound",
			"managed_total":      0,
			"missing_containers": []string{},
			"extra_containers":   []map[string]string{},
			"issues":             []string{"No managed containers are recorded for this stack."},
		}
	}

	req := agent.StackContainersRequest{Stack: stack}
	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeStackContainers, req, nil)
	if err != nil {
		return map[string]any{
			"state":   "unknown",
			"message": "Failed to inspect stack runtime state.",
			"issues":  []string{fmt.Sprintf("agent unavailable: %v", err)},
		}
	}

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			return map[string]any{"state": "unknown", "message": "Failed to inspect stack runtime state."}
		}
		if rd.Error != "" {
			return map[string]any{"state": "unknown", "message": "Failed to inspect stack runtime state.", "issues": []string{rd.Error}}
		}
		var containers []map[string]string
		if err := json.Unmarshal(rd.Value, &containers); err != nil {
			return map[string]any{"state": "unknown", "message": "Failed to inspect stack runtime state."}
		}

		ownedIDs := make(map[string]bool, len(stack.ManagedContainers))
		for _, id := range stack.ManagedContainers {
			ownedIDs[id] = true
		}

		running, healthy, unhealthy, stopped, degraded := 0, 0, 0, 0, 0
		presentIDs := make([]string, 0, len(containers))
		for _, c := range containers {
			if c["id"] != "" {
				presentIDs = append(presentIDs, c["id"])
			}
			switch c["state"] {
			case "running":
				running++
			default:
				stopped++
			}
			switch c["health"] {
			case "healthy":
				healthy++
			case "unhealthy":
				unhealthy++
			case "starting":
				degraded++
			}
		}

		missing := make([]string, 0)
		for _, id := range stack.ManagedContainers {
			if !stacks.Contains(presentIDs, id) {
				missing = append(missing, id)
			}
		}

		summary := map[string]any{
			"state":              "running",
			"message":            "All stack containers are running.",
			"total":              len(containers),
			"running":            running,
			"healthy":            healthy,
			"unhealthy":          unhealthy,
			"stopped":            stopped,
			"degraded":           degraded,
			"containers":         containers,
			"ownership_mode":     "managed",
			"managed_total":      len(stack.ManagedContainers),
			"missing_containers": missing,
			"extra_containers":   []map[string]string{},
			"issues":             []string{},
		}

		switch {
		case len(missing) > 0:
			summary["state"] = "drifted"
			summary["message"] = "Stack ownership drift detected."
		case running == 0:
			summary["state"] = "down"
			summary["message"] = "All stack containers are stopped."
		case stopped > 0 || unhealthy > 0:
			summary["state"] = "degraded"
			summary["message"] = "Some stack containers are stopped or unhealthy."
		}
		return summary
	case <-ctx.Done():
		return map[string]any{"state": "unknown", "message": "Failed to inspect stack runtime state."}
	}
}

// agentStackRegistered reports whether any stack registered for the given
// agent (or the local host when agentID is empty) matches the discovered
// compose project. Mirrors the server's FindForComposeTarget matching but is
// scoped so discovery for one agent is not confused by stacks registered for
// another host.
func (s *Server) agentStackRegistered(agentID, project, workingDir string, services []string) bool {
	if s.StackStore == nil {
		return false
	}

	candidates := s.StackStore.FindAllByComposeProject(project)
	if len(candidates) == 0 {
		return false
	}

	for _, stack := range candidates {
		if stack.AgentID != agentID {
			continue
		}
		if stacksStackMatchesCandidate(stack, workingDir, services) {
			return true
		}
	}
	return false
}

// resolveAgentContainerStack looks up a container's owning stack in the server's
// central store, scoped to stacks registered for the given agent. The agent
// reports containers from its own runtime; the server store is the authoritative
// source for stack ownership (the agent-local store is never populated from the
// central registry).
func (s *Server) resolveAgentContainerStack(agentID, containerID string) (stacks.Stack, bool) {
	if s.StackStore == nil || containerID == "" {
		return stacks.Stack{}, false
	}
	// Iterate all stacks (rather than GetByManagedContainer) so the result is
	// not dependent on map iteration order when multiple stacks claim the same
	// container ID — only a stack registered for this agent can own it.
	for _, stack := range s.StackStore.List() {
		if stack.AgentID != agentID {
			continue
		}
		for _, ownedID := range stack.ManagedContainers {
			if ownedID == containerID {
				return stack, true
			}
		}
	}
	return stacks.Stack{}, false
}

// stacksStackMatchesCandidate mirrors the working-dir / service matching used
// by stacks.Store.FindForComposeTarget.
func stacksStackMatchesCandidate(stack stacks.Stack, workingDir string, services []string) bool {
	wd := stacks.NormalizeComparePath(workingDir)
	if wd != "" {
		if stacks.NormalizeComparePath(stack.WorkingDir) == wd {
			return true
		}
		if stacks.NormalizeComparePath(stacks.ResolvePathForRuntime(stack, stack.WorkingDir)) == wd {
			return true
		}
	}

	for _, svc := range services {
		for _, known := range stack.Discovery.ServiceNames {
			if strings.EqualFold(strings.TrimSpace(svc), strings.TrimSpace(known)) {
				return true
			}
		}
	}

	return len(stack.Discovery.ServiceNames) == 0 && wd == ""
}

func (s *Server) dispatchAgentStackDiscover(w http.ResponseWriter, r *http.Request, agentID string) {
	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeStackDiscover, nil, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid agent response")
			return
		}
		if rd.Error != "" {
			writeError(w, http.StatusInternalServerError, rd.Error)
			return
		}

		// The agent reports candidates from its own runtime, but the server
		// holds the authoritative stack store. Recompute the "registered" flag
		// for each candidate against stacks registered for this agent so the
		// discovery list reflects the central registry. The agent-computed
		// config_files / compose_files fields are authoritative: they are read
		// from container labels and the agent host filesystem, which the server
		// cannot probe directly.
		var result struct {
			Candidates []agent.StackDiscoverCandidate `json:"candidates"`
		}
		if err := json.Unmarshal(rd.Value, &result); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(rd.Value)
			return
		}

		for i := range result.Candidates {
			c := &result.Candidates[i]
			c.Registered = s.agentStackRegistered(agentID, c.Project, c.WorkingDir, c.Services)
		}

		out, err := json.Marshal(map[string]any{"candidates": result.Candidates})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to encode discovery results")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	case <-ctx.Done():
		writeError(w, http.StatusGatewayTimeout, "agent request timed out")
	}
}

var _ = uuid.NewString
