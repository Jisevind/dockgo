package server

import (
	"context"
	"encoding/json"
	"errors"
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
	case "deploy", "pull", "restart", "stop", "start", "down":
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
	case "files":
		if len(parts) != 2 {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleAgentStackFiles(w, r, agentID, stack)
	case "file":
		// "file/validate" is the three-segment draft check. It is recognised
		// before the two-segment read/save case for the same reason
		// handleStackByID orders them that way: a draft check must never be
		// answered as a read of the stored file.
		if len(parts) == 3 && parts[2] == "validate" {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			s.handleAgentStackFileValidate(w, r, agentID, stack)
			return
		}
		if len(parts) != 2 {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.handleAgentStackFileRead(w, r, agentID, stack)
		case http.MethodPut:
			s.handleAgentStackFileWrite(w, r, agentID, stack)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
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
	case "stop":
		actionLabel = "stop"
	case "start":
		actionLabel = "start"
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

// The agent reports a stack-file failure as a message and nothing else:
// ResultData carries only Error and Value, so the proxy classifies a refusal by
// its text. These are the exact texts dockgo/agent/ops.go produces
// (errStackFileInvalidSyntax, errStackFileValidationFailed,
// errStackFileRollbackFailed and errGitStackUnsupported). That package's
// TestAgentStackFileErrorTextsAreDistinguishableOnTheWire keeps the three write
// refusals from sharing a prefix or a substring, which is the only thing that
// lets a prefix match here tell them apart - the agent's sentinels are
// unexported, so this duplication is the sole contract between the two sides.
const (
	agentFileSyntaxRefusal     = "file has syntax errors"
	agentFileValidationRefusal = "file failed compose validation"
	agentFileRollbackRefusal   = "rollback failed: the previous content could not be restored"
	agentFileGitStackRefusal   = "git-kind stacks are not supported on remote agents"
)

// agentStackFileErrorStatus maps an agent stack-file failure onto the status the
// local route answers the same condition with (see fileTargetStatus), so a
// client sees one answer per condition whichever host holds the stack.
func agentStackFileErrorStatus(message string) int {
	switch {
	// The failed rollback is classified FIRST. Its text describes a file that
	// was left invalid on the agent host, so it must never be answered with the
	// status of the clean refusal. dockgo/agent reworded the two texts so that
	// neither is a prefix of the other; keeping the failed rollback ahead of the
	// clean one means a later reword that reintroduces a shared prefix turns
	// into "the worst case wins" instead of a failed rollback being reported as
	// a restored file.
	case strings.HasPrefix(message, agentFileRollbackRefusal):
		return http.StatusInternalServerError
	case strings.HasPrefix(message, agentFileValidationRefusal), strings.HasPrefix(message, agentFileSyntaxRefusal):
		// A draft the agent refused, which the local write answers with 422.
		return http.StatusUnprocessableEntity
	case strings.HasPrefix(message, stacks.ErrFileMissing.Error()):
		return http.StatusNotFound
	case strings.HasPrefix(message, stacks.ErrFileNotRegular.Error()),
		strings.HasPrefix(message, stacks.ErrPathNotAllowed.Error()):
		return http.StatusForbidden
	case strings.HasPrefix(message, stacks.ErrFileTooLarge.Error()):
		return http.StatusRequestEntityTooLarge
	case strings.HasPrefix(message, agentFileGitStackRefusal):
		// A git-backed stack has no file on the agent host to edit, and this
		// server rejects one with the same 400 (handleAgentStackCreate).
		return http.StatusBadRequest
	default:
		// An agent-side failure the request does not explain, which is what the
		// local route reports as 500 for a read or a write.
		return http.StatusInternalServerError
	}
}

// agentStackFileWriteRefusal answers a write the agent refused. A clean refusal
// means the previous content was restored; a failed rollback means the rejected
// draft is still on the agent's disk. The two stay distinguishable in both
// status and body, because a client that read a failed rollback as a restored
// file would leave a stack invalid without telling its owner.
func agentStackFileWriteRefusal(w http.ResponseWriter, message string) {
	status := agentStackFileErrorStatus(message)
	switch {
	// Ordered as in agentStackFileErrorStatus, and for the same reason: the
	// rollback text is recognised before the validation text so that a rewording
	// which reintroduces a shared prefix reports the file that was NOT restored
	// rather than the one that was.
	case strings.HasPrefix(message, agentFileRollbackRefusal):
		writeJSON(w, status, map[string]any{"error": message, "rolled_back": false})
	case strings.HasPrefix(message, agentFileValidationRefusal):
		writeJSON(w, status, map[string]any{"error": message, "rolled_back": true})
	default:
		writeError(w, status, message)
	}
}

// agentFileTarget parses the kind/index selector and refuses one this stack does
// not have. Both hosts resolve a selector against the stack's own ComposeFiles /
// EnvFiles list before touching a filesystem (stacks.ResolveFileTarget), and the
// local route answers a selector that does not resolve with 400. Checking it
// here, where that list is authoritative, keeps an agent-hosted stack from
// answering the same client error with a different status; the messages are the
// ones stacks.ResolveFileTarget produces for the same selector.
func agentFileTarget(w http.ResponseWriter, stack stacks.Stack, r *http.Request) (string, int, bool) {
	kind, index, err := fileTargetRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", 0, false
	}

	var count int
	switch kind {
	case stacks.FileKindCompose:
		count = len(stack.ComposeFiles)
	case stacks.FileKindEnv:
		count = len(stack.EnvFiles)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported file kind: %s", kind))
		return "", 0, false
	}
	if index < 0 {
		writeError(w, http.StatusBadRequest, "index must not be negative")
		return "", 0, false
	}
	if index >= count {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%s index %d is out of range", kind, index))
		return "", 0, false
	}
	return kind, index, true
}

// decodeAgentFileContent reads the draft body behind the same size cap the local
// route applies, so an oversized body is refused before it is allocated.
func decodeAgentFileContent(w http.ResponseWriter, r *http.Request) (string, bool) {
	var payload fileContentPayload
	if err := decodeFileContentPayload(w, r, &payload); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
			return "", false
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return "", false
	}
	return payload.Content, true
}

// writeAgentStackFileValue forwards the agent's own JSON, so the proxy answers
// with the shape the local route produces - {"files": ...} for a listing,
// {"target": ..., "content": ...} for a read, the syntax result for a draft
// check and {"target": ...} for a save - instead of re-wrapping it.
func writeAgentStackFileValue(w http.ResponseWriter, value json.RawMessage) {
	writeJSON(w, http.StatusOK, value)
}

// agentStackFileExchange dispatches one stack-file operation and returns the
// agent's terminal result. A transport failure means the operation never ran, so
// it is answered here and ok is false: 503 when the agent cannot be reached, 504
// when it did not answer inside the request's context.
func (s *Server) agentStackFileExchange(ctx context.Context, w http.ResponseWriter, agentID, msgType string, payload any) (agent.ResultData, bool) {
	response, _, err := s.dispatchToAgent(ctx, agentID, msgType, payload, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return agent.ResultData{}, false
	}

	select {
	case env := <-response:
		var result agent.ResultData
		if err := env.Decode(&result); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid agent response")
			return agent.ResultData{}, false
		}
		return result, true
	case <-ctx.Done():
		writeError(w, http.StatusGatewayTimeout, "agent request timed out")
		return agent.ResultData{}, false
	}
}

// handleAgentStackFiles proxies the stack's editable-file listing. The agent
// owns the filesystem, so it decides which of the stack's files are editable
// there.
func (s *Server) handleAgentStackFiles(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	result, ok := s.agentStackFileExchange(ctx, w, agentID, agent.TypeStackFileList, agent.StackFileRequest{Stack: stack})
	if !ok {
		return
	}
	if result.Error != "" {
		writeError(w, agentStackFileErrorStatus(result.Error), result.Error)
		return
	}
	writeAgentStackFileValue(w, result.Value)
}

// handleAgentStackFileRead proxies the content of one file of an agent-hosted
// stack.
func (s *Server) handleAgentStackFileRead(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	kind, index, ok := agentFileTarget(w, stack, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	result, ok := s.agentStackFileExchange(ctx, w, agentID, agent.TypeStackFileRead, agent.StackFileRequest{
		Stack: stack, Kind: kind, Index: index,
	})
	if !ok {
		return
	}
	if result.Error != "" {
		writeError(w, agentStackFileErrorStatus(result.Error), result.Error)
		return
	}
	writeAgentStackFileValue(w, result.Value)
}

// handleAgentStackFileValidate asks the agent to syntax-check draft content
// without writing it, so the editor can validate while typing.
func (s *Server) handleAgentStackFileValidate(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	kind, index, ok := agentFileTarget(w, stack, r)
	if !ok {
		return
	}
	content, ok := decodeAgentFileContent(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	result, ok := s.agentStackFileExchange(ctx, w, agentID, agent.TypeStackFileValidate, agent.StackFileWriteRequest{
		Stack: stack, Kind: kind, Index: index, Content: content,
	})
	if !ok {
		return
	}
	if result.Error != "" {
		writeError(w, agentStackFileErrorStatus(result.Error), result.Error)
		return
	}
	writeAgentStackFileValue(w, result.Value)
}

// handleAgentStackFileWrite proxies a save and records the history entry the
// local write records: the agent keeps no stack history, this server owns the
// store.
func (s *Server) handleAgentStackFileWrite(w http.ResponseWriter, r *http.Request, agentID string, stack stacks.Stack) {
	kind, index, ok := agentFileTarget(w, stack, r)
	if !ok {
		return
	}
	content, ok := decodeAgentFileContent(w, r)
	if !ok {
		return
	}
	// The agent enforces the same cap first - matching the local write's order -
	// but refusing an oversized draft here keeps it off the wire.
	if len(content) > stacks.MaxEditableFileBytes {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("content exceeds the %d byte limit", stacks.MaxEditableFileBytes))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	result, ok := s.agentStackFileExchange(ctx, w, agentID, agent.TypeStackFileWrite, agent.StackFileWriteRequest{
		Stack: stack, Kind: kind, Index: index, Content: content,
	})
	if !ok {
		return
	}
	if result.Error != "" {
		agentStackFileWriteRefusal(w, result.Error)
		return
	}

	// result.Value is the agent's {"target": ...} payload. The agent resolved the
	// target before it wrote, so the target it reports carries the previous
	// content's size - the quantity the local write uses for its delta. Decoding
	// it is best effort: the save already succeeded, so a payload this proxy
	// cannot read must not turn a completed save into a reported failure.
	message := fmt.Sprintf("stack file updated (%s)", kind)
	var written struct {
		Target stacks.FileTarget `json:"target"`
	}
	if err := json.Unmarshal(result.Value, &written); err == nil && written.Target.Label != "" {
		message = fmt.Sprintf("%s updated (%s, %+d bytes)",
			written.Target.Label, kind, len(content)-int(written.Target.Size))
	}

	action := "edit compose"
	if kind == stacks.FileKindEnv {
		action = "edit env"
	}
	// Record before responding, matching the local write: a client that reads
	// history as soon as the save returns must see its own entry.
	s.recordStackHistory(stack, action, "success", message)

	writeAgentStackFileValue(w, result.Value)
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
