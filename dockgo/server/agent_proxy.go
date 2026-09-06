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
	"dockgo/notify"

	"github.com/google/uuid"
)

// handleAgentRoute dispatches to the appropriate agent-capable handler based on
// the route prefix. It supports both `/api/agent/:id/containers` style paths and
// the existing routes with `?agent=`.
func (s *Server) handleAgentRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/agent/")
	path = strings.Trim(path, "/")

	// Split off the agent ID; the remainder is the sub-route.
	agentID, rest, found := strings.Cut(path, "/")
	if !found || agentID == "" {
		writeError(w, http.StatusBadRequest, "agent id and route required")
		return
	}

	if !s.AgentManager.IsOnline(agentID) {
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("agent %s is offline", agentID))
		return
	}

	// Rewrite the URL path to the canonical form so the sub-handlers can parse it.
	r = r.Clone(r.Context())
	r.URL.Path = "/api/" + rest

	switch {
	case strings.HasPrefix(rest, "stream/check"):
		s.handleAgentStreamCheck(w, r)
	case strings.HasPrefix(rest, "update/"):
		s.handleAgentUpdate(w, r)
	case strings.HasPrefix(rest, "container/"):
		s.handleAgentContainerAction(w, r)
	case strings.HasPrefix(rest, "logs/"):
		s.handleAgentContainerLogs(w, r)
	case rest == "server/stats":
		s.handleAgentServerStats(w, r)
	case rest == "containers":
		s.handleAgentContainers(w, r)
	case strings.HasPrefix(rest, "stacks"):
		s.handleAgentStacksRoute(w, r)
	default:
		writeError(w, http.StatusNotFound, "unknown agent route")
	}
}

// agentOpTimeout bounds a single dispatched agent operation. It must be
// generous enough to cover slow daemon/filesystem operations on the agent host.
const agentOpTimeout = 5 * time.Minute

// agentQueryAgentID extracts the target agent ID from either the `?agent=`
// query parameter or the `/api/agent/:id/...` route prefix.
func agentQueryAgentID(r *http.Request) (string, bool) {
	if id := strings.TrimSpace(r.URL.Query().Get("agent")); id != "" {
		return id, true
	}
	rest, found := strings.CutPrefix(r.URL.Path, "/api/agent/")
	if found {
		id, _, _ := strings.Cut(rest, "/")
		if id != "" {
			return id, true
		}
	}
	return "", false
}

// dispatchToAgent sends a request to an agent and returns a function that
// reads progress envelopes from the agent and relays them to the caller. The
// returned channel delivers the single terminal result.
func (s *Server) dispatchToAgent(ctx context.Context, agentID, msgType string, payload any, onProgress func(agent.Envelope)) (<-chan agent.Envelope, func(), error) {
	progress := make(chan agent.Envelope, 64)
	requestID := uuid.NewString()
	response, err := s.AgentManager.Dispatch(ctx, agentID, requestID, msgType, payload, progress)
	if err != nil {
		return nil, nil, err
	}

	// Relay progress events to the SSE writer.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case env, ok := <-progress:
				if !ok {
					return
				}
				if onProgress != nil {
					onProgress(env)
				}
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	cancel := func() {
		close(done)
		wg.Wait()
		// Free the server-side concurrency slot promptly when the web client
		// disconnects. The agent keeps executing the op to completion, but the
		// response channel would otherwise retain the slot until then.
		if ac := s.AgentManager.AgentConn(agentID); ac != nil {
			ac.Cancel(requestID)
		}
	}

	return response, cancel, nil
}

// handleAgentContainers proxies the container list to an agent.
func (s *Server) handleAgentContainers(w http.ResponseWriter, r *http.Request) {
	agentID, ok := agentQueryAgentID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "agent id required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeContainersList, nil, nil)
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

		// Overlay update availability from the per-agent scan cache so the
		// dashboard renders accurate update badges for agent containers.
		var containers []map[string]any
		if err := json.Unmarshal(rd.Value, &containers); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(rd.Value)
			return
		}

		s.mu.RLock()
		agentCache := s.agentUpdatesCache[agentID]
		s.mu.RUnlock()

		for _, c := range containers {
			if id, ok := c["id"].(string); ok && id != "" && agentCache != nil {
				if agentCache[id] {
					c["update_available"] = true
				}
			}
		}

		// Overlay stack ownership from the server's central store so the
		// dashboard can group agent containers by stack, mirroring the local
		// containers path (resolveContainerStack). The agent reports
		// stack_registered=false for everything because its local store is not
		// synced from the central registry.
		for _, c := range containers {
			id, _ := c["id"].(string)
			if id == "" {
				continue
			}
			if stack, ok := s.resolveAgentContainerStack(agentID, id); ok {
				c["stack_managed"] = true
				c["stack_registered"] = true
				c["stack_id"] = stack.ID
				c["stack_name"] = stack.Name
			}
		}

		out, err := json.Marshal(containers)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to encode containers")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	case <-ctx.Done():
		writeError(w, http.StatusGatewayTimeout, "agent request timed out")
	}
}

// handleAgentStreamCheck proxies an update scan to an agent, streaming
// progress events as SSE.
func (s *Server) handleAgentStreamCheck(w http.ResponseWriter, r *http.Request) {
	agentID, ok := agentQueryAgentID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "agent id required")
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

	_, _ = w.Write([]byte("data: {\"type\":\"start\"}\n\n"))
	flusher.Flush()

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()

	var writeMu sync.Mutex
	emitSSE := func(payload map[string]any) {
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

	force := r.URL.Query().Get("force") == "true"
	req := agent.ScanRequest{Force: force}

	onProgress := func(env agent.Envelope) {
		var pd agent.ProgressData
		if err := env.Decode(&pd); err != nil {
			return
		}
		if pd.Progress == nil {
			return
		}
		emitSSE(map[string]any{
			"type":      "progress",
			"current":   pd.Progress.Current,
			"total":     pd.Progress.Total,
			"container": pd.Progress.Container,
			"status":    pd.Progress.Status,
		})
	}

	response, stopRelay, err := s.dispatchToAgent(ctx, agentID, agent.TypeScan, req, onProgress)
	if err != nil {
		emitSSE(map[string]any{"type": "error", "error": err.Error()})
		return
	}
	defer stopRelay()

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			emitSSE(map[string]any{"type": "error", "error": "invalid agent response"})
			return
		}
		if rd.Error != "" {
			emitSSE(map[string]any{"type": "error", "error": rd.Error})
			return
		}

		// Persist scan results into the server cache so the dashboard shows
		// update badges for agent containers.
		if rd.Value != nil {
			var updates []struct {
				ID              string `json:"id"`
				Name            string `json:"name"`
				Status          string `json:"status"`
				UpdateAvailable bool   `json:"update_available"`
			}
			if err := json.Unmarshal(rd.Value, &updates); err == nil {
				s.mu.Lock()
				if s.agentUpdatesCache[agentID] == nil {
					s.agentUpdatesCache[agentID] = make(map[string]bool)
				}
				for _, u := range updates {
					if u.Status == "skipped" {
						continue
					}
					if u.UpdateAvailable {
						s.agentUpdatesCache[agentID][u.ID] = true
					} else {
						delete(s.agentUpdatesCache[agentID], u.ID)
					}
				}
				s.lastCheckTime = time.Now()
				s.lastCheckStat = "success"
				s.mu.Unlock()
			}
		}

		emitSSE(map[string]any{"type": "done", "code": 0})
	case <-ctx.Done():
		emitSSE(map[string]any{"type": "error", "error": "agent scan timed out"})
	}
}

// handleAgentUpdate proxies a container update to an agent, streaming progress.
func (s *Server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	agentID, ok := agentQueryAgentID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "agent id required")
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/update/")
	if name == "" {
		writeError(w, http.StatusBadRequest, "container name required")
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
		"message": fmt.Sprintf("Starting update for %s...", name),
	})
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(startBytes)
	_, _ = w.Write([]byte("\n\n"))
	flusher.Flush()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	var writeMu sync.Mutex
	emitSSE := func(payload map[string]any) {
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

	req := agent.UpdateRequest{
		Name:            name,
		Safe:            false,
		PreserveNetwork: true,
	}

	onProgress := func(env agent.Envelope) {
		var pd agent.ProgressData
		if err := env.Decode(&pd); err != nil {
			return
		}
		payload := map[string]any{"type": "progress"}
		if pd.Progress != nil {
			payload["status"] = pd.Progress.Status
			payload["container"] = pd.Progress.Container
			if pd.Progress.Percent > 0 {
				payload["percent"] = pd.Progress.Percent
			}
		} else if pd.PullProgress != nil {
			payload["status"] = pd.PullProgress.Status
			payload["container"] = pd.PullProgress.Container
			if pd.PullProgress.Percent > 0 {
				payload["percent"] = pd.PullProgress.Percent
			}
		} else if pd.Line != "" {
			payload["status"] = pd.Line
		} else {
			return
		}
		emitSSE(payload)
	}

	response, stopRelay, err := s.dispatchToAgent(ctx, agentID, agent.TypeUpdate, req, onProgress)
	if err != nil {
		emitSSE(map[string]any{"type": "error", "error": err.Error()})
		return
	}
	defer stopRelay()

	select {
	case env := <-response:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			emitSSE(map[string]any{"type": "error", "error": "invalid agent response"})
			return
		}
		if rd.Error != "" {
			emitSSE(map[string]any{"type": "error", "error": fmt.Sprintf("Update process failed: %s", rd.Error)})
			s.Notifier.Notify("DockGo Update Failed", fmt.Sprintf("Failed to update container %s: %s", name, rd.Error), notify.TypeFailure)
			return
		}

		// Refresh the per-agent cache for the updated container: the agent
		// just pulled and recreated it, so clear any pending update flag.
		go s.clearAgentUpdateBadge(agentID)

		s.Notifier.Notify("DockGo Update Success", fmt.Sprintf("Container %s updated successfully", name), notify.TypeSuccess)
		emitSSE(map[string]any{
			"type":    "done",
			"success": true,
			"message": "Update completed successfully",
		})
	case <-ctx.Done():
		emitSSE(map[string]any{"type": "error", "error": "agent update timed out"})
	}
}

// clearAgentUpdateBadge drops all pending update flags for an agent after a
// successful update. The next scan will repopulate accurate flags.
func (s *Server) clearAgentUpdateBadge(agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentUpdatesCache[agentID] = make(map[string]bool)
}

// handleAgentContainerAction proxies start/stop/restart to an agent.
func (s *Server) handleAgentContainerAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID, ok := agentQueryAgentID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "agent id required")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/container/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[1] != "action" {
		http.Error(w, "Invalid route", http.StatusNotFound)
		return
	}
	name := parts[0]
	if name == "" || !validContainerName.MatchString(name) {
		http.Error(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	var reqBody struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(reqBody.Action)
	if action != "start" && action != "stop" && action != "restart" {
		http.Error(w, "Invalid action. Must be 'start', 'stop', or 'restart'", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	req := agent.ContainerActionRequest{Name: name, Action: action}
	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeContainerAction, req, nil)
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
			s.Notifier.Notify("DockGo Action Failed", fmt.Sprintf("Failed to %s container %s: %s", action, name, rd.Error), notify.TypeFailure)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to %s container: %s", action, rd.Error))
			return
		}

		s.Notifier.Notify("DockGo Container Action", fmt.Sprintf("Successfully executed '%s' on container %s", action, name), notify.TypeInfo)
		body, _ := json.Marshal(map[string]any{
			"success": true,
			"message": fmt.Sprintf("Successfully executed %s on %s", action, name),
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	case <-ctx.Done():
		writeError(w, http.StatusGatewayTimeout, "agent request timed out")
	}
}

// handleAgentContainerLogs proxies a container log stream to an agent.
func (s *Server) handleAgentContainerLogs(w http.ResponseWriter, r *http.Request) {
	agentID, ok := agentQueryAgentID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "agent id required")
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/logs/")
	if name == "" || !validContainerName.MatchString(name) {
		http.Error(w, "Invalid container name", http.StatusBadRequest)
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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	var writeMu sync.Mutex
	writeLine := func(line string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		bytes, _ := json.Marshal(map[string]any{"line": line})
		_, _ = w.Write(append(append([]byte("data: "), bytes...), []byte("\n\n")...))
		flusher.Flush()
	}

	req := agent.ContainerLogsRequest{Name: name}

	onProgress := func(env agent.Envelope) {
		var pd agent.ProgressData
		if err := env.Decode(&pd); err != nil {
			return
		}
		if pd.ProgressType == agent.ProgressLog && pd.Line != "" {
			writeLine(pd.Line)
		}
	}

	response, stopRelay, err := s.dispatchToAgent(ctx, agentID, agent.TypeContainerLogs, req, onProgress)
	if err != nil {
		writeLine(fmt.Sprintf("Error fetching logs: %v", err))
		return
	}
	defer stopRelay()

	select {
	case env := <-response:
		var rd agent.ResultData
		_ = env.Decode(&rd)
		if rd.Error != "" {
			writeLine(fmt.Sprintf("--- Stream interrupted: %v ---", rd.Error))
			return
		}
		writeLine("--- Stream disconnected ---")
	case <-ctx.Done():
		writeLine("--- Stream disconnected ---")
	}
}

// handleAgentServerStats proxies host stats to an agent.
func (s *Server) handleAgentServerStats(w http.ResponseWriter, r *http.Request) {
	agentID, ok := agentQueryAgentID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "agent id required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), agentOpTimeout)
	defer cancel()

	response, _, err := s.dispatchToAgent(ctx, agentID, agent.TypeServerStats, nil, nil)
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
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rd.Value)
	case <-ctx.Done():
		writeError(w, http.StatusGatewayTimeout, "agent request timed out")
	}
}
