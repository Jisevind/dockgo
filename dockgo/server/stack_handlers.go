package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"dockgo/stacks"
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
	Stack      stacks.Stack             `json:"stack"`
	Validation *stacks.ValidationResult `json:"validation,omitempty"`
}

func (s *Server) handleStacks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		stackList := s.StackStore.List()
		type stackListItem struct {
			Stack         stacks.Stack          `json:"stack"`
			RecentHistory []stacks.HistoryEntry `json:"recent_history"`
		}
		items := make([]stackListItem, 0, len(stackList))
		for _, stack := range stackList {
			items = append(items, stackListItem{
				Stack:         stack,
				RecentHistory: s.StackHistory.ListByStack(stack.ID, 3),
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
		validation := stacks.Validate(context.Background(), stack)
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
			writeJSON(w, http.StatusOK, stackDetailResponse{
				Stack:      stack,
				Validation: validationPtr(stacks.Validate(context.Background(), stack)),
			})
		case http.MethodPut:
			var payload stackPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			updatedInput := stackFromPayload(stack, payload)
			validation := stacks.Validate(context.Background(), updatedInput)
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

		result := stacks.Validate(ctx, stack)
		if result.Valid {
			s.recordStackHistory(stack, "validate", "success", "stack validation passed")
		} else {
			s.recordStackHistory(stack, "validate", "error", strings.Join(result.Issues, "; "))
		}
		writeJSON(w, http.StatusOK, result)
		return
	}

	if len(parts) == 2 && parts[1] == "deploy" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
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
			"message": "Starting stack deployment...",
			"stack":   stack.Name,
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
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(bytes)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}

		err := stacks.Deploy(ctx, stack, func(line string) {
			emit(map[string]any{
				"type":   "progress",
				"status": line,
				"stack":  stack.Name,
			})
		})
		if err != nil {
			_ = s.StackStore.RecordDeployStatus(stack.ID, "error", time.Now().UTC())
			s.recordStackHistory(stack, "deploy", "error", err.Error())
			emit(map[string]any{
				"type":  "error",
				"error": err.Error(),
				"stack": stack.Name,
			})
			return
		}

		_ = s.StackStore.RecordDeployStatus(stack.ID, "success", time.Now().UTC())
		s.recordStackHistory(stack, "deploy", "success", "stack deployment completed")
		emit(map[string]any{
			"type":    "done",
			"success": true,
			"stack":   stack.Name,
		})
		return
	}

	if len(parts) == 2 && parts[1] == "history" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"entries": s.StackHistory.ListByStack(stack.ID, 20),
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

	type candidate struct {
		Project    string   `json:"project"`
		WorkingDir string   `json:"working_dir"`
		Services   []string `json:"services"`
		Registered bool     `json:"registered"`
	}

	grouped := make(map[string]*candidate)
	registered := s.StackStore.List()

	for _, c := range containers {
		project := c.Labels["com.docker.compose.project"]
		if project == "" {
			continue
		}

		entry, ok := grouped[project]
		if !ok {
			entry = &candidate{
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

	for _, entry := range grouped {
		for _, stack := range registered {
			if stack.Discovery.ComposeProject == entry.Project || stack.ProjectName == entry.Project {
				entry.Registered = true
				break
			}
		}
	}

	out := make([]candidate, 0, len(grouped))
	for _, entry := range grouped {
		out = append(out, *entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{"candidates": out})
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

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) recordStackHistory(stack stacks.Stack, action string, status string, message string) {
	if s.StackHistory == nil {
		return
	}
	_ = s.StackHistory.Append(stacks.HistoryEntry{
		StackID:   stack.ID,
		StackName: stack.Name,
		Action:    action,
		Status:    status,
		Message:   message,
	})
}
