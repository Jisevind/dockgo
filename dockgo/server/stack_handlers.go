package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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
		writeJSON(w, http.StatusOK, map[string]any{
			"stacks": s.StackStore.List(),
		})
	case http.MethodPost:
		var payload stackPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		stack, err := s.StackStore.Save(stackFromPayload(stacks.Stack{}, payload))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, stackDetailResponse{
			Stack:      stack,
			Validation: validationPtr(stacks.Validate(context.Background(), stack)),
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

			updated, err := s.StackStore.Save(stackFromPayload(stack, payload))
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}

			writeJSON(w, http.StatusOK, stackDetailResponse{
				Stack:      updated,
				Validation: validationPtr(stacks.Validate(context.Background(), updated)),
			})
		case http.MethodDelete:
			if err := s.StackStore.Delete(id); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
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

		writeJSON(w, http.StatusOK, stacks.Validate(ctx, stack))
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
