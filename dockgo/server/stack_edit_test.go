package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"dockgo/stacks"
)

// TestHandleStackByIDUpdatePersistsEditableFields covers a successful local
// edit: the fields the form owns change, and the stack keeps its identity.
func TestHandleStackByIDUpdatePersistsEditableFields(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test targets non-Windows DockGo runtime behavior")
	}

	srv, stack := newTestStackServer(t)

	composePrimary := filepath.Join(stack.WorkingDir, "compose.yaml")
	composeOverride := filepath.Join(stack.WorkingDir, "compose.override.yaml")
	envPrimary := filepath.Join(stack.WorkingDir, ".env")
	envLocal := filepath.Join(stack.WorkingDir, ".env.local")

	// Validation checks that the referenced files exist on disk.
	for _, path := range []string{composePrimary, composeOverride, envPrimary, envLocal} {
		if err := os.WriteFile(path, []byte("services: {}\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}

	body := `{
		"name": "bazarr",
		"project_name": "bazarr",
		"working_dir": "` + stack.WorkingDir + `",
		"compose_files": [` + quoted(composePrimary) + `, ` + quoted(composeOverride) + `],
		"env_files": [` + quoted(envPrimary) + `, ` + quoted(envLocal) + `],
		"path_mode": "host_native",
		"profiles": ["debug"],
		"project_env": {"TZ": "UTC"},
		"policies": {},
		"update_policy": {
			"pull": true, "build": true, "down_before_up": true,
			"force_recreate": true, "remove_orphans": false
		},
		"health_policy": {
			"use_compose_wait": false, "require_healthy": false,
			"wait_timeout_seconds": 45, "startup_grace_seconds": 5
		}
	}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/stacks/"+stack.ID, strings.NewReader(body))
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	updated, ok := srv.StackStore.Get(stack.ID)
	if !ok {
		t.Fatalf("expected stack after update")
	}

	if got, want := updated.ComposeFiles, []string{composePrimary, composeOverride}; !reflect.DeepEqual(got, want) {
		t.Errorf("compose files = %#v, want %#v", got, want)
	}
	if got, want := updated.EnvFiles, []string{envPrimary, envLocal}; !reflect.DeepEqual(got, want) {
		t.Errorf("env files = %#v, want %#v", got, want)
	}
	if got, want := updated.Profiles, []string{"debug"}; !reflect.DeepEqual(got, want) {
		t.Errorf("profiles = %#v, want %#v", got, want)
	}
	if updated.ProjectEnv["TZ"] != "UTC" {
		t.Errorf("project env = %#v, want TZ=UTC", updated.ProjectEnv)
	}
	if !updated.UpdatePolicy.ForceRecreate || updated.UpdatePolicy.RemoveOrphans {
		t.Errorf("update policy = %#v, want force_recreate only", updated.UpdatePolicy)
	}
	if updated.HealthPolicy.WaitTimeoutSeconds != 45 {
		t.Errorf("wait timeout = %d, want 45", updated.HealthPolicy.WaitTimeoutSeconds)
	}
	if updated.ID != stack.ID {
		t.Errorf("stack id changed: %q -> %q", stack.ID, updated.ID)
	}
	if updated.AgentID != stack.AgentID {
		t.Errorf("agent id changed: %q -> %q", stack.AgentID, updated.AgentID)
	}
}

// TestStackUpdateFromPayloadPreservesProvenance locks in that an edit payload
// cannot move a stack to another host, change its kind, or drop metadata the
// form does not surface.
func TestStackUpdateFromPayloadPreservesProvenance(t *testing.T) {
	existing := stacks.Stack{
		ID:                "stack-1",
		Name:              "media",
		Kind:              stacks.KindGitRepo,
		AgentID:           "agent-1",
		ManagedContainers: []string{"c1", "c2"},
		Labels:            map[string]string{"team": "ops"},
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "media",
			ServiceNames:   []string{"web", "db"},
		},
		GitSource: &stacks.GitSource{RepoURL: "https://example.com/media.git", Ref: "main"},
	}

	payload := stackPayload{
		Name:         "media-renamed",
		ProjectName:  "media",
		AgentID:      "agent-2",
		ComposeFiles: []string{"compose.yaml"},
	}

	updated := stackUpdateFromPayload(existing, payload)

	if updated.ID != existing.ID {
		t.Errorf("id = %q, want %q", updated.ID, existing.ID)
	}
	if updated.Kind != stacks.KindGitRepo {
		t.Errorf("kind = %q, want %q", updated.Kind, stacks.KindGitRepo)
	}
	if updated.AgentID != "agent-1" {
		t.Errorf("agent id = %q, want agent-1", updated.AgentID)
	}
	if !reflect.DeepEqual(updated.ManagedContainers, existing.ManagedContainers) {
		t.Errorf("managed containers = %#v, want %#v", updated.ManagedContainers, existing.ManagedContainers)
	}
	if updated.GitSource == nil || updated.GitSource.RepoURL != existing.GitSource.RepoURL {
		t.Errorf("git source = %#v, want %#v", updated.GitSource, existing.GitSource)
	}
	if !reflect.DeepEqual(updated.Labels, existing.Labels) {
		t.Errorf("labels = %#v, want %#v", updated.Labels, existing.Labels)
	}
	if !reflect.DeepEqual(updated.Discovery, existing.Discovery) {
		t.Errorf("discovery = %#v, want %#v", updated.Discovery, existing.Discovery)
	}
	if updated.Name != "media-renamed" {
		t.Errorf("name = %q, want media-renamed", updated.Name)
	}
	if updated.ComposeFiles[0] != "compose.yaml" {
		t.Errorf("compose files = %#v, want compose.yaml", updated.ComposeFiles)
	}
}

// TestHandleAgentStackUpdateRejectsValidationFailure ensures an invalid edit is
// not persisted through the agent route.
func TestHandleAgentStackUpdateRejectsValidationFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test targets non-Windows DockGo runtime behavior")
	}

	srv, _ := newTestServerWithAgent(t)
	agentRec := srv.AgentStore.List()[0]

	stack, err := srv.StackStore.Save(stacks.Stack{
		Name:         "remote",
		ProjectName:  "remote",
		WorkingDir:   `D:\Docker\remote`,
		ComposeFiles: []string{`D:\Docker\remote\compose.yaml`},
		PathMode:     stacks.PathModeMapped,
		AgentID:      agentRec.ID,
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	body := `{
		"name": "remote-renamed",
		"project_name": "remote",
		"working_dir": "D:\\Docker\\elsewhere",
		"compose_files": ["D:\\Docker\\elsewhere\\compose.yaml"],
		"path_mode": "mapped"
	}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut,
		"/api/stacks/"+stack.ID+"?agent="+agentRec.ID, strings.NewReader(body))
	srv.handleAgentStacksRoute(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	stored, ok := srv.StackStore.Get(stack.ID)
	if !ok {
		t.Fatalf("expected stack after rejected update")
	}
	if stored.Name != "remote" {
		t.Errorf("name = %q, want remote (rejected update must not persist)", stored.Name)
	}
}

// TestStackUpdatePayloadRoundTripsMultipleFiles guards the multi-file form
// change: the arrays must survive an edit unchanged.
func TestStackUpdatePayloadRoundTripsMultipleFiles(t *testing.T) {
	existing := stacks.Stack{
		ID:           "stack-2",
		Name:         "web",
		Kind:         stacks.KindComposeFiles,
		ComposeFiles: []string{"compose.yaml", "compose.override.yaml"},
		EnvFiles:     []string{".env", ".env.prod"},
		PathMode:     stacks.PathModeHostNative,
	}

	body := `{
		"name": "web",
		"project_name": "web",
		"compose_files": ["compose.yaml", "compose.override.yaml"],
		"env_files": [".env", ".env.prod"],
		"path_mode": "host_native"
	}`

	var payload stackPayload
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	updated := stackUpdateFromPayload(existing, payload)

	if !reflect.DeepEqual(updated.ComposeFiles, existing.ComposeFiles) {
		t.Errorf("compose files = %#v, want %#v", updated.ComposeFiles, existing.ComposeFiles)
	}
	if !reflect.DeepEqual(updated.EnvFiles, existing.EnvFiles) {
		t.Errorf("env files = %#v, want %#v", updated.EnvFiles, existing.EnvFiles)
	}
}

// quoted renders a path as a JSON string literal for the raw test payloads.
func quoted(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return `""`
	}
	return string(encoded)
}
