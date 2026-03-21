package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"dockgo/stacks"

	"github.com/docker/docker/api/types"
)

func TestSuggestComposeFilePrefersComposeYamlVariants(t *testing.T) {
	tempDir := t.TempDir()
	composePath := filepath.Join(tempDir, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services: {}"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "docker-compose.yml"), []byte("services: {}"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	srv := &Server{}
	got := srv.suggestComposeFile(tempDir)

	if got != composePath {
		t.Fatalf("suggestComposeFile() = %q, want %q", got, composePath)
	}
}

func TestSuggestComposeFileFallsBackToDockerComposeYml(t *testing.T) {
	tempDir := t.TempDir()
	srv := &Server{}

	got := srv.suggestComposeFile(tempDir)
	want := filepath.Join(tempDir, "docker-compose.yml")

	if got != want {
		t.Fatalf("suggestComposeFile() = %q, want %q", got, want)
	}
}

func TestSuggestEnvFileReturnsEnvPath(t *testing.T) {
	tempDir := t.TempDir()
	envPath := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envPath, []byte("FOO=bar"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	srv := &Server{}
	got := srv.suggestEnvFile(tempDir)

	if got != envPath {
		t.Fatalf("suggestEnvFile() = %q, want %q", got, envPath)
	}
}

func TestSuggestEnvFileReturnsEmptyWhenMissing(t *testing.T) {
	tempDir := t.TempDir()

	srv := &Server{}
	got := srv.suggestEnvFile(tempDir)

	if got != "" {
		t.Fatalf("suggestEnvFile() = %q, want empty string", got)
	}
}

func TestCompareStackRuntimeStateWarnsOnWorkingDirMismatch(t *testing.T) {
	warnings := compareStackRuntimeState(
		`D:\Docker\bazarr`,
		map[string]struct{}{
			normalizeComparePath(`D:\Docker\other`): {},
		},
		nil,
		nil,
	)

	if len(warnings) != 1 || !strings.Contains(warnings[0], "runtime working directory differs") {
		t.Fatalf("warnings = %#v, want working directory mismatch warning", warnings)
	}
}

func TestCompareStackRuntimeStateWarnsOnMultipleRuntimeDirs(t *testing.T) {
	warnings := compareStackRuntimeState(
		`/srv/apps/bazarr`,
		map[string]struct{}{
			normalizeComparePath(`/srv/apps/a`): {},
			normalizeComparePath(`/srv/apps/b`): {},
		},
		nil,
		nil,
	)

	if len(warnings) != 1 || !strings.Contains(warnings[0], "multiple working directories") {
		t.Fatalf("warnings = %#v, want multiple working directories warning", warnings)
	}
}

func TestCompareStackRuntimeStateWarnsOnMissingAndExtraServices(t *testing.T) {
	warnings := compareStackRuntimeState(
		`/srv/apps/media`,
		map[string]struct{}{
			normalizeComparePath(`/srv/apps/media`): {},
		},
		[]string{"radarr", "sonarr"},
		map[string]struct{}{
			"radarr": {},
			"lidarr": {},
		},
	)

	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "runtime service 'lidarr' is not present in the saved compose config") {
		t.Fatalf("warnings = %#v, want extra runtime service warning", warnings)
	}
	if !strings.Contains(joined, "saved compose service 'sonarr' is not present among current runtime containers") {
		t.Fatalf("warnings = %#v, want missing runtime service warning", warnings)
	}
}

func TestExecuteStackActionRecordsSuccessfulDeploy(t *testing.T) {
	srv, stack := newTestStackServer(t)

	var streamed []string
	err := srv.executeStackAction(context.Background(), stack, "deploy", "dashboard_update",
		func(ctx context.Context, in stacks.Stack, log stacks.Logger) error {
			log("Pulling image")
			log("Starting service")
			return nil
		},
		func(line string) {
			streamed = append(streamed, line)
		},
	)
	if err != nil {
		t.Fatalf("executeStackAction() error = %v", err)
	}

	updated, ok := srv.StackStore.Get(stack.ID)
	if !ok {
		t.Fatalf("stack missing after executeStackAction")
	}
	if updated.LastDeployStatus != "success" {
		t.Fatalf("LastDeployStatus = %q, want success", updated.LastDeployStatus)
	}
	if updated.LastDeployAt == nil {
		t.Fatalf("LastDeployAt = nil, want timestamp")
	}

	history := srv.StackHistory.ListByStackFiltered(stack.ID, stacks.HistoryFilter{Action: "deploy", Limit: 1})
	if len(history) != 1 {
		t.Fatalf("history len = %d, want 1", len(history))
	}
	entry := history[0]
	if entry.Status != "success" || entry.Source != "dashboard_update" {
		t.Fatalf("history entry = %+v, want success/dashboard_update", entry)
	}
	if len(entry.Details) != 2 || entry.Details[0] != "Pulling image" || entry.Details[1] != "Starting service" {
		t.Fatalf("history details = %#v, want streamed log lines", entry.Details)
	}
	if entry.DurationMs < 0 {
		t.Fatalf("DurationMs = %d, want non-negative", entry.DurationMs)
	}
	if len(streamed) != 3 {
		t.Fatalf("streamed len = %d, want 3", len(streamed))
	}
}

func TestExecuteStackActionRecordsFailedDeploy(t *testing.T) {
	srv, stack := newTestStackServer(t)

	wantErr := errors.New("deploy failed hard")
	err := srv.executeStackAction(context.Background(), stack, "deploy", "stacks_view",
		func(ctx context.Context, in stacks.Stack, log stacks.Logger) error {
			log("Starting deployment")
			return wantErr
		},
		nil,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("executeStackAction() error = %v, want %v", err, wantErr)
	}

	updated, ok := srv.StackStore.Get(stack.ID)
	if !ok {
		t.Fatalf("stack missing after executeStackAction")
	}
	if updated.LastDeployStatus != "error" {
		t.Fatalf("LastDeployStatus = %q, want error", updated.LastDeployStatus)
	}
	if updated.LastDeployAt == nil {
		t.Fatalf("LastDeployAt = nil, want timestamp")
	}

	history := srv.StackHistory.ListByStackFiltered(stack.ID, stacks.HistoryFilter{Action: "deploy", Limit: 1})
	if len(history) != 1 {
		t.Fatalf("history len = %d, want 1", len(history))
	}
	entry := history[0]
	if entry.Status != "error" || entry.Source != "stacks_view" {
		t.Fatalf("history entry = %+v, want error/stacks_view", entry)
	}
	if entry.Message != wantErr.Error() {
		t.Fatalf("history message = %q, want %q", entry.Message, wantErr.Error())
	}
	if len(entry.Details) != 1 || entry.Details[0] != "Starting deployment" {
		t.Fatalf("history details = %#v, want captured log line", entry.Details)
	}
}

func TestExecuteStackActionDoesNotUpdateDeployStatusForNonDeployAction(t *testing.T) {
	srv, stack := newTestStackServer(t)

	err := srv.executeStackAction(context.Background(), stack, "pull", "stacks_view",
		func(ctx context.Context, in stacks.Stack, log stacks.Logger) error {
			log("Pulling image")
			return nil
		},
		nil,
	)
	if err != nil {
		t.Fatalf("executeStackAction() error = %v", err)
	}

	updated, ok := srv.StackStore.Get(stack.ID)
	if !ok {
		t.Fatalf("stack missing after executeStackAction")
	}
	if updated.LastDeployStatus != "" {
		t.Fatalf("LastDeployStatus = %q, want empty for non-deploy action", updated.LastDeployStatus)
	}
	if updated.LastDeployAt != nil {
		t.Fatalf("LastDeployAt = %v, want nil for non-deploy action", updated.LastDeployAt)
	}

	history := srv.StackHistory.ListByStackFiltered(stack.ID, stacks.HistoryFilter{Action: "pull", Limit: 1})
	if len(history) != 1 {
		t.Fatalf("history len = %d, want 1", len(history))
	}
	if history[0].Status != "success" || history[0].Source != "stacks_view" {
		t.Fatalf("history entry = %+v, want success/stacks_view", history[0])
	}
}

func TestDeployBindingErrorRequiresBoundContainersWhenDiscoveryIsAvailable(t *testing.T) {
	err := deployBindingError(true, 0, nil)
	if err == nil {
		t.Fatalf("deployBindingError() = nil, want error")
	}
	if !strings.Contains(err.Error(), "no runtime containers were bound") {
		t.Fatalf("deployBindingError() = %q, want binding failure message", err.Error())
	}
}

func TestDeployBindingErrorWrapsOwnershipSyncFailure(t *testing.T) {
	err := deployBindingError(true, 0, errors.New("docker unavailable"))
	if err == nil {
		t.Fatalf("deployBindingError() = nil, want error")
	}
	if !strings.Contains(err.Error(), "ownership binding failed") || !strings.Contains(err.Error(), "docker unavailable") {
		t.Fatalf("deployBindingError() = %q, want wrapped sync failure", err.Error())
	}
}

func TestDeployBindingErrorAllowsZeroBoundContainersWithoutDiscovery(t *testing.T) {
	err := deployBindingError(false, 0, nil)
	if err != nil {
		t.Fatalf("deployBindingError() error = %v, want nil", err)
	}
}

func TestHandleStacksRejectsInvalidCreateWithoutPersisting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test targets non-Windows DockGo runtime behavior")
	}

	srv, _ := newTestStackServer(t)
	initialCount := len(srv.StackStore.List())

	body := `{
		"name":"bad-stack",
		"project_name":"bad-stack",
		"working_dir":"D:\\Docker\\bad-stack",
		"compose_files":["D:\\Docker\\bad-stack\\compose.yaml"],
		"path_mode":"mapped"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/stacks", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.handleStacks(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var payload struct {
		Error      string                  `json:"error"`
		Validation stacks.ValidationResult `json:"validation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if payload.Error != "stack validation failed" || payload.Validation.Valid {
		t.Fatalf("unexpected response payload: %+v", payload)
	}
	if len(srv.StackStore.List()) != initialCount {
		t.Fatalf("stack count changed after invalid create")
	}
}

func TestHandleStackByIDRejectsInvalidUpdateWithoutPersisting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test targets non-Windows DockGo runtime behavior")
	}

	srv, stack := newTestStackServer(t)
	original, ok := srv.StackStore.Get(stack.ID)
	if !ok {
		t.Fatalf("expected saved stack")
	}

	body := `{
		"name":"bazarr-updated",
		"project_name":"bazarr",
		"working_dir":"D:\\Docker\\bazarr",
		"compose_files":["D:\\Docker\\bazarr\\compose.yaml"],
		"path_mode":"mapped"
	}`

	req := httptest.NewRequest(http.MethodPut, "/api/stacks/"+stack.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	updated, ok := srv.StackStore.Get(stack.ID)
	if !ok {
		t.Fatalf("expected stack after invalid update")
	}
	if updated.Name != original.Name || updated.WorkingDir != original.WorkingDir {
		t.Fatalf("stack changed after invalid update: before=%+v after=%+v", original, updated)
	}
}

func TestHandleStackByIDValidateRecordsInvalidResultHistory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test targets non-Windows DockGo runtime behavior")
	}

	srv, stack := newTestStackServer(t)
	stack.WorkingDir = `D:\Docker\bazarr`
	stack.ComposeFiles = []string{`D:\Docker\bazarr\compose.yaml`}
	stack.PathMode = stacks.PathModeMapped

	var err error
	stack, err = srv.StackStore.Save(stack)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/stacks/"+stack.ID+"/validate", nil)
	rec := httptest.NewRecorder()

	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result stacks.ValidationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if result.Valid {
		t.Fatalf("validation unexpectedly passed: %+v", result)
	}

	history := srv.StackHistory.ListByStackFiltered(stack.ID, stacks.HistoryFilter{
		Action: "validate",
		Status: "error",
		Limit:  1,
	})
	if len(history) != 1 {
		t.Fatalf("validate history len = %d, want 1", len(history))
	}
	if history[0].Source != "system" {
		t.Fatalf("validate history source = %q, want system", history[0].Source)
	}
	if len(history[0].Details) == 0 {
		t.Fatalf("validate history details empty, want validation issues")
	}
}

func TestBuildStackDiscoverCandidatesMarksExactMatchRegistered(t *testing.T) {
	tempDir := t.TempDir()
	store, err := stacks.NewStore(filepath.Join(tempDir, "stacks.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	_, err = store.Save(stacks.Stack{
		Name:         "bazarr",
		ProjectName:  "media",
		WorkingDir:   `D:\Docker\bazarr`,
		ComposeFiles: []string{filepath.Join(tempDir, "compose.yaml")},
		PathMode:     stacks.PathModeMapped,
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "media",
			ServiceNames:   []string{"bazarr"},
		},
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	candidates := buildStackDiscoverCandidates([]types.Container{
		{
			Labels: map[string]string{
				"com.docker.compose.project":             "media",
				"com.docker.compose.project.working_dir": `D:\Docker\bazarr`,
				"com.docker.compose.service":             "bazarr",
			},
		},
	}, store, func(dir string) string { return dir + `/compose.yaml` }, func(dir string) string { return dir + `/.env` })

	if len(candidates) != 1 {
		t.Fatalf("candidates len = %d, want 1", len(candidates))
	}
	if !candidates[0].Registered {
		t.Fatalf("candidate = %+v, want registered", candidates[0])
	}
}

func TestBuildStackDiscoverCandidatesFailsClosedOnAmbiguousProject(t *testing.T) {
	tempDir := t.TempDir()
	store, err := stacks.NewStore(filepath.Join(tempDir, "stacks.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	for _, workingDir := range []string{`D:\Docker\app-a`, `D:\Docker\app-b`} {
		_, err = store.Save(stacks.Stack{
			Name:         filepath.Base(workingDir),
			ProjectName:  "shared",
			WorkingDir:   workingDir,
			ComposeFiles: []string{filepath.Join(tempDir, "compose.yaml")},
			PathMode:     stacks.PathModeMapped,
			Discovery: stacks.DiscoverySelector{
				ComposeProject: "shared",
			},
		})
		if err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	candidates := buildStackDiscoverCandidates([]types.Container{
		{
			Labels: map[string]string{
				"com.docker.compose.project":             "shared",
				"com.docker.compose.project.working_dir": `D:\Docker\unknown`,
				"com.docker.compose.service":             "web",
			},
		},
	}, store, func(dir string) string { return dir + `/compose.yaml` }, func(dir string) string { return dir + `/.env` })

	if len(candidates) != 1 {
		t.Fatalf("candidates len = %d, want 1", len(candidates))
	}
	if candidates[0].Registered {
		t.Fatalf("candidate = %+v, want unregistered due to ambiguity", candidates[0])
	}
}

func TestBuildStackDiscoverCandidatesUsesServiceTieBreakWhenAvailable(t *testing.T) {
	tempDir := t.TempDir()
	store, err := stacks.NewStore(filepath.Join(tempDir, "stacks.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	for _, tc := range []struct {
		name    string
		service string
	}{
		{name: "radarr", service: "radarr"},
		{name: "sonarr", service: "sonarr"},
	} {
		_, err = store.Save(stacks.Stack{
			Name:         tc.name,
			ProjectName:  "media",
			WorkingDir:   `D:\Docker\shared`,
			ComposeFiles: []string{filepath.Join(tempDir, tc.name+".yaml")},
			PathMode:     stacks.PathModeMapped,
			Discovery: stacks.DiscoverySelector{
				ComposeProject: "media",
				ServiceNames:   []string{tc.service},
			},
		})
		if err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	candidates := buildStackDiscoverCandidates([]types.Container{
		{
			Labels: map[string]string{
				"com.docker.compose.project":             "media",
				"com.docker.compose.project.working_dir": `D:\Docker\shared`,
				"com.docker.compose.service":             "sonarr",
			},
		},
	}, store, func(dir string) string { return dir + `/compose.yaml` }, func(dir string) string { return dir + `/.env` })

	if len(candidates) != 1 {
		t.Fatalf("candidates len = %d, want 1", len(candidates))
	}
	if !candidates[0].Registered {
		t.Fatalf("candidate = %+v, want registered via service tie-break", candidates[0])
	}
}

func TestResolveContainerStackPrefersManagedContainerOwnership(t *testing.T) {
	tempDir := t.TempDir()
	store, err := stacks.NewStore(filepath.Join(tempDir, "stacks.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	owner, err := store.Save(stacks.Stack{
		Name:              "owner",
		ProjectName:       "shared",
		WorkingDir:        "/srv/owner",
		ComposeFiles:      []string{filepath.Join(tempDir, "owner.yaml")},
		PathMode:          stacks.PathModeHostNative,
		ManagedContainers: []string{"container-1"},
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	_, err = store.Save(stacks.Stack{
		Name:         "fallback",
		ProjectName:  "shared",
		WorkingDir:   "/srv/other",
		ComposeFiles: []string{filepath.Join(tempDir, "other.yaml")},
		PathMode:     stacks.PathModeHostNative,
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "shared",
			ServiceNames:   []string{"web"},
		},
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	srv := &Server{StackStore: store}
	container := types.Container{
		ID: "container-1",
		Labels: map[string]string{
			"com.docker.compose.project":             "shared",
			"com.docker.compose.project.working_dir": "/srv/other",
			"com.docker.compose.service":             "web",
		},
	}

	resolved, ok := srv.resolveContainerStack(container)
	if !ok {
		t.Fatalf("resolveContainerStack() ok = false, want true")
	}
	if resolved.ID != owner.ID {
		t.Fatalf("resolveContainerStack() = %+v, want owner stack", resolved)
	}
}

func TestResolveContainerStackDoesNotFallBackToRegisteredComposeMatch(t *testing.T) {
	tempDir := t.TempDir()
	store, err := stacks.NewStore(filepath.Join(tempDir, "stacks.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	_, err = store.Save(stacks.Stack{
		Name:         "sonarr",
		ProjectName:  "media",
		WorkingDir:   "/srv/media",
		ComposeFiles: []string{filepath.Join(tempDir, "sonarr.yaml")},
		PathMode:     stacks.PathModeHostNative,
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "media",
			ServiceNames:   []string{"sonarr"},
		},
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	srv := &Server{StackStore: store}
	container := types.Container{
		ID: "container-2",
		Labels: map[string]string{
			"com.docker.compose.project":             "media",
			"com.docker.compose.project.working_dir": "/srv/media",
			"com.docker.compose.service":             "sonarr",
		},
	}

	if _, ok := srv.resolveContainerStack(container); ok {
		t.Fatalf("resolveContainerStack() ok = true, want false")
	}
}

func TestResolveContainerStackFailsClosedWhenUnresolved(t *testing.T) {
	tempDir := t.TempDir()
	store, err := stacks.NewStore(filepath.Join(tempDir, "stacks.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	for _, dir := range []string{"/srv/app-a", "/srv/app-b"} {
		_, err = store.Save(stacks.Stack{
			Name:         filepath.Base(dir),
			ProjectName:  "shared",
			WorkingDir:   dir,
			ComposeFiles: []string{filepath.Join(tempDir, filepath.Base(dir)+".yaml")},
			PathMode:     stacks.PathModeHostNative,
		})
		if err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	srv := &Server{StackStore: store}
	container := types.Container{
		ID: "container-3",
		Labels: map[string]string{
			"com.docker.compose.project":             "shared",
			"com.docker.compose.project.working_dir": "/srv/unknown",
			"com.docker.compose.service":             "web",
		},
	}

	if _, ok := srv.resolveContainerStack(container); ok {
		t.Fatalf("resolveContainerStack() ok = true, want false")
	}
}

func TestContainerMatchesStackProjectMatchesRuntimePathForMappedStack(t *testing.T) {
	stack := stacks.Stack{
		Name:         "bazarr",
		ProjectName:  "bazarr",
		WorkingDir:   `D:\Docker\bazarr`,
		PathMode:     stacks.PathModeMapped,
		PathMappings: []stacks.PathMapping{{HostPath: `D:\Docker`, ContainerPath: "/compose"}},
	}

	container := types.Container{
		Labels: map[string]string{
			"com.docker.compose.project":             "bazarr",
			"com.docker.compose.project.working_dir": "/compose/bazarr",
		},
	}

	if !containerMatchesStackProject(stack, container) {
		t.Fatalf("containerMatchesStackProject() = false, want true")
	}
}

func TestStackOwnershipIssuesIncludesMissingAndExtraContainers(t *testing.T) {
	extra := []types.Container{
		{ID: "container-2", Names: []string{"/bazarr-2"}},
	}

	issues := stackOwnershipIssues([]string{"container-1"}, extra)
	joined := strings.Join(issues, "\n")

	if !strings.Contains(joined, "Managed container missing: container-1") {
		t.Fatalf("issues = %#v, want missing-container issue", issues)
	}
	if !strings.Contains(joined, "Runtime container not managed by this stack: bazarr-2") {
		t.Fatalf("issues = %#v, want extra-container issue", issues)
	}
}

func TestBlockedStackActionReasonBlocksRiskyActionsWhenDrifted(t *testing.T) {
	statusSummary := map[string]any{
		"state": "drifted",
	}

	for _, action := range []string{"pull", "restart", "down"} {
		blocked, reason := blockedStackActionReason(statusSummary, action)
		if !blocked {
			t.Fatalf("blockedStackActionReason(%q) blocked = false, want true", action)
		}
		if !strings.Contains(reason, "blocked while the stack is drifted") {
			t.Fatalf("reason = %q, want drift explanation", reason)
		}
	}
}

func TestBlockedStackActionReasonAllowsDeployWhenDrifted(t *testing.T) {
	blocked, reason := blockedStackActionReason(map[string]any{"state": "drifted"}, "deploy")
	if blocked {
		t.Fatalf("blockedStackActionReason(deploy) blocked = true, want false (reason=%q)", reason)
	}
}

func TestBlockedStackActionReasonBlocksRiskyActionsWhenUnbound(t *testing.T) {
	statusSummary := map[string]any{
		"state": "unbound",
	}

	for _, action := range []string{"pull", "restart", "down"} {
		blocked, reason := blockedStackActionReason(statusSummary, action)
		if !blocked {
			t.Fatalf("blockedStackActionReason(%q) blocked = false, want true", action)
		}
		if !strings.Contains(reason, "blocked while the stack is unbound") {
			t.Fatalf("reason = %q, want unbound explanation", reason)
		}
	}
}

func newTestStackServer(t *testing.T) (*Server, stacks.Stack) {
	t.Helper()

	tempDir := t.TempDir()
	store, err := stacks.NewStore(filepath.Join(tempDir, "stacks.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	history, err := stacks.NewHistoryStore(filepath.Join(tempDir, "stack_history.json"))
	if err != nil {
		t.Fatalf("NewHistoryStore() error = %v", err)
	}

	stack, err := store.Save(stacks.Stack{
		Name:         "bazarr",
		ProjectName:  "bazarr",
		WorkingDir:   tempDir,
		ComposeFiles: []string{filepath.Join(tempDir, "compose.yaml")},
		PathMode:     stacks.PathModeHostNative,
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	return &Server{
		StackStore:   store,
		StackHistory: history,
	}, stack
}
