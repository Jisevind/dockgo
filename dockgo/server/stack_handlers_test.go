package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dockgo/stacks"
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
	if len(streamed) != 2 {
		t.Fatalf("streamed len = %d, want 2", len(streamed))
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
