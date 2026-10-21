package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dockgo/stacks"
)

func TestHandleStackEnvFileCreate(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)
	root := t.TempDir()
	srv.AllowedPaths = []string{root}

	stack, err := srv.StackStore.Save(stacks.Stack{
		Name:        "envtest",
		ProjectName: "envtest",
		WorkingDir:  root,
		PathMode:    stacks.PathModeHostNative,
	})
	if err != nil {
		t.Fatalf("StackStore.Save() error = %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/stacks/"+stack.ID+"/env-file",
		strings.NewReader(`{"name":".env"}`),
	)
	rr := httptest.NewRecorder()
	srv.handleStackByID(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rr.Code, rr.Body.String())
	}

	envPath := filepath.Join(root, ".env")
	if info, err := os.Stat(envPath); err != nil || info.Size() != 0 {
		t.Fatalf("created env file stat = %v, size = %v", err, info)
	}

	updated, ok := srv.StackStore.Get(stack.ID)
	if !ok {
		t.Fatal("stack missing after create")
	}
	if len(updated.EnvFiles) != 1 || updated.EnvFiles[0] != envPath {
		t.Fatalf("EnvFiles = %v, want [%s]", updated.EnvFiles, envPath)
	}
}
