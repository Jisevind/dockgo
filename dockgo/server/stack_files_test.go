package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"dockgo/stacks"
)

func TestHandleStackActionStreamRejectsWorkingDirOutsideAllowList(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{t.TempDir()} // unrelated to the stack's dir

	req := httptest.NewRequest(http.MethodPost, "/api/stacks/"+stack.ID+"/restart", nil)
	rec := httptest.NewRecorder()

	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestHandleStackActionStreamAllowsWorkingDirInsideAllowList(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	req := httptest.NewRequest(http.MethodPost, "/api/stacks/"+stack.ID+"/restart", nil)
	rec := httptest.NewRecorder()

	srv.handleStackByID(rec, req)

	// An admitted directory must not be rejected: the request proceeds to the
	// next gate, which for this unbound stack is the "blocked while unbound"
	// conflict. Nothing downstream differs between an admitted request and an
	// unguarded one, so this test cannot prove the guard exists - that comes
	// from the rejection test above. Its job is to catch over-restriction.
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestHandleStackFilesListsComposeAndEnvTargets(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/files", nil)
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"kind":"compose"`) {
		t.Fatalf("body = %s, want a compose target", rec.Body.String())
	}
}

func TestHandleStackFileReadsContent(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	content := "services:\n  web:\n    image: nginx\n"
	if err := os.WriteFile(stack.ComposeFiles[0], []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/file?kind=compose&index=0", nil)
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "image: nginx") {
		t.Fatalf("body = %s, want the file content", rec.Body.String())
	}
}

func TestHandleStackFileRejectsBadTarget(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	for _, target := range []string{
		"/api/stacks/" + stack.ID + "/file?kind=compose&index=9",
		"/api/stacks/" + stack.ID + "/file?kind=nonsense&index=0",
		"/api/stacks/" + stack.ID + "/file?index=0",
		"/api/stacks/" + stack.ID + "/file?kind=env&index=0", // stack has no env file
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		srv.handleStackByID(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", target, rec.Code)
		}
	}
}

func TestHandleStackFileValidateChecksDraftWithoutWriting(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	original := "services: {}\n"
	if err := os.WriteFile(stack.ComposeFiles[0], []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	body := `{"content":"services:\n  web: [\n"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/stacks/"+stack.ID+"/file/validate?kind=compose&index=0", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"valid":false`) {
		t.Fatalf("body = %s, want valid:false", rec.Body.String())
	}

	saved, err := os.ReadFile(stack.ComposeFiles[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(saved) != original {
		t.Fatalf("content = %q, want %q (validation must not write)", saved, original)
	}
}

func TestHandleStackFileReadMissingReturnsNotFound(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	// newTestStackServer registers a compose path it never creates, so this is
	// the deleted-before-read case. GuardPath resolves symlinks before checking
	// the allow-list, so the miss must still surface as "missing", not as a
	// generic bad-request.
	req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/file?kind=compose&index=0", nil)
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestHandleStackFileReadNonRegularReturnsForbidden(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	// A directory sitting at the registered path exists and passes the
	// allow-list, but is not editable content, so it must be refused with 403.
	if err := os.Mkdir(stack.ComposeFiles[0], 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/file?kind=compose&index=0", nil)
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// writeFakeDocker installs a stub docker on PATH. When failConfig is true the
// stub makes `docker compose config` fail, which is what triggers rollback.
func writeFakeDocker(t *testing.T, failConfig bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub docker relies on a POSIX shell script")
	}

	dir := t.TempDir()
	exit := "0"
	if failConfig {
		exit = "1"
	}
	script := "#!/bin/sh\n" +
		"case \"$*\" in\n" +
		"  *compose*config*)\n" +
		"    printf '%s' '{\"services\":{\"web\":{\"image\":\"nginx\"}}}'\n" +
		"    exit " + exit + "\n" +
		"    ;;\n" +
		"esac\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile(docker stub) error = %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestHandleStackFileWriteSavesValidContent(t *testing.T) {
	writeFakeDocker(t, false)
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	if err := os.WriteFile(stack.ComposeFiles[0], []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	body := `{"content":"services:\n  web:\n    image: nginx\n"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/stacks/"+stack.ID+"/file?kind=compose&index=0", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	saved, err := os.ReadFile(stack.ComposeFiles[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(saved), "image: nginx") {
		t.Fatalf("saved content = %q, want the new content", saved)
	}
}

func TestHandleStackFileWriteRejectsInvalidSyntax(t *testing.T) {
	writeFakeDocker(t, false)
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	original := "services: {}\n"
	if err := os.WriteFile(stack.ComposeFiles[0], []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	body := `{"content":"services:\n  web: [\n"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/stacks/"+stack.ID+"/file?kind=compose&index=0", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}

	saved, err := os.ReadFile(stack.ComposeFiles[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(saved) != original {
		t.Fatalf("content = %q, want the original %q (nothing may be written)", saved, original)
	}
}

func TestHandleStackFileWriteRollsBackWhenDockerRejects(t *testing.T) {
	writeFakeDocker(t, true) // docker compose config fails
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	original := "services: {}\n"
	if err := os.WriteFile(stack.ComposeFiles[0], []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	body := `{"content":"services:\n  web:\n    image: nginx\n"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/stacks/"+stack.ID+"/file?kind=compose&index=0", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"rolled_back":true`) {
		t.Fatalf("body = %s, want rolled_back:true", rec.Body.String())
	}

	saved, err := os.ReadFile(stack.ComposeFiles[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(saved) != original {
		t.Fatalf("content = %q, want the original %q restored", saved, original)
	}
}

func TestHandleStackFileWriteRejectsWorkingDirOutsideAllowList(t *testing.T) {
	writeFakeDocker(t, false)
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{t.TempDir()}

	// The guard resolves symlinks (and therefore existence) before checking
	// the allow-list, so the target must exist for the allow-list rejection to
	// be reachable; a missing file would surface as 404 first.
	if err := os.WriteFile(stack.ComposeFiles[0], []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	body := `{"content":"services: {}\n"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/stacks/"+stack.ID+"/file?kind=compose&index=0", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleStackFileWriteRecordsHistoryWithByteDelta(t *testing.T) {
	writeFakeDocker(t, false)
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	original := "services: {}\n"
	if err := os.WriteFile(stack.ComposeFiles[0], []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	content := "services:\n  web:\n    image: nginx\n"
	body := fmt.Sprintf(`{"content":%q}`, content)
	req := httptest.NewRequest(http.MethodPut,
		"/api/stacks/"+stack.ID+"/file?kind=compose&index=0", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	entries := srv.StackHistory.ListByStackFiltered(stack.ID, stacks.HistoryFilter{
		Action: "edit compose",
		Status: "success",
	})
	if len(entries) != 1 {
		t.Fatalf("history entries = %d, want 1", len(entries))
	}

	want := fmt.Sprintf("%+d bytes", len(content)-len(original))
	if !strings.Contains(entries[0].Message, want) {
		t.Fatalf("history message = %q, want it to contain %q", entries[0].Message, want)
	}
}

func TestHandleStackFileWriteRejectsAgentHostedStack(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	// A stack hosted on a remote agent stores paths that are only valid on the
	// agent host. The save path must fail closed rather than resolve them
	// against this server's local filesystem.
	stack.AgentID = "agent-1"
	if _, err := srv.StackStore.Save(stack); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	original := "services: {}\n"
	if err := os.WriteFile(stack.ComposeFiles[0], []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	body := `{"content":"services:\n  web:\n    image: nginx\n"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/stacks/"+stack.ID+"/file?kind=compose&index=0", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleStackByID(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (body=%s)", rec.Code, rec.Body.String())
	}

	saved, err := os.ReadFile(stack.ComposeFiles[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(saved) != original {
		t.Fatalf("content = %q, want the original %q (agent save must not touch the file)", saved, original)
	}
}

func TestHandleStackFileRoutesFailClosedForAgentHostedStack(t *testing.T) {
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	original := "services:\n  web:\n    image: nginx\n"
	if err := os.WriteFile(stack.ComposeFiles[0], []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	stack.AgentID = "agent-1"
	if _, err := srv.StackStore.Save(stack); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	tests := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{name: "list", method: http.MethodGet, target: "/api/stacks/" + stack.ID + "/files"},
		{name: "read", method: http.MethodGet, target: "/api/stacks/" + stack.ID + "/file?kind=compose&index=0"},
		{name: "validate", method: http.MethodPost, target: "/api/stacks/" + stack.ID + "/file/validate?kind=compose&index=0", body: `{"content":"services: {}"}`},
		{name: "write", method: http.MethodPut, target: "/api/stacks/" + stack.ID + "/file?kind=compose&index=0", body: `{"content":"services:\n  web:\n    image: nginx\n"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			srv.handleStackByID(rec, req)

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501 (body=%s)", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "image: nginx") {
				t.Fatalf("body = %s, must not leak the file content", rec.Body.String())
			}
		})
	}

	saved, err := os.ReadFile(stack.ComposeFiles[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(saved) != original {
		t.Fatalf("content = %q, want the original %q (agent file routes must not touch the file)", saved, original)
	}
}

func TestHandleStackFileRejectsOversizedRequestBody(t *testing.T) {
	writeFakeDocker(t, false)
	srv, stack := newTestStackServer(t)
	srv.AllowedPaths = []string{filepath.Dir(stack.WorkingDir)}

	original := "services: {}\n"
	if err := os.WriteFile(stack.ComposeFiles[0], []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// The decoded content is tiny, but the raw body is padded past the decode
	// cap, so a 413 here proves MaxBytesReader is applied before the
	// post-decode content check.
	oversized := `{"content":"services: {}"` + strings.Repeat(" ", stacks.MaxEditableFileBytes+4096) + `}`
	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "validate", method: http.MethodPost, target: "/api/stacks/" + stack.ID + "/file/validate?kind=compose&index=0"},
		{name: "write", method: http.MethodPut, target: "/api/stacks/" + stack.ID + "/file?kind=compose&index=0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(oversized))
			rec := httptest.NewRecorder()
			srv.handleStackByID(rec, req)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413 (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}

	saved, err := os.ReadFile(stack.ComposeFiles[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(saved) != original {
		t.Fatalf("content = %q, want the original %q (oversized body must not touch the file)", saved, original)
	}
}

func TestHandleStackFilesListsResolvedGuardedTargets(t *testing.T) {
	srv, stack := newTestStackServer(t)

	mappedDir := t.TempDir()
	compose := filepath.Join(mappedDir, "compose.yaml")
	if err := os.WriteFile(compose, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	stack.PathMode = stacks.PathModeMapped
	stack.PathMappings = []stacks.PathMapping{{HostPath: "/host/docker", ContainerPath: mappedDir}}
	stack.ComposeFiles = []string{"/host/docker/compose.yaml"}
	if _, err := srv.StackStore.Save(stack); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	t.Run("inside allow-list", func(t *testing.T) {
		srv.AllowedPaths = []string{mappedDir}
		req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/files", nil)
		rec := httptest.NewRecorder()
		srv.handleStackByID(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		wantPath := fmt.Sprintf(`"path":%q`, compose)
		if !strings.Contains(body, wantPath) {
			t.Fatalf("body = %s, want the resolved path %q", body, compose)
		}
		if !strings.Contains(body, `"exists":true`) {
			t.Fatalf("body = %s, want exists:true", body)
		}
		if !strings.Contains(body, `"editable":true`) {
			t.Fatalf("body = %s, want editable:true", body)
		}
		if !strings.Contains(body, `"size":13`) {
			t.Fatalf("body = %s, want the resolved size", body)
		}
	})

	t.Run("outside allow-list is not editable", func(t *testing.T) {
		srv.AllowedPaths = []string{t.TempDir()}
		req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/files", nil)
		rec := httptest.NewRecorder()
		srv.handleStackByID(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"exists":true`) {
			t.Fatalf("body = %s, want exists:true", body)
		}
		if !strings.Contains(body, `"editable":false`) {
			t.Fatalf("body = %s, want editable:false", body)
		}
	})

	t.Run("missing target is not editable", func(t *testing.T) {
		srv.AllowedPaths = []string{mappedDir}
		stack.ComposeFiles = []string{"/host/docker/missing.yaml"}
		if _, err := srv.StackStore.Save(stack); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+stack.ID+"/files", nil)
		rec := httptest.NewRecorder()
		srv.handleStackByID(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"exists":false`) {
			t.Fatalf("body = %s, want exists:false", body)
		}
		if !strings.Contains(body, `"editable":false`) {
			t.Fatalf("body = %s, want editable:false", body)
		}
	})
}
