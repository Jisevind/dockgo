package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
