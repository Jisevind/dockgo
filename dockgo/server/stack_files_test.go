package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

	// The action itself cannot run without Docker here, but it must get past
	// the guard: anything other than 403 proves the allow-list admitted it.
	if rec.Code == http.StatusForbidden {
		t.Fatalf("status = 403, want the guard to admit an allowed directory (body=%s)", rec.Body.String())
	}
}
