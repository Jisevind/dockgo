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

	// An admitted directory must not be rejected: the request proceeds to the
	// next gate, which for this unbound stack is the "blocked while unbound"
	// conflict. Nothing downstream differs between an admitted request and an
	// unguarded one, so this test cannot prove the guard exists - that comes
	// from the rejection test above. Its job is to catch over-restriction.
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
	}
}
