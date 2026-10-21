package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func testWebFS() fs.FS {
	return fstest.MapFS{
		"index.html":        {Data: []byte("<!doctype html><title>dashboard</title>")},
		"networks.html":     {Data: []byte("<!doctype html><title>networks page</title>")},
		"images.html":       {Data: []byte("<!doctype html><title>images page</title>")},
		"volumes.html":      {Data: []byte("<!doctype html><title>volumes page</title>")},
		"volume.html":       {Data: []byte("<!doctype html><title>volume overview</title>")},
		"containers.html":   {Data: []byte("<!doctype html><title>containers page</title>")},
		"stacks.html":       {Data: []byte("<!doctype html><title>stacks page</title>")},
		"stacks-new.html":   {Data: []byte("<!doctype html><title>add stack page</title>")},
		"stack-editor.html": {Data: []byte("<!doctype html><title>stack editor page</title>")},
		"style.css":         {Data: []byte("body{}")},
	}
}

func TestWebHandlerServesStandalonePagesAtOwnURLs(t *testing.T) {
	handler := buildWebHandler(testWebFS())

	for path, want := range map[string]string{
		"/networks":        "networks page",
		"/images":          "images page",
		"/volumes":         "volumes page",
		"/volumes/data":    "volume overview",
		"/containers":      "containers page",
		"/stacks":          "stacks page",
		"/stacks/new":      "add stack page",
		"/stacks/s1/files": "stack editor page",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, rr.Code)
			continue
		}
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("GET %s body = %q, want the %s document", path, rr.Body.String(), want)
		}
	}
}

func TestWebHandlerRedirectsTrailingSlash(t *testing.T) {
	handler := buildWebHandler(testWebFS())

	for _, page := range []string{"/networks", "/images", "/volumes"} {
		req := httptest.NewRequest(http.MethodGet, page+"/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMovedPermanently {
			t.Errorf("GET %s/ status = %d, want 301", page, rr.Code)
			continue
		}
		if got := rr.Header().Get("Location"); got != page {
			t.Errorf("GET %s/ Location = %q, want %s", page, got, page)
		}
	}
}

func TestWebHandlerStillServesDashboardAndAssets(t *testing.T) {
	handler := buildWebHandler(testWebFS())

	for path, want := range map[string]string{
		"/":          "dashboard",
		"/style.css": "body{}",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, rr.Code)
			continue
		}
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("GET %s body = %q, want it to contain %q", path, rr.Body.String(), want)
		}
	}
}
