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
		"dashboard.html":    {Data: []byte("<!doctype html><title>new dashboard page</title>")},
		"agents.html":       {Data: []byte("<!doctype html><title>agents page</title>")},
		"networks.html":     {Data: []byte("<!doctype html><title>networks page</title>")},
		"images.html":       {Data: []byte("<!doctype html><title>images page</title>")},
		"volumes.html":      {Data: []byte("<!doctype html><title>volumes page</title>")},
		"volume.html":       {Data: []byte("<!doctype html><title>volume overview</title>")},
		"containers.html":   {Data: []byte("<!doctype html><title>containers page</title>")},
		"stacks.html":       {Data: []byte("<!doctype html><title>stacks page</title>")},
		"stack-form.html":   {Data: []byte("<!doctype html><title>stack form page</title>")},
		"stack-editor.html": {Data: []byte("<!doctype html><title>stack editor page</title>")},
		"stack-detail.html": {Data: []byte("<!doctype html><title>stack detail page</title>")},
		"style.css":         {Data: []byte("body{}")},
		"font.woff2":        {Data: []byte("wOF2")},
	}
}

func TestWebHandlerServesStandalonePagesAtOwnURLs(t *testing.T) {
	handler := buildWebHandler(testWebFS())

	for path, want := range map[string]string{
		"/dashboard":       "new dashboard page",
		"/agents":          "agents page",
		"/networks":        "networks page",
		"/images":          "images page",
		"/volumes":         "volumes page",
		"/volumes/data":    "volume overview",
		"/containers":      "containers page",
		"/stacks":          "stacks page",
		"/stacks/new":      "stack form page",
		"/stacks/s1":       "stack detail page",
		"/stacks/s1/edit":  "stack form page",
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

	for _, page := range []string{"/dashboard", "/agents", "/networks", "/images", "/volumes", "/stacks/s1"} {
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

func TestWebHandlerServesWoff2WithFontMimeType(t *testing.T) {
	handler := buildWebHandler(testWebFS())
	req := httptest.NewRequest(http.MethodGet, "/font.woff2", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /font.woff2 status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "font/woff2" {
		t.Fatalf("Content-Type = %q, want font/woff2", got)
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
