package server

import (
	"io/fs"
	"mime"
	"net/http"
	"net/url"
)

func init() {
	// Alpine does not ship a MIME database by default, so register the icon
	// font type explicitly instead of relying on the host system.
	_ = mime.AddExtensionType(".woff2", "font/woff2")
}

// webPages maps each standalone page URL to its document in the embedded web
// assets.
var webPages = map[string]string{
	"/dashboard":  "dashboard.html",
	"/agents":     "agents.html",
	"/networks":   "networks.html",
	"/images":     "images.html",
	"/volumes":    "volumes.html",
	"/containers": "containers.html",
	"/stacks":     "stacks.html",
	"/stacks/new": "stacks-new.html",
}

// buildWebHandler serves the embedded dashboard assets and gives each
// standalone page its own URL. Registered page routes must stay ahead of the
// catch-all file server.
func buildWebHandler(webFS fs.FS) http.Handler {
	mux := http.NewServeMux()

	for path, document := range webPages {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, webFS, document)
		})
		mux.HandleFunc("GET "+path+"/{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, path, http.StatusMovedPermanently)
		})
	}

	mux.HandleFunc("GET /stacks/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, webFS, "stack-editor.html")
	})
	mux.HandleFunc("GET /stacks/{id}/files/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r,
			"/stacks/"+url.PathEscape(r.PathValue("id"))+"/files",
			http.StatusMovedPermanently)
	})

	mux.HandleFunc("GET /volumes/{name}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, webFS, "volume.html")
	})
	mux.HandleFunc("GET /volumes/{name}/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/volumes/"+url.PathEscape(r.PathValue("name")), http.StatusMovedPermanently)
	})

	mux.Handle("/", http.FileServer(http.FS(webFS)))
	return mux
}
