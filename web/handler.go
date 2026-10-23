// Package webui serves the operator web application (HP-UI-016). Release and container builds embed web/dist with
// the embedui build tag; other builds serve a short notice instead.
package webui

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// Handler serves the UI: hashed assets are immutable and cached, every other path gets index.html (client-side
// routing) with no-cache. Missing asset files are 404, never index.html, so broken references fail visibly.
func Handler(files fs.FS) http.Handler {
	if files == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "The Hallpass web UI is not included in this build (build with -tags embedui after `pnpm build`).\n")
		})
	}
	assets := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if strings.HasPrefix(p, "/assets/") || isStaticFile(files, p) {
			if strings.HasPrefix(p, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			if _, err := fs.Stat(files, strings.TrimPrefix(p, "/")); err != nil {
				http.NotFound(w, r)
				return
			}
			assets.ServeHTTP(w, r)
			return
		}
		index, err := fs.ReadFile(files, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}

// isStaticFile reports top-level files such as /favicon.svg (but not index.html, which is served for every route).
func isStaticFile(files fs.FS, p string) bool {
	name := strings.TrimPrefix(p, "/")
	if name == "" || name == "index.html" || strings.Contains(name, "/") || !strings.Contains(name, ".") {
		return false
	}
	_, err := fs.Stat(files, name)
	return err == nil
}
