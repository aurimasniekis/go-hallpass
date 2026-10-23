package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHandler(t *testing.T) {
	files := fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html><title>Hallpass</title>")},
		"favicon.svg":          {Data: []byte("<svg/>")},
		"assets/app-abc123.js": {Data: []byte("console.log(1)")},
	}
	h := Handler(files)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	if r := get("/requests/req_1"); r.Code != 200 || !strings.Contains(r.Body.String(), "Hallpass") || r.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("SPA route: %d %v", r.Code, r.Header())
	}
	if r := get("/assets/app-abc123.js"); r.Code != 200 || !strings.Contains(r.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %v", r.Code, r.Header())
	}
	if r := get("/assets/missing.js"); r.Code != 404 {
		t.Fatalf("missing asset: %d", r.Code)
	}
	if r := get("/favicon.svg"); r.Code != 200 {
		t.Fatalf("favicon: %d", r.Code)
	}
	if r := get("/../../etc/passwd"); r.Code != 200 || strings.Contains(r.Body.String(), "root:") {
		t.Fatalf("traversal: %d", r.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != 405 {
		t.Fatalf("POST: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	Handler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 404 {
		t.Fatalf("no UI: %d", rec.Code)
	}
	if _, ok := Dist(); ok {
		t.Fatal("Dist without embedui tag")
	}
}
