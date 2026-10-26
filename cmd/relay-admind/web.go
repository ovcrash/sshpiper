package main

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
)

//go:embed web/index.html
//go:embed all:web/dist
var webFS embed.FS

// staticHandler serves the embedded console UI (path == ""), a directory on
// disk (useful with `npm run watch` during development), or nothing
// (path == "disable", API only).
func staticHandler(path string) http.Handler {
	switch path {
	case "disable":
		slog.Info("console UI disabled (--web-static-path=disable); only the API is served")
		return http.NotFoundHandler()
	case "":
		sub, err := fs.Sub(webFS, "web")
		if err != nil {
			slog.Error("console UI unavailable: cannot open embedded web/", "error", err)
			return http.NotFoundHandler()
		}
		return http.FileServer(noListing{http.FS(sub)})
	default:
		slog.Info("serving console UI from disk", "path", path)
		return http.FileServer(noListing{http.Dir(path)})
	}
}

// noListing wraps a filesystem so directory requests without an index.html
// return 404 instead of a generated listing.
type noListing struct{ fs http.FileSystem }

func (n noListing) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if stat.IsDir() {
		idx, err := n.fs.Open(strings.TrimSuffix(name, "/") + "/index.html")
		if err != nil {
			_ = f.Close()
			return nil, fs.ErrNotExist
		}
		_ = idx.Close()
	}
	return f, nil
}
