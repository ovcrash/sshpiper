package main

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/tg123/sshpiper/auditindex"
)

// auditReady writes 404 and returns false when --audit-dir was not set.
func (s *server) auditReady(w http.ResponseWriter) bool {
	if s.audit == nil {
		writeError(w, http.StatusNotFound, "audit browsing is disabled (set --audit-dir)")
		return false
	}
	return true
}

func (s *server) auditSessions(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	list, err := s.audit.Sessions(r.URL.Query().Get("ip"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *server) auditSession(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	d, err := s.audit.Session(r.PathValue("day"), r.PathValue("id"))
	if err != nil {
		writeAuditError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *server) auditCast(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	rc, err := s.audit.Cast(r.PathValue("day"), r.PathValue("id"), r.PathValue("channel"))
	if err != nil {
		writeAuditError(w, err)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, rc)
}

func (s *server) auditFile(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	sha := r.PathValue("sha")
	rc, size, err := s.audit.File(r.PathValue("day"), r.PathValue("id"), sha)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition", `attachment; filename="`+sha+`"`)
	_, _ = io.Copy(w, rc)
}

func writeAuditError(w http.ResponseWriter, err error) {
	if errors.Is(err, auditindex.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}
