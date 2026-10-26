package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tg123/sshpiper/auditindex"
	"github.com/tg123/sshpiper/registry"
	"github.com/tg123/sshpiper/relayadmin"
)

type server struct {
	svc     *relayadmin.Service
	audit   *auditindex.Store // nil when --audit-dir is unset
	webPath string            // --web-static-path: "" embedded, "disable", or a dir
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/entries", s.createEntry)
	mux.HandleFunc("GET /v1/entries", s.listEntries)
	mux.HandleFunc("GET /v1/entries/{ip}", s.getEntry)
	mux.HandleFunc("POST /v1/entries/{ip}/persona/generate", s.genPersona)
	mux.HandleFunc("POST /v1/entries/{ip}/persona/import", s.importPersona)
	mux.HandleFunc("GET /v1/entries/{ip}/persona/keys", s.exportKeys)
	mux.HandleFunc("POST /v1/entries/{ip}/probe", s.probe)
	mux.HandleFunc("POST /v1/entries/{ip}/expose", s.expose)
	mux.HandleFunc("POST /v1/entries/{ip}/retire", s.retire)

	// read-only audit browsing (enabled by --audit-dir)
	mux.HandleFunc("GET /v1/audit/sessions", s.auditSessions)
	mux.HandleFunc("GET /v1/audit/sessions/{day}/{id}", s.auditSession)
	mux.HandleFunc("GET /v1/audit/sessions/{day}/{id}/cast/{channel}", s.auditCast)
	mux.HandleFunc("GET /v1/audit/sessions/{day}/{id}/files/{sha}", s.auditFile)

	// console UI (catch-all; the /v1/* patterns above take precedence)
	mux.Handle("/", staticHandler(s.webPath))
	return mux
}

// --- JSON shapes ---

type createRequest struct {
	ExternalIP  string `json:"external_ip"`
	Username    string `json:"username"`
	BackendHost string `json:"backend_host"`
	BackendPort int    `json:"backend_port"`
	Password    string `json:"password"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
}

type entryView struct {
	ID           int64  `json:"id"`
	ExternalIP   string `json:"external_ip"`
	Username     string `json:"username"`
	AuthPassword bool   `json:"auth_password"`
	AuthKey      bool   `json:"auth_key"`
	BackendHost  string `json:"backend_host"`
	BackendPort  int    `json:"backend_port"`
	State        string `json:"state"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	RetiredAt    string `json:"retired_at,omitempty"`
}

// view returns a secret-free view of an entry.
func view(e *registry.Entry) entryView {
	return entryView{
		ID: e.ID, ExternalIP: e.ExternalIP, Username: e.Username,
		AuthPassword: e.AuthPassword, AuthKey: e.AuthKey,
		BackendHost: e.BackendHost, BackendPort: e.BackendPort,
		State: string(e.State), CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, RetiredAt: e.RetiredAt,
	}
}

// --- handlers ---

func (s *server) createEntry(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decode(w, r, &req) {
		return
	}
	e, err := s.svc.AddEntry(r.Context(), registry.NewEntry{
		ExternalIP:  req.ExternalIP,
		Username:    req.Username,
		BackendHost: req.BackendHost,
		BackendPort: req.BackendPort,
		Password:    req.Password,
		PublicKey:   req.PublicKey,
		PrivateKey:  req.PrivateKey,
	})
	if err != nil {
		writeOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view(e))
}

func (s *server) listEntries(w http.ResponseWriter, r *http.Request) {
	entries, err := s.svc.List(r.Context())
	if err != nil {
		writeOpError(w, err)
		return
	}
	out := make([]entryView, 0, len(entries))
	for _, e := range entries {
		out = append(out, view(e))
	}
	writeJSON(w, http.StatusOK, out)
}

type entryDetail struct {
	entryView
	Persona *personaView `json:"persona,omitempty"`
	Events  []eventView  `json:"events,omitempty"`
}

type personaView struct {
	HasHostKeys bool   `json:"has_host_keys"`
	SSHVersion  string `json:"ssh_version,omitempty"`
	HASSHServer string `json:"hassh_server,omitempty"`
	AuthMethods string `json:"auth_methods,omitempty"`
	ProbedAt    string `json:"probed_at,omitempty"`
}

type eventView struct {
	Event  string `json:"event"`
	At     string `json:"at"`
	Detail string `json:"detail,omitempty"`
}

func (s *server) getEntry(w http.ResponseWriter, r *http.Request) {
	e := s.lookup(w, r)
	if e == nil {
		return
	}
	d := entryDetail{entryView: view(e)}
	if p, err := s.svc.Persona(r.Context(), e.ID); err == nil {
		d.Persona = &personaView{HasHostKeys: p.HasHostKeys(), SSHVersion: p.SSHVersion, HASSHServer: p.HASSHServer, AuthMethods: p.AuthMethods, ProbedAt: p.ProbedAt}
	}
	if evs, err := s.svc.Events(r.Context(), e.ID); err == nil {
		for _, ev := range evs {
			d.Events = append(d.Events, eventView{Event: ev.Event, At: ev.At, Detail: ev.Detail})
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *server) genPersona(w http.ResponseWriter, r *http.Request) {
	e := s.lookup(w, r)
	if e == nil {
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	if err := s.svc.GenPersona(r.Context(), e, req.Force); err != nil {
		writeOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "host keys generated"})
}

func (s *server) importPersona(w http.ResponseWriter, r *http.Request) {
	e := s.lookup(w, r)
	if e == nil {
		return
	}
	var hk registry.HostKeys
	if !decode(w, r, &hk) {
		return
	}
	if err := s.svc.ImportPersonaKeys(r.Context(), e, hk); err != nil {
		writeOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "host keys imported"})
}

func (s *server) exportKeys(w http.ResponseWriter, r *http.Request) {
	e := s.lookup(w, r)
	if e == nil {
		return
	}
	hk, err := s.svc.ExportKeys(r.Context(), e.ID)
	if err != nil {
		writeOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hk)
}

func (s *server) probe(w http.ResponseWriter, r *http.Request) {
	e := s.lookup(w, r)
	if e == nil {
		return
	}
	res, err := s.svc.Probe(r.Context(), e)
	if err != nil {
		writeOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) expose(w http.ResponseWriter, r *http.Request) {
	e := s.lookup(w, r)
	if e == nil {
		return
	}
	if err := s.svc.Expose(r.Context(), e); err != nil {
		writeOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view(e))
}

func (s *server) retire(w http.ResponseWriter, r *http.Request) {
	e := s.lookup(w, r)
	if e == nil {
		return
	}
	var req struct {
		HookCmd string `json:"hook_cmd"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.svc.Retire(r.Context(), e); err != nil {
		writeOpError(w, err)
		return
	}
	if err := s.svc.RunRetireHook(r.Context(), e, req.HookCmd); err != nil {
		writeError(w, http.StatusInternalServerError, "retired, but the hook failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view(e))
}

// lookup resolves {ip}; writes 404 and returns nil if unknown.
func (s *server) lookup(w http.ResponseWriter, r *http.Request) *registry.Entry {
	e, err := s.svc.Get(r.Context(), r.PathValue("ip"))
	if err != nil {
		writeOpError(w, err)
		return nil
	}
	return e
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeOpError maps a service error to an HTTP status.
func writeOpError(w http.ResponseWriter, err error) {
	var te *registry.TransitionError
	switch {
	case errors.Is(err, registry.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, registry.ErrExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.As(err, &te):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}
