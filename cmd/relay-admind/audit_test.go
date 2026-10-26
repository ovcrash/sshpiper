package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tg123/sshpiper/auditindex"
	"github.com/tg123/sshpiper/registry"
	"github.com/tg123/sshpiper/relayadmin"
)

const auditSha = "0000000000000000000000000000000000000000000000000000000000000001"

func newAuditServer(t *testing.T, withAudit bool) *httptest.Server {
	t.Helper()
	db, err := registry.Open(filepath.Join(t.TempDir(), "r.db"), registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := &server{svc: relayadmin.New(db)}
	if withAudit {
		root := t.TempDir()
		dir := filepath.Join(root, "2026-01-02", "11111111-1111-1111-1111-111111111111")
		if err := os.MkdirAll(filepath.Join(dir, "files"), 0o700); err != nil {
			t.Fatal(err)
		}
		events := strings.Join([]string{
			`{"eventid":"piper.session.connect","timestamp":"2026-01-02T10:00:00.000000Z","src_ip":"198.51.100.7","dst_ip":"203.0.113.10","dst_port":22}`,
			`{"eventid":"piper.login.success","timestamp":"2026-01-02T10:00:02.000000Z","username":"root"}`,
			`{"eventid":"piper.file.upload","timestamp":"2026-01-02T10:00:04.000000Z","filename":"x","transfer":"upload","shasum":"` + auditSha + `","size":5}`,
		}, "\n") + "\n"
		write := func(name, content string) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write("events.jsonl", events)
		write("channel-0.cast", "[0,\"o\",\"hi\"]\n")
		if err := os.WriteFile(filepath.Join(dir, "files", auditSha), []byte("hello"), 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := auditindex.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		srv.audit = store
	}
	ts := httptest.NewServer(requireToken(testToken, srv.routes()))
	t.Cleanup(ts.Close)
	return ts
}

func TestAuditDisabled(t *testing.T) {
	ts := newAuditServer(t, false)
	if code, _ := do(t, ts, "GET", "/v1/audit/sessions", testToken, ""); code != http.StatusNotFound {
		t.Errorf("audit disabled: got %d, want 404", code)
	}
}

func TestAuditSessionsAndDetail(t *testing.T) {
	ts := newAuditServer(t, true)

	code, body := do(t, ts, "GET", "/v1/audit/sessions", testToken, "")
	if code != http.StatusOK || !strings.Contains(body, "203.0.113.10") {
		t.Fatalf("sessions: %d %s", code, body)
	}

	// filter by external IP
	if _, b := do(t, ts, "GET", "/v1/audit/sessions?ip=203.0.113.10", testToken, ""); !strings.Contains(b, "11111111") {
		t.Errorf("filter missed the session: %s", b)
	}
	if _, b := do(t, ts, "GET", "/v1/audit/sessions?ip=10.0.0.1", testToken, ""); strings.Contains(b, "11111111") {
		t.Errorf("filter should exclude: %s", b)
	}

	code, body = do(t, ts, "GET", "/v1/audit/sessions/2026-01-02/11111111-1111-1111-1111-111111111111", testToken, "")
	if code != http.StatusOK || !strings.Contains(body, "channel-0.cast") || !strings.Contains(body, auditSha) {
		t.Fatalf("detail: %d %s", code, body)
	}
}

func TestAuditCastAndFile(t *testing.T) {
	ts := newAuditServer(t, true)
	base := "/v1/audit/sessions/2026-01-02/11111111-1111-1111-1111-111111111111"

	if code, body := do(t, ts, "GET", base+"/cast/channel-0.cast", testToken, ""); code != http.StatusOK || !strings.Contains(body, `"o"`) {
		t.Errorf("cast: %d %s", code, body)
	}
	if code, body := do(t, ts, "GET", base+"/files/"+auditSha, testToken, ""); code != http.StatusOK || body != "hello" {
		t.Errorf("file: %d %q", code, body)
	}
	// bad sha and bad cast name are rejected
	if code, _ := do(t, ts, "GET", base+"/files/nothex", testToken, ""); code != http.StatusNotFound {
		t.Errorf("bad sha: got %d, want 404", code)
	}
}

// The static carve-out: non-/v1 paths skip the token (so a browser can load
// the console), while /v1/* still demands it.
func TestStaticCarveOut(t *testing.T) {
	ts := newAuditServer(t, true)
	// "/" has no handler yet, but it must NOT be a 401 (token not required).
	if code, _ := do(t, ts, "GET", "/", "", ""); code == http.StatusUnauthorized {
		t.Errorf("static path should not require a token, got 401")
	}
	if code, _ := do(t, ts, "GET", "/v1/audit/sessions", "", ""); code != http.StatusUnauthorized {
		t.Errorf("/v1 without token: got %d, want 401", code)
	}
}
