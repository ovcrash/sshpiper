package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tg123/sshpiper/registry"
	"github.com/tg123/sshpiper/relayadmin"
)

const testToken = "secret-token"

func newTestServer(t *testing.T) (*httptest.Server, *registry.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "r.db")
	db, err := registry.Open(path, registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := &server{svc: relayadmin.New(db)}
	ts := httptest.NewServer(requireToken(testToken, srv.routes()))
	t.Cleanup(ts.Close)
	return ts, db
}

func do(t *testing.T, ts *httptest.Server, method, path, token, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAuth(t *testing.T) {
	ts, _ := newTestServer(t)

	if code, _ := do(t, ts, "GET", "/v1/entries", "", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", code)
	}
	if code, _ := do(t, ts, "GET", "/v1/entries", "wrong", ""); code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d, want 401", code)
	}
	if code, _ := do(t, ts, "GET", "/v1/entries", testToken, ""); code != http.StatusOK {
		t.Errorf("good token: %d, want 200", code)
	}
	// healthz needs no token
	if code, _ := do(t, ts, "GET", "/v1/healthz", "", ""); code != http.StatusOK {
		t.Errorf("healthz: %d, want 200", code)
	}
}

func TestCreateValidationAndRedaction(t *testing.T) {
	ts, _ := newTestServer(t)

	// missing auth method
	if code, _ := do(t, ts, "POST", "/v1/entries", testToken, `{"external_ip":"203.0.113.10","username":"u","backend_host":"h"}`); code != http.StatusBadRequest {
		t.Fatalf("no method: %d, want 400", code)
	}

	code, body := do(t, ts, "POST", "/v1/entries", testToken, `{"external_ip":"203.0.113.10","username":"u","backend_host":"h","password":"s3cret-pw"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	if strings.Contains(body, "s3cret-pw") {
		t.Fatalf("create response leaks the password: %s", body)
	}

	// duplicate IP -> 409
	if code, _ := do(t, ts, "POST", "/v1/entries", testToken, `{"external_ip":"203.0.113.10","username":"u","backend_host":"h","password":"x"}`); code != http.StatusConflict {
		t.Fatalf("duplicate: %d, want 409", code)
	}

	// list and get never leak secrets
	_, list := do(t, ts, "GET", "/v1/entries", testToken, "")
	if strings.Contains(list, "s3cret-pw") {
		t.Fatal("list leaks the password")
	}
	code, get := do(t, ts, "GET", "/v1/entries/203.0.113.10", testToken, "")
	if code != http.StatusOK || strings.Contains(get, "s3cret-pw") {
		t.Fatalf("get: %d, leak=%v", code, strings.Contains(get, "s3cret-pw"))
	}

	// unknown IP -> 404
	if code, _ := do(t, ts, "GET", "/v1/entries/203.0.113.99", testToken, ""); code != http.StatusNotFound {
		t.Fatalf("unknown: %d, want 404", code)
	}
}

func TestLifecycleAndNoRestart(t *testing.T) {
	ts, db := newTestServer(t)

	// a read-only handle, like the daemon, opened on the same file
	ro, err := registry.Open(db.Path(), registry.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()

	if code, b := do(t, ts, "POST", "/v1/entries", testToken, `{"external_ip":"203.0.113.20","username":"u","backend_host":"10.0.0.21","password":"pw"}`); code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, b)
	}
	// the daemon-like reader sees the new entry immediately (no restart)
	if _, err := ro.ByExternalIP(context.Background(), "203.0.113.20"); err != nil {
		t.Fatalf("reader does not see the new entry: %v", err)
	}

	// generate host keys, then export them (private keys returned)
	if code, b := do(t, ts, "POST", "/v1/entries/203.0.113.20/persona/generate", testToken, ""); code != http.StatusOK {
		t.Fatalf("gen: %d %s", code, b)
	}
	code, keys := do(t, ts, "GET", "/v1/entries/203.0.113.20/persona/keys", testToken, "")
	if code != http.StatusOK {
		t.Fatalf("export keys: %d", code)
	}
	var hk registry.HostKeys
	if err := json.Unmarshal([]byte(keys), &hk); err != nil {
		t.Fatal(err)
	}
	if err := hk.Validate(); err != nil {
		t.Fatalf("exported keys invalid: %v", err)
	}

	// expose before a successful probe is refused (409: bad transition)
	if code, _ := do(t, ts, "POST", "/v1/entries/203.0.113.20/expose", testToken, ""); code == http.StatusOK {
		t.Fatal("expose before ready should fail")
	}

	// retire works and the reader sees it
	if code, _ := do(t, ts, "POST", "/v1/entries/203.0.113.20/retire", testToken, "{}"); code != http.StatusOK {
		t.Fatal("retire failed")
	}
	e, _ := ro.ByExternalIP(context.Background(), "203.0.113.20")
	if e.State != registry.StateRetired {
		t.Fatalf("reader sees state %s after retire", e.State)
	}
}
