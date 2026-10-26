package auditindex

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSession lays down a session directory the way the daemon would. It sets
// the directory mtime to the day (Sessions orders by mtime, as on a live
// sensor), so sessions on later days sort ahead of earlier ones.
func writeSession(t *testing.T, root, day, id string, lines []string, casts map[string]string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(root, day, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := strings.Join(lines, "\n")
	if len(lines) > 0 {
		body += "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range casts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(files) > 0 {
		fdir := filepath.Join(dir, "files")
		if err := os.MkdirAll(filepath.Join(fdir, "tmp"), 0o700); err != nil {
			t.Fatal(err)
		}
		for sha, content := range files {
			if err := os.WriteFile(filepath.Join(fdir, sha), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// a staging file that must never surface
		if err := os.WriteFile(filepath.Join(fdir, "tmp", "partial"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Set the dir mtime to the day so mtime-based ordering matches the dates.
	if d, err := time.Parse("2006-01-02", day); err == nil {
		_ = os.Chtimes(dir, d, d)
	}
}

const sha1 = "0000000000000000000000000000000000000000000000000000000000000001"

func seed(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	// session A on 203.0.113.10: one failed + one ok login, one command, a cast, a file
	writeSession(t, root, "2026-01-02", "11111111-1111-1111-1111-111111111111",
		[]string{
			`{"eventid":"piper.session.connect","timestamp":"2026-01-02T10:00:00.000000Z","src_ip":"198.51.100.7","src_port":40000,"dst_ip":"203.0.113.10","dst_port":22}`,
			`{"eventid":"piper.client.version","timestamp":"2026-01-02T10:00:00.100000Z","version":"SSH-2.0-OpenSSH_9.6","hassh":"abc"}`,
			`{"eventid":"piper.login.failed","timestamp":"2026-01-02T10:00:01.000000Z","username":"root","password":"123"}`,
			`{"eventid":"piper.login.success","timestamp":"2026-01-02T10:00:02.000000Z","username":"root","password":"toor"}`,
			`{"eventid":"piper.command.input","timestamp":"2026-01-02T10:00:03.000000Z","input":"whoami"}`,
			`{"eventid":"piper.file.upload","timestamp":"2026-01-02T10:00:04.000000Z","filename":"loot.sh","transfer":"upload","shasum":"` + sha1 + `","size":5}`,
			`{"eventid":"piper.session.closed","timestamp":"2026-01-02T10:00:05.000000Z"}`,
		},
		map[string]string{"channel-0.cast": "[0,\"o\",\"hi\"]\n"},
		map[string]string{sha1: "hello"},
	)
	// session B on a different external IP, no login success
	writeSession(t, root, "2026-01-03", "22222222-2222-2222-2222-222222222222",
		[]string{
			`{"eventid":"piper.session.connect","timestamp":"2026-01-03T09:00:00.000000Z","src_ip":"198.51.100.8","src_port":41000,"dst_ip":"203.0.113.20","dst_port":22}`,
			`{"eventid":"piper.login.failed","timestamp":"2026-01-03T09:00:01.000000Z","username":"admin"}`,
		},
		nil, nil,
	)
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSessionsListAndFilter(t *testing.T) {
	s := seed(t)
	all, err := s.Sessions("", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(all))
	}
	// newest first: 2026-01-03 before 2026-01-02
	if all[0].Day != "2026-01-03" {
		t.Errorf("want newest first, got %s", all[0].Day)
	}

	only, err := s.Sessions("203.0.113.10", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 1 || only[0].DstIP != "203.0.113.10" {
		t.Fatalf("filter by external IP failed: %+v", only)
	}
	a := only[0]
	if a.SrcIP != "198.51.100.7" || a.LoginAttempts != 2 || !a.LoginSuccess ||
		a.Commands != 1 || a.Channels != 1 || a.Files != 1 || a.ClientVersion != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("summary wrong: %+v", a)
	}
	if a.Start != "2026-01-02T10:00:00.000000Z" || a.End != "2026-01-02T10:00:05.000000Z" {
		t.Errorf("start/end wrong: %s..%s", a.Start, a.End)
	}
}

func TestSessionDetail(t *testing.T) {
	s := seed(t)
	d, err := s.Session("2026-01-02", "11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Events) != 7 {
		t.Errorf("want 7 events, got %d", len(d.Events))
	}
	if len(d.Casts) != 1 || d.Casts[0].Channel != "channel-0.cast" {
		t.Errorf("casts wrong: %+v", d.Casts)
	}
	if len(d.Files) != 1 || d.Files[0].Sha != sha1 || d.Files[0].Filename != "loot.sh" || d.Files[0].Transfer != "upload" {
		t.Errorf("files wrong: %+v", d.Files)
	}
	if d.Files[0].Size != int64(len("hello")) {
		t.Errorf("file size wrong: %d", d.Files[0].Size)
	}
}

func TestCastAndFileContent(t *testing.T) {
	s := seed(t)
	rc, err := s.Cast("2026-01-02", "11111111-1111-1111-1111-111111111111", "channel-0.cast")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "[0,\"o\",\"hi\"]\n" {
		t.Errorf("cast content wrong: %q", b)
	}

	fr, size, err := s.File("2026-01-02", "11111111-1111-1111-1111-111111111111", sha1)
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := io.ReadAll(fr)
	_ = fr.Close()
	if string(fb) != "hello" || size != 5 {
		t.Errorf("file content/size wrong: %q %d", fb, size)
	}
}

func TestRejectsBadInput(t *testing.T) {
	s := seed(t)
	bad := []struct{ day, id string }{
		{"../etc", "x"},
		{"2026-01-02", ".."},
		{"2026-01-02", "../../etc/passwd"},
		{"2026-13-99", "11111111-1111-1111-1111-111111111111"}, // regex-valid day but nonexistent is NotFound too
		{"2026-01-02", "has/slash"},
	}
	for _, c := range bad {
		if _, err := s.Session(c.day, c.id); err != ErrNotFound {
			t.Errorf("Session(%q,%q) = %v, want ErrNotFound", c.day, c.id, err)
		}
	}
	// cast/file name validation
	if _, err := s.Cast("2026-01-02", "11111111-1111-1111-1111-111111111111", "../../events.jsonl"); err != ErrNotFound {
		t.Errorf("bad cast name not rejected: %v", err)
	}
	if _, _, err := s.File("2026-01-02", "11111111-1111-1111-1111-111111111111", "nothex"); err != ErrNotFound {
		t.Errorf("bad sha not rejected: %v", err)
	}
	if _, _, err := s.File("2026-01-02", "11111111-1111-1111-1111-111111111111", "tmp"); err != ErrNotFound {
		t.Errorf("tmp must not be served: %v", err)
	}
}

func TestSessionsLimit(t *testing.T) {
	root := t.TempDir()
	for i := range 6 {
		id := "1111111" + string(rune('a'+i)) + "-1111-1111-1111-111111111111"
		writeSession(t, root, "2026-02-01", id,
			[]string{`{"eventid":"piper.session.connect","timestamp":"2026-02-01T10:0` + string(rune('0'+i)) + `:00.000000Z","dst_ip":"203.0.113.10"}`},
			nil, nil)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Sessions("", 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("limit 3: got %d sessions", len(got))
	}
	all, _ := s.Sessions("", 0, 0) // default cap >= 6, returns all
	if len(all) != 6 {
		t.Errorf("default: got %d sessions, want 6", len(all))
	}

	// pagination: two pages of 3 cover all 6, in order, without overlap.
	p1, _ := s.Sessions("", 3, 0)
	p2, _ := s.Sessions("", 3, 3)
	if len(p1) != 3 || len(p2) != 3 {
		t.Fatalf("pages: got %d and %d", len(p1), len(p2))
	}
	seen := map[string]bool{}
	for _, x := range append(append([]SessionSummary{}, p1...), p2...) {
		if seen[x.ID] {
			t.Errorf("session %s appears on both pages", x.ID)
		}
		seen[x.ID] = true
	}
	if len(seen) != 6 {
		t.Errorf("two pages cover %d sessions, want 6", len(seen))
	}
	// offset past the end returns empty, not an error.
	if end, _ := s.Sessions("", 3, 99); len(end) != 0 {
		t.Errorf("offset past end: got %d", len(end))
	}
}

func TestEmptyDir(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "does-not-exist-yet"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Sessions("", 0, 0)
	if err != nil || len(got) != 0 {
		t.Errorf("empty store: got %v err %v", got, err)
	}
}
