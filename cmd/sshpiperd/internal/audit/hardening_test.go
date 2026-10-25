package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLogRetentionDeletesOldDays(t *testing.T) {
	dir := t.TempDir()
	// an old day directory and its all-<date> file, plus a recent one
	old := time.Now().UTC().AddDate(0, 0, -100).Format("2006-01-02")
	recent := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	for _, d := range []string{old, recent} {
		if err := os.MkdirAll(filepath.Join(dir, d, "sess"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "all-"+d+".jsonl"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	w, err := NewWriter(Options{Dir: dir, Sensor: "s", LogRetention: 90 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(2 * time.Second)

	if _, err := os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
		t.Errorf("old day dir %s not deleted", old)
	}
	if _, err := os.Stat(filepath.Join(dir, "all-"+old+".jsonl")); !os.IsNotExist(err) {
		t.Errorf("old all-%s.jsonl not deleted", old)
	}
	if _, err := os.Stat(filepath.Join(dir, recent)); err != nil {
		t.Errorf("recent day dir %s deleted: %v", recent, err)
	}
}

func TestLogRetentionZeroKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().UTC().AddDate(0, 0, -400).Format("2006-01-02")
	_ = os.MkdirAll(filepath.Join(dir, old), 0o700)

	w, err := NewWriter(Options{Dir: dir, Sensor: "s", LogRetention: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(2 * time.Second)
	if _, err := os.Stat(filepath.Join(dir, old)); err != nil {
		t.Error("retention 0 must keep everything")
	}
}

func TestCloseFlushesQueuedEvents(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Options{Dir: dir, Sensor: "s", QueueSize: 10000})
	if err != nil {
		t.Fatal(err)
	}
	sess := NewSession(w, "flush", "198.51.100.7", 40000, "203.0.113.10", 22)
	for range 500 {
		sess.Emit(&Event{EventID: "piper.test", Message: "x"})
	}
	sess.Close()
	w.Close(10 * time.Second) // must drain before returning

	data, err := os.ReadFile(filepath.Join(dir, time.Now().UTC().Format("2006-01-02"), "flush", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	n := strings.Count(string(data), "\"eventid\":\"piper.test\"")
	if n != 500 {
		t.Fatalf("flushed %d test events, want 500", n)
	}
}

func TestManySessionsNoGoroutineLeak(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Options{Dir: dir, Sensor: "s", QueueSize: 10000})
	if err != nil {
		t.Fatal(err)
	}

	runSession := func(id string) {
		sess := NewSession(w, id, "198.51.100.7", 40000, "203.0.113.10", 22)
		_ = sess.Uphook(pktOpenConfirm(0, 7))
		_ = sess.Downhook(pktReq(7, "shell", nil))
		_ = sess.Downhook(pktData(7, "whoami\r"))
		_ = sess.Uphook(pktData(0, "root\r\n"))
		sess.Close()
	}

	for i := range 50 { // warm up, let transient goroutines settle
		runSession("warm-" + strconv.Itoa(i))
	}
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := range 300 {
		runSession("sess-" + strconv.Itoa(i))
	}
	w.Close(10 * time.Second)
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	// the Session/Writer must not spawn a goroutine per session
	if after > before+5 {
		t.Fatalf("goroutines grew from %d to %d across 300 sessions", before, after)
	}
}
