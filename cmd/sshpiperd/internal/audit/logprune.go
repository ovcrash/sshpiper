package audit

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (w *Writer) maybePruneLogs() {
	if w.logRetention <= 0 || time.Since(w.lastLogPrune) < time.Hour {
		return
	}
	w.pruneLogs()
}

// pruneLogs deletes day directories and all-<date>.jsonl files whose date is
// older than the retention. Dates are parsed from the names, so the clock of
// the files is irrelevant. The day file currently open is never removed.
func (w *Writer) pruneLogs() {
	w.lastLogPrune = time.Now()
	if w.logRetention <= 0 {
		return
	}
	cutoff := time.Now().UTC().Add(-w.logRetention)
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		var day string
		switch {
		case e.IsDir() && looksLikeDay(name):
			day = name
		case !e.IsDir() && strings.HasPrefix(name, "all-") && strings.HasSuffix(name, ".jsonl"):
			day = strings.TrimSuffix(strings.TrimPrefix(name, "all-"), ".jsonl")
		default:
			continue
		}
		t, err := time.Parse("2006-01-02", day)
		if err != nil || !t.Before(cutoff) {
			continue
		}
		if name == "all-"+w.allDay+".jsonl" {
			continue
		}
		_ = os.RemoveAll(filepath.Join(w.dir, name))
	}
}

func looksLikeDay(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}
