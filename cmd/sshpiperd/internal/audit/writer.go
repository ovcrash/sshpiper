package audit

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Options configure a Writer.
type Options struct {
	Dir       string // audit root; empty disables auditing
	QueueSize int    // bounded queue length (default 10000)
	Sensor    string // sensor name stamped on every event
}

// Writer serializes all audit output through one goroutine fed by a bounded
// queue. Enqueue never blocks: when the queue is full the record is dropped
// and counted, so the piped session is never slowed or cut.
type Writer struct {
	dir    string
	sensor string

	queue   chan record
	wg      sync.WaitGroup
	closing chan struct{}

	dropped   atomic.Int64
	reported  int64
	dropSince atomic.Int64 // unix micros of the first drop in the current streak

	// touched only by the loop goroutine
	files  map[string]*os.File
	allDay string
	all    *os.File
}

type record struct {
	session string
	ev      *Event
	path    string // relative file under the session dir, for a raw append
	data    []byte
	close   bool // close this session's files
}

// Sensor returns the configured sensor name.
func (w *Writer) Sensor() string { return w.sensor }

// NewWriter creates the audit root (mode 0700) and starts the writer
// goroutine.
func NewWriter(opts Options) (*Writer, error) {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 10000
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	w := &Writer{
		dir:     opts.Dir,
		sensor:  opts.Sensor,
		queue:   make(chan record, opts.QueueSize),
		closing: make(chan struct{}),
		files:   make(map[string]*os.File),
	}
	w.wg.Add(1)
	go w.loop()
	return w, nil
}

// stamp fills the envelope fields that the Writer owns.
func (w *Writer) stamp(ev *Event) {
	ev.Sensor = w.sensor
	ev.Protocol = "ssh"
	if ev.Timestamp == "" {
		ev.Timestamp = nowRFC3339Micro()
	}
}

// Emit queues an event for a session. It never blocks.
func (w *Writer) Emit(session string, ev *Event) {
	w.stamp(ev)
	w.enqueue(record{session: session, ev: ev})
}

// appendFile queues a raw append to <session>/<path>. It never blocks.
func (w *Writer) appendFile(session, path string, data []byte) {
	w.enqueue(record{session: session, path: path, data: data})
}

func (w *Writer) enqueue(r record) {
	select {
	case w.queue <- r:
	default:
		if w.dropped.Add(1) == 1 {
			w.dropSince.Store(time.Now().UnixMicro())
		}
	}
}

func (w *Writer) loop() {
	defer w.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case r := <-w.queue:
			w.write(r)
			w.reportDrops()
		case <-ticker.C:
			w.reportDrops()
		case <-w.closing:
			// drain what is already queued, then close files
			for {
				select {
				case r := <-w.queue:
					w.write(r)
				default:
					w.reportDrops()
					w.closeFiles()
					return
				}
			}
		}
	}
}

// reportDrops writes one piper.audit.dropped event per streak of drops.
func (w *Writer) reportDrops() {
	total := w.dropped.Load()
	if total <= w.reported {
		return
	}
	n := total - w.reported
	since := time.UnixMicro(w.dropSince.Load()).UTC().Format("2006-01-02T15:04:05.000000Z")
	w.reported = total
	ev := &Event{EventID: EventDropped, Count: n, Since: since, Message: "audit records dropped"}
	w.stamp(ev)
	// write directly (do not re-enqueue: the queue is full by definition)
	if b, err := ev.marshal(); err == nil {
		w.writeAll(b)
	}
}

func (w *Writer) sessionFile(session, rel string) *os.File {
	key := session + "/" + rel
	if f := w.files[key]; f != nil {
		return f
	}
	day := time.Now().UTC().Format("2006-01-02")
	dir := filepath.Join(w.dir, day, session)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Error("audit: cannot create session dir", "dir", dir, "error", err)
		return nil
	}
	f, err := os.OpenFile(filepath.Join(dir, rel), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		slog.Error("audit: cannot open file", "file", rel, "error", err)
		return nil
	}
	w.files[key] = f
	return f
}

func (w *Writer) write(r record) {
	if r.close {
		prefix := r.session + "/"
		for k, f := range w.files {
			if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
				_ = f.Close()
				delete(w.files, k)
			}
		}
		return
	}
	if r.ev != nil {
		b, err := r.ev.marshal()
		if err != nil {
			return
		}
		if f := w.sessionFile(r.session, "events.jsonl"); f != nil {
			_, _ = f.Write(b)
		}
		w.writeAll(b)
		return
	}
	if f := w.sessionFile(r.session, r.path); f != nil {
		_, _ = f.Write(r.data)
	}
}

// writeAll appends to the daily global stream <audit-dir>/all-<date>.jsonl.
func (w *Writer) writeAll(b []byte) {
	day := time.Now().UTC().Format("2006-01-02")
	if w.all == nil || w.allDay != day {
		if w.all != nil {
			_ = w.all.Close()
		}
		f, err := os.OpenFile(filepath.Join(w.dir, "all-"+day+".jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			slog.Error("audit: cannot open all.jsonl", "error", err)
			return
		}
		w.all, w.allDay = f, day
	}
	_, _ = w.all.Write(b)
}

// CloseSession closes the files of one session (called when it ends). The
// close is ordered after every record already enqueued for the session.
func (w *Writer) CloseSession(session string) {
	w.enqueue(record{session: session, close: true})
}

func (w *Writer) closeFiles() {
	for k, f := range w.files {
		_ = f.Close()
		delete(w.files, k)
	}
	if w.all != nil {
		_ = w.all.Close()
		w.all = nil
	}
}

// Close drains the queue (up to a timeout) and stops the goroutine.
func (w *Writer) Close(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		close(w.closing)
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("audit: flush timed out, some records may be lost")
	}
}
