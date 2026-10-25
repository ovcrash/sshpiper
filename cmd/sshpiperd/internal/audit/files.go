package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultFileMaxSize   = 50 << 20
	defaultFileQuota     = 5 << 30
	defaultFileRetention = 90 * 24 * time.Hour
)

// Event IDs of transferred files.
const (
	EventFileUpload   = "piper.file.upload"
	EventFileDownload = "piper.file.download"
)

// fileOp is a write or the end of a transfer, applied by the writer goroutine.
type fileOp struct {
	t      *transfer
	offset int64
	data   []byte // nil with done
	done   bool
}

// fileStore keeps the copies of transferred files under <audit-dir>/files.
// All its methods except newFileStore run on the writer goroutine.
type fileStore struct {
	w         *Writer
	dir, tmp  string
	maxSize   int64
	quota     int64
	retention time.Duration

	used      int64 // bytes of stored copies
	open      map[*transfer]*os.File
	lastPrune time.Time
}

var transferSeq atomic.Int64

func newFileStore(w *Writer, opts Options) *fileStore {
	st := &fileStore{
		w:         w,
		dir:       filepath.Join(w.dir, "files"),
		maxSize:   opts.FileMaxSize,
		quota:     opts.FileQuota,
		retention: opts.FileRetention,
		open:      make(map[*transfer]*os.File),
	}
	st.tmp = filepath.Join(st.dir, "tmp")
	if st.maxSize <= 0 {
		st.maxSize = defaultFileMaxSize
	}
	if st.quota <= 0 {
		st.quota = defaultFileQuota
	}
	if st.retention <= 0 {
		st.retention = defaultFileRetention
	}
	if err := os.MkdirAll(st.tmp, 0o700); err != nil {
		slog.Error("audit: cannot create files dir", "dir", st.tmp, "error", err)
	}
	_ = os.Chmod(st.dir, 0o700)
	// leftovers of an interrupted run
	if entries, err := os.ReadDir(st.tmp); err == nil {
		for _, e := range entries {
			_ = os.Remove(filepath.Join(st.tmp, e.Name()))
		}
	}
	st.prune()
	return st
}

func (st *fileStore) maybePrune() {
	if time.Since(st.lastPrune) >= 24*time.Hour {
		st.prune()
	}
}

// prune deletes copies older than the retention and recomputes the usage.
func (st *fileStore) prune() {
	st.lastPrune = time.Now()
	cutoff := time.Now().Add(-st.retention)
	var used int64
	entries, err := os.ReadDir(st.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(st.dir, e.Name()))
			continue
		}
		used += info.Size()
	}
	st.used = used
}

func (st *fileStore) apply(op *fileOp) {
	if op.done {
		st.finish(op.t)
		return
	}
	f := st.open[op.t]
	if f == nil {
		var err error
		f, err = os.OpenFile(filepath.Join(st.tmp, op.t.tmpName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			slog.Error("audit: cannot create file copy", "error", err)
			op.t.broken.Store(true)
			return
		}
		st.open[op.t] = f
	}
	if _, err := f.WriteAt(op.data, op.offset); err != nil {
		op.t.broken.Store(true)
	}
}

func (st *fileStore) finish(t *transfer) {
	f := st.open[t]
	delete(st.open, t)
	tmpPath := filepath.Join(st.tmp, t.tmpName)

	ev := t.sess.newEvent(t.eventID())
	ev.Transfer, ev.Path, ev.Filename = t.proto, t.path, t.filename
	ev.Channel = uint32p(t.channel)
	ev.Size = t.size.Load()
	ev.Truncated = t.truncated.Load()
	ev.Incomplete = t.incomplete || t.broken.Load()
	ev.Message = fmt.Sprintf("file %s %s (%d bytes)", t.dir, t.displayName(), ev.Size)

	if f == nil {
		// no byte stored (empty file, or the copy could not be created)
		f, _ = os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	}
	if f != nil {
		sum, stored, err := st.keep(f, tmpPath)
		if err != nil {
			slog.Error("audit: cannot store file copy", "error", err)
			ev.Incomplete = true
		}
		ev.ShaSum = sum
		ev.Stored = &stored
		if stored {
			ev.OutFile = "files/" + sum
		}
	}
	t.sess.emitDirect(ev)
}

// keep hashes the copy, then moves it to files/<sha256> unless the content is
// already stored or the quota would be exceeded.
func (st *fileStore) keep(f *os.File, tmpPath string) (sum string, stored bool, err error) {
	defer func() { _ = os.Remove(tmpPath) }() // no-op after a rename
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return "", false, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		return "", false, err
	}
	sum = hex.EncodeToString(h.Sum(nil))
	dst := filepath.Join(st.dir, sum)

	if _, err := os.Stat(dst); err == nil {
		now := time.Now()
		_ = os.Chtimes(dst, now, now) // seen again: keep it for the retention period
		return sum, true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return sum, false, err
	}
	if st.used+n > st.quota {
		return sum, false, nil
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return sum, false, err
	}
	st.used += n
	return sum, true, nil
}

func (st *fileStore) closeAll() {
	for t, f := range st.open {
		_ = f.Close()
		_ = os.Remove(filepath.Join(st.tmp, t.tmpName))
		delete(st.open, t)
	}
}

// transfer is one file moving through a channel, in one direction.
type transfer struct {
	sess     *Session
	proto    string // scp or sftp
	dir      string // upload or download
	channel  uint32
	path     string
	filename string
	tmpName  string
	maxSize  int64

	size       atomic.Int64 // highest offset+length seen
	truncated  atomic.Bool
	broken     atomic.Bool // a chunk could not be queued or written
	incomplete bool        // ended before the protocol said so (set before done)
	finished   sync.Once
}

func (t *transfer) eventID() string {
	if t.dir == "download" {
		return EventFileDownload
	}
	return EventFileUpload
}

func (t *transfer) displayName() string {
	if t.filename != "" && t.path != "" {
		return t.path + " (" + t.filename + ")"
	}
	if t.path != "" {
		return t.path
	}
	return t.filename
}

// startTransfer begins the copy of a file seen on a channel.
func (s *Session) startTransfer(proto, dir string, channel uint32, path, filename string) *transfer {
	return &transfer{
		sess:     s,
		proto:    proto,
		dir:      dir,
		channel:  channel,
		path:     path,
		filename: filename,
		tmpName:  fmt.Sprintf("%s-%d", s.id, transferSeq.Add(1)),
		maxSize:  s.w.store.maxSize,
	}
}

// write copies data seen at offset. Bytes past the size limit are counted but
// not stored. It never blocks.
func (t *transfer) write(offset int64, data []byte) {
	if len(data) == 0 || offset < 0 {
		return
	}
	end := offset + int64(len(data))
	for {
		cur := t.size.Load()
		if end <= cur || t.size.CompareAndSwap(cur, end) {
			break
		}
	}
	if offset >= t.maxSize {
		t.truncated.Store(true)
		return
	}
	if end > t.maxSize {
		data = data[:t.maxSize-offset]
		t.truncated.Store(true)
	}
	chunk := append([]byte(nil), data...) // the hook's slice is reused by the pipe
	if !t.sess.w.tryEnqueue(record{file: &fileOp{t: t, offset: offset, data: chunk}}) {
		t.broken.Store(true)
	}
}

// finish ends the transfer once; incomplete marks a transfer cut short.
func (t *transfer) finish(incomplete bool) {
	t.finished.Do(func() {
		t.incomplete = incomplete
		if !t.sess.w.tryEnqueue(record{file: &fileOp{t: t, done: true}}) {
			slog.Warn("audit: file event lost, queue full", "session", t.sess.id)
		}
	})
}
