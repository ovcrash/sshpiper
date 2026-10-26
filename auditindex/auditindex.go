// Package auditindex is a read-only reader over the audit directory produced
// by the daemon (package cmd/sshpiperd/internal/audit). It lists recorded
// sessions, decodes their event timelines, and serves asciicast recordings
// and captured files, so an operator UI can browse the audit without touching
// the writer. It never writes and holds no handles between calls.
//
// On-disk layout (written by the daemon):
//
//	<dir>/all-<YYYY-MM-DD>.jsonl        daily global stream (ignored here)
//	<dir>/<YYYY-MM-DD>/<session>/
//	    events.jsonl                    one JSON event per line
//	    channel-<n>.cast                asciicast v2, one per channel
//	    files/<sha256>                  captured files, addressed by digest
//	    files/tmp/                      staging — never served
package auditindex

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ErrNotFound is returned when a day, session, cast or file does not exist or
// fails validation (the two are deliberately indistinguishable to a caller).
var ErrNotFound = errors.New("audit: not found")

// Event IDs we key on. Mirrored from the writer (not imported: it lives under
// an internal/ path). Kept to the few the index needs.
const (
	evVersion      = "piper.client.version"
	evLoginFailed  = "piper.login.failed"
	evLoginOK      = "piper.login.success"
	evCommand      = "piper.command.input"
	evFileUpload   = "piper.file.upload"
	evFileDownload = "piper.file.download"
)

var (
	dayRe  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	castRe = regexp.MustCompile(`^channel-\d+\.cast$`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Store reads one audit directory.
type Store struct{ dir string }

// Open returns a Store over dir. dir need not exist yet; calls just return
// empty results or ErrNotFound until the daemon creates it.
func Open(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("audit: empty directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Store{dir: abs}, nil
}

// SessionSummary is the one-line view of a recorded session.
type SessionSummary struct {
	Day           string `json:"day"`
	ID            string `json:"id"`
	SrcIP         string `json:"src_ip,omitempty"`
	SrcPort       int    `json:"src_port,omitempty"`
	DstIP         string `json:"dst_ip,omitempty"`
	DstPort       int    `json:"dst_port,omitempty"`
	Start         string `json:"start,omitempty"`
	End           string `json:"end,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	HASSH         string `json:"hassh,omitempty"`
	LoginAttempts int    `json:"login_attempts"`
	LoginSuccess  bool   `json:"login_success"`
	Commands      int    `json:"commands"`
	Channels      int    `json:"channels"`
	Files         int    `json:"files"`
}

// TimelineEvent is a decoded event, minus the bulky channel payloads (we do
// not surface raw keystroke/output bytes here; those live in the casts).
type TimelineEvent struct {
	EventID     string  `json:"eventid"`
	Timestamp   string  `json:"timestamp"`
	SrcIP       string  `json:"src_ip,omitempty"`
	SrcPort     int     `json:"src_port,omitempty"`
	DstIP       string  `json:"dst_ip,omitempty"`
	DstPort     int     `json:"dst_port,omitempty"`
	Message     string  `json:"message,omitempty"`
	Username    string  `json:"username,omitempty"`
	Password    string  `json:"password,omitempty"`
	Method      string  `json:"method,omitempty"`
	Input       string  `json:"input,omitempty"`
	RequestType string  `json:"request_type,omitempty"`
	Filename    string  `json:"filename,omitempty"`
	Transfer    string  `json:"transfer,omitempty"`
	ShaSum      string  `json:"shasum,omitempty"`
	Size        int64   `json:"size,omitempty"`
	Channel     *uint32 `json:"channel,omitempty"`
	Version     string  `json:"version,omitempty"`
	HASSH       string  `json:"hassh,omitempty"`
}

// CastInfo names one asciicast recording in a session.
type CastInfo struct {
	Channel string `json:"channel"` // file name, e.g. "channel-3.cast"
	Size    int64  `json:"size"`
}

// FileInfo names one captured file in a session.
type FileInfo struct {
	Sha      string `json:"sha"`
	Size     int64  `json:"size"`
	Filename string `json:"filename,omitempty"`
	Transfer string `json:"transfer,omitempty"`
}

// SessionDetail is the full view of a session.
type SessionDetail struct {
	SessionSummary
	Events []TimelineEvent `json:"events"`
	Casts  []CastInfo      `json:"casts"`
	Files  []FileInfo      `json:"files"`
}

// Sessions lists every recorded session, newest first. filterIP, when set,
// keeps only sessions whose destination (external) IP matches it.
func (s *Store) Sessions(filterIP string) ([]SessionSummary, error) {
	days, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []SessionSummary{}, nil
		}
		return nil, err
	}
	out := []SessionSummary{}
	for _, d := range days {
		if !d.IsDir() || !dayRe.MatchString(d.Name()) {
			continue
		}
		day := d.Name()
		sessions, err := os.ReadDir(filepath.Join(s.dir, day))
		if err != nil {
			continue
		}
		for _, se := range sessions {
			if !se.IsDir() || !idRe.MatchString(se.Name()) {
				continue
			}
			sum, err := s.summarize(day, se.Name())
			if err != nil {
				continue
			}
			if filterIP != "" && sum.DstIP != filterIP {
				continue
			}
			out = append(out, sum)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start > out[j].Start // newest first
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// Session returns the full detail of one session.
func (s *Store) Session(day, id string) (*SessionDetail, error) {
	dir, err := s.sessionDir(day, id)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, ErrNotFound
	}
	events, err := s.readEvents(dir)
	if err != nil {
		return nil, err
	}
	d := &SessionDetail{
		SessionSummary: summarizeEvents(day, id, events),
		Events:         events,
		Casts:          []CastInfo{},
		Files:          []FileInfo{},
	}
	d.Casts = listCasts(dir)
	d.Files = listFiles(dir, events)
	d.SessionSummary.Channels = len(d.Casts)
	d.SessionSummary.Files = len(d.Files)
	return d, nil
}

// Cast opens an asciicast recording for reading. channel is the file name
// ("channel-<n>.cast"). The caller closes the returned reader.
func (s *Store) Cast(day, id, channel string) (io.ReadCloser, error) {
	dir, err := s.sessionDir(day, id)
	if err != nil {
		return nil, err
	}
	if !castRe.MatchString(channel) {
		return nil, ErrNotFound
	}
	f, err := os.Open(filepath.Join(dir, channel))
	if err != nil {
		return nil, ErrNotFound
	}
	return f, nil
}

// File opens a captured file for reading and reports its size. The caller
// closes the returned reader.
func (s *Store) File(day, id, sha string) (io.ReadCloser, int64, error) {
	dir, err := s.sessionDir(day, id)
	if err != nil {
		return nil, 0, err
	}
	if !shaRe.MatchString(sha) {
		return nil, 0, ErrNotFound
	}
	p := filepath.Join(dir, "files", sha)
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return nil, 0, ErrNotFound
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, ErrNotFound
	}
	return f, fi.Size(), nil
}

// --- internals ---

// sessionDir validates day/id and returns the path, guaranteed to stay inside
// the store directory.
func (s *Store) sessionDir(day, id string) (string, error) {
	if !dayRe.MatchString(day) || !idRe.MatchString(id) {
		return "", ErrNotFound
	}
	p := filepath.Join(s.dir, day, id)
	if !s.within(p) {
		return "", ErrNotFound
	}
	return p, nil
}

// within reports whether p resolves inside the store directory (defence in
// depth on top of the charset checks).
func (s *Store) within(p string) bool {
	rel, err := filepath.Rel(s.dir, p)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	return true
}

func (s *Store) summarize(day, id string) (SessionSummary, error) {
	dir := filepath.Join(s.dir, day, id)
	events, err := s.readEvents(dir)
	if err != nil {
		return SessionSummary{}, err
	}
	sum := summarizeEvents(day, id, events)
	sum.Channels = len(listCasts(dir))
	sum.Files = len(listFiles(dir, events))
	return sum, nil
}

// readEvents decodes events.jsonl line by line. Lines can be large (base64
// channel payloads), so a plain bufio.Scanner would overflow; we read with no
// per-line cap and skip unparseable lines rather than failing the session.
func (s *Store) readEvents(dir string) ([]TimelineEvent, error) {
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return []TimelineEvent{}, nil
		}
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	out := []TimelineEvent{}
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var ev TimelineEvent
			if json.Unmarshal(line, &ev) == nil && ev.EventID != "" {
				out = append(out, ev)
			}
		}
		if err != nil {
			break // io.EOF or a read error: return what we have
		}
	}
	return out, nil
}

func summarizeEvents(day, id string, events []TimelineEvent) SessionSummary {
	sum := SessionSummary{Day: day, ID: id}
	for i := range events {
		ev := &events[i]
		if sum.Start == "" {
			sum.Start = ev.Timestamp
		}
		if ev.Timestamp != "" {
			sum.End = ev.Timestamp
		}
		switch ev.EventID {
		case evVersion:
			sum.ClientVersion = ev.Version
		case evLoginFailed:
			sum.LoginAttempts++
		case evLoginOK:
			sum.LoginAttempts++
			sum.LoginSuccess = true
		case evCommand:
			sum.Commands++
		}
		if ev.HASSH != "" && sum.HASSH == "" {
			sum.HASSH = ev.HASSH
		}
		// Every event carries the connection endpoints on its envelope; take
		// them from the first event that has them.
		if sum.DstIP == "" && ev.DstIP != "" {
			sum.DstIP, sum.DstPort = ev.DstIP, ev.DstPort
		}
		if sum.SrcIP == "" && ev.SrcIP != "" {
			sum.SrcIP, sum.SrcPort = ev.SrcIP, ev.SrcPort
		}
	}
	return sum
}

func listCasts(dir string) []CastInfo {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []CastInfo{}
	}
	out := []CastInfo{}
	for _, e := range entries {
		if e.IsDir() || !castRe.MatchString(e.Name()) {
			continue
		}
		var size int64
		if fi, err := e.Info(); err == nil {
			size = fi.Size()
		}
		out = append(out, CastInfo{Channel: e.Name(), Size: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Channel < out[j].Channel })
	return out
}

// listFiles pairs the captured files on disk with the filename/transfer each
// was seen under (from upload/download events, matched by digest).
func listFiles(dir string, events []TimelineEvent) []FileInfo {
	meta := map[string]TimelineEvent{}
	for _, ev := range events {
		if (ev.EventID == evFileUpload || ev.EventID == evFileDownload) && ev.ShaSum != "" {
			meta[ev.ShaSum] = ev
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "files"))
	if err != nil {
		return []FileInfo{}
	}
	out := []FileInfo{}
	for _, e := range entries {
		if e.IsDir() || !shaRe.MatchString(e.Name()) {
			continue // skips tmp/ and anything unexpected
		}
		fi := FileInfo{Sha: e.Name()}
		if info, err := e.Info(); err == nil {
			fi.Size = info.Size()
		}
		if m, ok := meta[e.Name()]; ok {
			fi.Filename = m.Filename
			fi.Transfer = m.Transfer
		}
		out = append(out, fi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sha < out[j].Sha })
	return out
}
