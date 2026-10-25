package audit

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// SSH message numbers parsed here (RFC 4253/4254).
const (
	msgGlobalRequest      = 80
	msgChannelOpen        = 90
	msgChannelOpenConfirm = 91
	msgChannelData        = 94
	msgChannelExtData     = 95
	msgChannelEOF         = 96
	msgChannelClose       = 97
	msgChannelRequest     = 98
)

// Session records one piped connection. Its Uphook/Downhook are installed on
// the pipe; they parse packets and queue audit records. They never return an
// error, so the pipe is never cut by the auditor. A session is used from the
// two piping goroutines (up and down), so its mutable state is guarded.
type Session struct {
	w       *Writer
	id      string
	src     addr
	dst     addr
	start   time.Time
	envOnly map[string]string // env seen before a shell/exec, to seed the cast header

	mu            sync.Mutex
	srvToCli      map[uint32]uint32 // server channel id -> client (canonical) id
	chans         map[uint32]*chanState
	lastAttempt   attempt
	offered       []string
	loggedSuccess bool
	closed        bool
}

type addr struct {
	ip   string
	port int
}

type chanState struct {
	started bool
	start   time.Time
	width   uint32
	height  uint32
	term    string
}

// NewSession creates a recorder and emits piper.session.connect.
func NewSession(w *Writer, id, srcIP string, srcPort int, dstIP string, dstPort int) *Session {
	s := &Session{
		w:        w,
		id:       id,
		src:      addr{srcIP, srcPort},
		dst:      addr{dstIP, dstPort},
		start:    time.Now(),
		envOnly:  make(map[string]string),
		srvToCli: make(map[uint32]uint32),
		chans:    make(map[uint32]*chanState),
	}
	s.emit(&Event{EventID: EventConnect, Message: fmt.Sprintf("new connection from %s", srcIP)})
	return s
}

// ID returns the session id (also the recording directory name).
func (s *Session) ID() string { return s.id }

// newEvent returns an event pre-filled with this session's envelope.
func (s *Session) newEvent(id string) *Event {
	return &Event{
		EventID: id,
		Session: s.id,
		SrcIP:   s.src.ip, SrcPort: s.src.port,
		DstIP: s.dst.ip, DstPort: s.dst.port,
	}
}

func (s *Session) emit(ev *Event) {
	s.mu.Lock()
	if s.closed {
		ev.Late = true
	}
	s.mu.Unlock()
	if ev.Session == "" {
		ev.Session = s.id
		ev.SrcIP, ev.SrcPort = s.src.ip, s.src.port
		ev.DstIP, ev.DstPort = s.dst.ip, s.dst.port
	}
	s.w.Emit(s.id, ev)
}

// Emit queues an arbitrary event under this session (used for version/kex/auth
// events built by the caller).
func (s *Session) Emit(ev *Event) { s.emit(ev) }

// Close emits piper.session.closed and releases the session files.
func (s *Session) Close() {
	ev := s.newEvent(EventSessClosed)
	ev.DurationMs = time.Since(s.start).Milliseconds()
	s.emit(ev)
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.w.CloseSession(s.id)
}

// --- packet helpers ---

func readUint32(b []byte) (uint32, []byte, bool) {
	if len(b) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(b), b[4:], true
}

func readString(b []byte) (string, []byte, bool) {
	n, rest, ok := readUint32(b)
	if !ok || uint64(n) > uint64(len(rest)) {
		return "", nil, false
	}
	return string(rest[:n]), rest[n:], true
}

func readBool(b []byte) (bool, []byte, bool) {
	if len(b) < 1 {
		return false, nil, false
	}
	return b[0] != 0, b[1:], true
}

func setData(ev *Event, raw []byte) {
	if utf8.Valid(raw) {
		ev.Data = string(raw)
		return
	}
	ev.DataB64 = b64(raw)
	ev.Encoding = "base64"
}

func uint32p(v uint32) *uint32 { return &v }

func jsonString(raw []byte) string {
	b, err := json.Marshal(string(raw))
	if err != nil {
		return `""`
	}
	return string(b)
}
