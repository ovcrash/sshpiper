// Package audit writes a structured record of every relayed SSH session:
// JSON lines (one event per line) and asciicast v2 recordings per channel.
//
// The daemon is the single writer. Events are queued and flushed by one
// goroutine per session, so an audit error or a slow disk never slows down
// or interrupts the piped connection (decision: the auditor must never cut a
// session).
package audit

import (
	"encoding/json"
	"time"
)

// Event IDs, mirrored on the plan (Cowrie-inspired, not compatible).
const (
	EventConnect     = "piper.session.connect"
	EventVersion     = "piper.client.version"
	EventKex         = "piper.client.kex"
	EventLoginFailed = "piper.login.failed"
	EventLoginOK     = "piper.login.success"
	EventFingerprint = "piper.client.fingerprint"
	EventSize        = "piper.client.size"
	EventVar         = "piper.client.var"
	EventCommand     = "piper.command.input"
	EventChanInput   = "piper.channel.input"
	EventChanOutput  = "piper.channel.output"
	EventChanRequest = "piper.channel.request"
	EventChanExit    = "piper.channel.exit"
	EventSessClosed  = "piper.session.closed"
	EventDropped     = "piper.audit.dropped"

	EventBackendConnected    = "piper.backend.connected"
	EventBackendDisconnected = "piper.backend.disconnected"
	EventBackendConnectError = "piper.backend.connect_error"
)

// Event is one audit record. The envelope fields are always present; the
// rest is event-specific and omitted when empty.
type Event struct {
	EventID   string `json:"eventid"`
	Message   string `json:"message,omitempty"`
	Sensor    string `json:"sensor"`
	Timestamp string `json:"timestamp"`
	Session   string `json:"session"`
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	Late      bool   `json:"late,omitempty"`

	// event-specific
	Version         string   `json:"version,omitempty"`
	HASSH           string   `json:"hassh,omitempty"`
	HASSHAlgorithms string   `json:"hasshAlgorithms,omitempty"`
	KexAlgs         string   `json:"kexAlgs,omitempty"`
	KeyAlgs         string   `json:"keyAlgs,omitempty"`
	EncCS           string   `json:"encCS,omitempty"`
	MacCS           string   `json:"macCS,omitempty"`
	CompCS          string   `json:"compCS,omitempty"`
	LangCS          string   `json:"langCS,omitempty"`
	Username        string   `json:"username,omitempty"`
	Method          string   `json:"method,omitempty"`
	Password        string   `json:"password,omitempty"`
	Fingerprint     string   `json:"fingerprint,omitempty"`
	Key             string   `json:"key,omitempty"`
	KeyType         string   `json:"type,omitempty"`
	AllowedMethods  []string `json:"allowed_methods,omitempty"`
	Channel         *uint32  `json:"channel,omitempty"`
	Width           uint32   `json:"width,omitempty"`
	Height          uint32   `json:"height,omitempty"`
	Name            string   `json:"name,omitempty"`
	Value           string   `json:"value,omitempty"`
	Input           string   `json:"input,omitempty"`
	Data            string   `json:"data,omitempty"`
	DataB64         string   `json:"data_b64,omitempty"`
	Encoding        string   `json:"encoding,omitempty"`
	Stream          string   `json:"stream,omitempty"`
	RequestType     string   `json:"request_type,omitempty"`
	Signal          string   `json:"signal,omitempty"`
	ExitStatus      *uint32  `json:"exit_status,omitempty"`
	ExitSignal      string   `json:"exit_signal,omitempty"`
	DurationMs      int64    `json:"duration_ms,omitempty"`
	TTYLog          string   `json:"ttylog,omitempty"`
	ShaSum          string   `json:"shasum,omitempty"`
	Count           int64    `json:"count,omitempty"`
	Since           string   `json:"since,omitempty"`
	BackendIP       string   `json:"backend_ip,omitempty"`
	BackendPort     int      `json:"backend_port,omitempty"`
	LocalIP         string   `json:"local_ip,omitempty"`
	LocalPort       int      `json:"local_port,omitempty"`
	Error           string   `json:"error,omitempty"`
}

func nowRFC3339Micro() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
}

func (e *Event) marshal() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
