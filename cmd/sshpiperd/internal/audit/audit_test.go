package audit

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- SSH packet builders ---

func str(b *[]byte, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	*b = append(*b, n[:]...)
	*b = append(*b, s...)
}

func u32(b *[]byte, v uint32) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], v)
	*b = append(*b, n[:]...)
}

func pktData(recipient uint32, data string) []byte {
	b := []byte{msgChannelData}
	u32(&b, recipient)
	str(&b, data)
	return b
}

func pktExtData(recipient, code uint32, data string) []byte {
	b := []byte{msgChannelExtData}
	u32(&b, recipient)
	u32(&b, code)
	str(&b, data)
	return b
}

func pktOpenConfirm(cli, srv uint32) []byte {
	b := []byte{msgChannelOpenConfirm}
	u32(&b, cli)
	u32(&b, srv)
	u32(&b, 0x200000)
	u32(&b, 0x8000)
	return b
}

func pktReq(recipient uint32, reqType string, specific []byte) []byte {
	b := []byte{msgChannelRequest}
	u32(&b, recipient)
	str(&b, reqType)
	b = append(b, 0) // want_reply
	return append(b, specific...)
}

func ptySpecific(term string, w, h uint32) []byte {
	var s []byte
	str(&s, term)
	u32(&s, w)
	u32(&s, h)
	u32(&s, 0)
	u32(&s, 0)
	str(&s, "")
	return s
}

func envSpecific(name, value string) []byte {
	var s []byte
	str(&s, name)
	str(&s, value)
	return s
}

func execSpecific(cmd string) []byte {
	var s []byte
	str(&s, cmd)
	return s
}

func winSpecific(w, h uint32) []byte {
	var s []byte
	u32(&s, w)
	u32(&s, h)
	u32(&s, 0)
	u32(&s, 0)
	return s
}

func exitStatus(code uint32) []byte {
	var s []byte
	u32(&s, code)
	return s
}

// --- helpers ---

func newTestWriter(t *testing.T) (*Writer, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := NewWriter(Options{Dir: dir, Sensor: "sensor-test", QueueSize: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return w, dir
}

func readEvents(t *testing.T, dir, session string) []Event {
	t.Helper()
	var path string
	days, _ := os.ReadDir(dir)
	for _, d := range days {
		p := filepath.Join(dir, d.Name(), session, "events.jsonl")
		if _, err := os.Stat(p); err == nil {
			path = p
		}
	}
	if path == "" {
		t.Fatalf("no events.jsonl for session %s", session)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func findEvents(evs []Event, id string) []Event {
	var out []Event
	for _, e := range evs {
		if e.EventID == id {
			out = append(out, e)
		}
	}
	return out
}

func TestSessionShellFlow(t *testing.T) {
	w, dir := newTestWriter(t)
	sess := NewSession(w, "sess-shell", "198.51.100.7", 40000, "203.0.113.10", 22)

	// client opens, server confirms: client id 0, server id 7
	_ = sess.Uphook(pktOpenConfirm(0, 7))
	// pty-req then shell (client -> server, recipient = server id 7)
	_ = sess.Downhook(pktReq(7, "pty-req", ptySpecific("xterm-256color", 80, 24)))
	_ = sess.Downhook(pktReq(7, "env", envSpecific("LANG", "C.UTF-8")))
	_ = sess.Downhook(pktReq(7, "shell", nil))
	// keystrokes (client -> server)
	_ = sess.Downhook(pktData(7, "ls\r"))
	// output (server -> client, recipient = client id 0)
	_ = sess.Uphook(pktData(0, "file1 file2\r\n"))
	_ = sess.Uphook(pktExtData(0, 1, "a warning\r\n"))
	// resize
	_ = sess.Downhook(pktReq(7, "window-change", winSpecific(132, 43)))
	// exit (server -> client)
	_ = sess.Uphook(pktReq(0, "exit-status", exitStatus(0)))
	sess.Close()
	w.Close(5 * time.Second)

	evs := readEvents(t, dir, "sess-shell")
	if len(findEvents(evs, EventConnect)) != 1 {
		t.Error("missing connect event")
	}

	// every event carries the envelope
	for _, e := range evs {
		if e.Sensor != "sensor-test" || e.Session != "sess-shell" || e.Protocol != "ssh" {
			t.Fatalf("bad envelope: %+v", e)
		}
	}

	size := findEvents(evs, EventSize)
	if len(size) != 2 || size[0].Width != 80 || size[1].Width != 132 {
		t.Errorf("size events = %+v", size)
	}
	if v := findEvents(evs, EventVar); len(v) != 1 || v[0].Name != "LANG" || v[0].Value != "C.UTF-8" {
		t.Errorf("env events = %+v", v)
	}
	in := findEvents(evs, EventChanInput)
	if len(in) != 1 || in[0].Data != "ls\r" || *in[0].Channel != 0 {
		t.Errorf("input events = %+v", in)
	}
	out := findEvents(evs, EventChanOutput)
	if len(out) != 2 || out[0].Stream != "stdout" || out[1].Stream != "stderr" {
		t.Errorf("output events = %+v", out)
	}
	exit := findEvents(evs, EventChanExit)
	if len(exit) != 1 || exit[0].ExitStatus == nil || *exit[0].ExitStatus != 0 {
		t.Errorf("exit events = %+v", exit)
	}
	if c := findEvents(evs, EventSessClosed); len(c) != 1 {
		t.Error("missing session.closed")
	}

	// the cast replays with input and output
	cast := readCast(t, dir, "sess-shell", 0)
	if !strings.Contains(cast, `"version": 2`) && !strings.Contains(cast, `"version":2`) {
		t.Errorf("no asciicast header:\n%s", cast)
	}
	if !strings.Contains(cast, `,"i",`) || !strings.Contains(cast, `,"o",`) || !strings.Contains(cast, `,"r",`) {
		t.Errorf("cast missing i/o/r lines:\n%s", cast)
	}
}

func readCast(t *testing.T, dir, session string, ch uint32) string {
	t.Helper()
	days, _ := os.ReadDir(dir)
	for _, d := range days {
		p := filepath.Join(dir, d.Name(), session, castFile(ch))
		if b, err := os.ReadFile(p); err == nil {
			return string(b)
		}
	}
	t.Fatalf("no cast for channel %d", ch)
	return ""
}

func TestExecCommandRecorded(t *testing.T) {
	w, dir := newTestWriter(t)
	sess := NewSession(w, "sess-exec", "198.51.100.7", 40000, "203.0.113.10", 22)
	_ = sess.Uphook(pktOpenConfirm(3, 9))
	_ = sess.Downhook(pktReq(9, "exec", execSpecific("id; uname -a")))
	_ = sess.Uphook(pktData(3, "uid=0(root)\r\n"))
	_ = sess.Uphook(pktReq(3, "exit-status", exitStatus(0)))
	sess.Close()
	w.Close(5 * time.Second)

	evs := readEvents(t, dir, "sess-exec")
	cmd := findEvents(evs, EventCommand)
	if len(cmd) != 1 || cmd[0].Input != "id; uname -a" || *cmd[0].Channel != 3 {
		t.Fatalf("command events = %+v", cmd)
	}
}

func TestNonUTF8DataBase64(t *testing.T) {
	w, dir := newTestWriter(t)
	sess := NewSession(w, "sess-bin", "198.51.100.7", 40000, "203.0.113.10", 22)
	_ = sess.Uphook(pktOpenConfirm(0, 1))
	_ = sess.Downhook(pktReq(1, "shell", nil))
	_ = sess.Uphook(pktData(0, "\xff\xfe\x00binary"))
	sess.Close()
	w.Close(5 * time.Second)

	out := findEvents(readEvents(t, dir, "sess-bin"), EventChanOutput)
	if len(out) != 1 || out[0].Encoding != "base64" || out[0].DataB64 == "" || out[0].Data != "" {
		t.Fatalf("binary output not base64: %+v", out)
	}
}

func TestDropAccounting(t *testing.T) {
	dir := t.TempDir()
	// queue of size 1: the loop drains slowly while we flood
	w, err := NewWriter(Options{Dir: dir, Sensor: "s", QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20000; i++ {
		w.Emit("flood", &Event{EventID: "piper.test", Message: "x"})
	}
	if w.dropped.Load() == 0 {
		t.Skip("queue kept up, cannot force a drop deterministically on this machine")
	}
	w.Close(5 * time.Second)

	// a dropped event must appear in the global stream
	var all string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "all-") {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			all += string(b)
		}
	}
	if !strings.Contains(all, EventDropped) {
		t.Fatalf("no %s event emitted after drops (dropped=%d)", EventDropped, w.dropped.Load())
	}
}

func TestHooksNeverPanic(t *testing.T) {
	w, _ := newTestWriter(t)
	defer w.Close(time.Second)
	sess := NewSession(w, "sess-trunc", "1.2.3.4", 1, "5.6.7.8", 22)
	// truncated packets must not panic
	for _, p := range [][]byte{
		{msgChannelData},
		{msgChannelData, 0, 0},
		{msgChannelRequest, 0, 0, 0, 0},
		{msgChannelOpenConfirm, 1},
		{msgChannelExtData, 0},
		{},
		pktReq(0, "pty-req", []byte{0, 0}),
	} {
		if err := sess.Downhook(p); err != nil {
			t.Errorf("downhook returned error: %v", err)
		}
		if err := sess.Uphook(p); err != nil {
			t.Errorf("uphook returned error: %v", err)
		}
	}
}

func TestBackendEvents(t *testing.T) {
	w, dir := newTestWriter(t)
	sess := NewSession(w, "sess-backend", "198.51.100.7", 40000, "203.0.113.10", 22)
	local := &net.TCPAddr{IP: net.ParseIP("10.99.0.2"), Port: 40000}
	remote := &net.TCPAddr{IP: net.ParseIP("10.99.0.21"), Port: 22}

	sess.BackendConnected(local, remote)
	sess.BackendConnectError("10.99.0.21:22", errors.New("connection refused"))
	sess.Close()
	// an abandoned attempt released after the session ended
	sess.BackendDisconnected(local, remote)
	w.Close(5 * time.Second)

	evs := readEvents(t, dir, "sess-backend")
	c := findEvents(evs, EventBackendConnected)
	if len(c) != 1 || c[0].LocalPort != 40000 || c[0].BackendIP != "10.99.0.21" || c[0].BackendPort != 22 || c[0].Late {
		t.Fatalf("connected = %+v", c)
	}
	e := findEvents(evs, EventBackendConnectError)
	if len(e) != 1 || e[0].Error != "connection refused" || e[0].BackendPort != 22 {
		t.Fatalf("connect_error = %+v", e)
	}
	d := findEvents(evs, EventBackendDisconnected)
	if len(d) != 1 || !d[0].Late || d[0].LocalPort != 40000 {
		t.Fatalf("disconnected = %+v (must be marked late)", d)
	}
}
