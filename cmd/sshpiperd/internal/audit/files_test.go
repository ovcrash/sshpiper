package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// storedBytes returns the content of files/<sha> under the audit dir.
func storedBytes(t *testing.T, dir, sha string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "files", sha))
	if err != nil {
		t.Fatalf("stored file %s: %v", sha, err)
	}
	return b
}

// --- scp ---

func scpC(mode, name string, size int) []byte {
	return []byte("C" + mode + " " + strconv.Itoa(size) + " " + name + "\n")
}

func TestSCPUpload(t *testing.T) {
	w, dir := newTestWriter(t)
	sess := NewSession(w, "scp-up", "198.51.100.7", 40000, "203.0.113.10", 22)
	_ = sess.Uphook(pktOpenConfirm(0, 7))
	_ = sess.Downhook(pktReq(7, "exec", execSpecific("scp -t /tmp/dest")))

	body := []byte("hello scp upload\n")
	// client sends: C line, body, trailing status byte 0
	stream := append(scpC("0644", "payload.txt", len(body)), body...)
	stream = append(stream, 0)
	// feed in two chunks to exercise reassembly
	_ = sess.Downhook(pktData(7, string(stream[:10])))
	_ = sess.Downhook(pktData(7, string(stream[10:])))
	sess.Close()
	w.Close(5 * time.Second)

	evs := findEvents(readEvents(t, dir, "scp-up"), EventFileUpload)
	if len(evs) != 1 {
		t.Fatalf("upload events = %d, want 1", len(evs))
	}
	e := evs[0]
	if e.Transfer != "scp" || e.Filename != "payload.txt" || e.Path != "/tmp/dest" {
		t.Fatalf("event = %+v", e)
	}
	if e.Size != int64(len(body)) || e.ShaSum != sum(body) || e.Stored == nil || !*e.Stored {
		t.Fatalf("size/sha/stored = %+v", e)
	}
	if string(storedBytes(t, dir, e.ShaSum)) != string(body) {
		t.Fatal("stored content differs from the original")
	}
}

func TestSCPDownload(t *testing.T) {
	w, dir := newTestWriter(t)
	sess := NewSession(w, "scp-dl", "198.51.100.7", 40000, "203.0.113.10", 22)
	_ = sess.Uphook(pktOpenConfirm(0, 7))
	_ = sess.Downhook(pktReq(7, "exec", execSpecific("scp -f /etc/motd")))

	body := []byte("the backend sends this file\n")
	stream := append(scpC("0644", "motd", len(body)), body...)
	stream = append(stream, 0)
	// server -> client (uphook), recipient = client id 0
	_ = sess.Uphook(pktData(0, string(stream)))
	sess.Close()
	w.Close(5 * time.Second)

	evs := findEvents(readEvents(t, dir, "scp-dl"), EventFileDownload)
	if len(evs) != 1 || evs[0].ShaSum != sum(body) {
		t.Fatalf("download events = %+v", evs)
	}
}

// --- sftp ---

func sftpPacket(typ byte, id uint32, body []byte) []byte {
	payload := make([]byte, 5+len(body))
	payload[0] = typ
	binary.BigEndian.PutUint32(payload[1:], id)
	copy(payload[5:], body)
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

func sftpStr(s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	return b
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func u32b(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func TestSFTPUpload(t *testing.T) {
	w, dir := newTestWriter(t)
	sess := NewSession(w, "sftp-up", "198.51.100.7", 40000, "203.0.113.10", 22)
	_ = sess.Uphook(pktOpenConfirm(0, 7))
	_ = sess.Downhook(pktReq(7, "subsystem", subsystemSpecific("sftp")))

	body := []byte("uploaded over sftp, in two writes")
	// OPEN (write) id=1
	open := append(sftpStr("/home/user/up.bin"), u32b(fxfWrite|0x08)...) // WRITE|CREAT
	_ = sess.Downhook(pktData(7, string(sftpPacket(fxpOpen, 1, open))))
	// server HANDLE id=1 -> "h1"
	_ = sess.Uphook(pktData(0, string(sftpPacket(fxpHandle, 1, sftpStr("h1")))))
	// two WRITEs
	wr := func(off uint64, data []byte) {
		b := append(sftpStr("h1"), u64(off)...)
		b = append(b, sftpStr(string(data))...)
		_ = sess.Downhook(pktData(7, string(sftpPacket(fxpWrite, 2, b))))
	}
	wr(0, body[:10])
	wr(10, body[10:])
	// CLOSE
	_ = sess.Downhook(pktData(7, string(sftpPacket(fxpClose, 3, sftpStr("h1")))))
	sess.Close()
	w.Close(5 * time.Second)

	evs := findEvents(readEvents(t, dir, "sftp-up"), EventFileUpload)
	if len(evs) != 1 {
		t.Fatalf("upload events = %d (%+v)", len(evs), evs)
	}
	e := evs[0]
	if e.Transfer != "sftp" || e.Path != "/home/user/up.bin" || e.Size != int64(len(body)) || e.ShaSum != sum(body) {
		t.Fatalf("event = %+v", e)
	}
	if string(storedBytes(t, dir, e.ShaSum)) != string(body) {
		t.Fatal("stored content differs")
	}
}

func TestSFTPDownloadSplitPacket(t *testing.T) {
	w, dir := newTestWriter(t)
	sess := NewSession(w, "sftp-dl", "198.51.100.7", 40000, "203.0.113.10", 22)
	_ = sess.Uphook(pktOpenConfirm(0, 7))
	_ = sess.Downhook(pktReq(7, "subsystem", subsystemSpecific("sftp")))

	body := []byte("downloaded via sftp read/data")
	openPkt := sftpPacket(fxpOpen, 1, append(sftpStr("/etc/hosts"), u32b(fxfRead)...))
	_ = sess.Downhook(pktData(7, string(openPkt)))
	_ = sess.Uphook(pktData(0, string(sftpPacket(fxpHandle, 1, sftpStr("hd")))))
	// READ id=2
	rd := append(sftpStr("hd"), u64(0)...)
	rd = append(rd, u32b(uint32(len(body)))...)
	_ = sess.Downhook(pktData(7, string(sftpPacket(fxpRead, 2, rd))))
	// DATA reply id=2, split across two channel-data packets
	dataPkt := sftpPacket(fxpData, 2, sftpStr(string(body)))
	_ = sess.Uphook(pktData(0, string(dataPkt[:7])))
	_ = sess.Uphook(pktData(0, string(dataPkt[7:])))
	_ = sess.Downhook(pktData(7, string(sftpPacket(fxpClose, 3, sftpStr("hd")))))
	sess.Close()
	w.Close(5 * time.Second)

	evs := findEvents(readEvents(t, dir, "sftp-dl"), EventFileDownload)
	if len(evs) != 1 || evs[0].ShaSum != sum(body) || evs[0].Path != "/etc/hosts" {
		t.Fatalf("download events = %+v", evs)
	}
}

func TestFileTruncatedAndQuota(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Options{Dir: dir, Sensor: "s", QueueSize: 1000, FileMaxSize: 8, FileQuota: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	sess := NewSession(w, "trunc", "198.51.100.7", 40000, "203.0.113.10", 22)
	_ = sess.Uphook(pktOpenConfirm(0, 7))
	_ = sess.Downhook(pktReq(7, "exec", execSpecific("scp -t /tmp/x")))
	body := []byte("0123456789abcdef") // 16 bytes, limit is 8
	stream := append(scpC("0644", "big", len(body)), body...)
	stream = append(stream, 0)
	_ = sess.Downhook(pktData(7, string(stream)))
	sess.Close()
	w.Close(5 * time.Second)

	e := findEvents(readEvents(t, dir, "trunc"), EventFileUpload)[0]
	if e.Size != 16 || !e.Truncated || e.Stored == nil || !*e.Stored {
		t.Fatalf("truncated event = %+v", e)
	}
	if got := storedBytes(t, dir, e.ShaSum); len(got) != 8 || string(got) != "01234567" {
		t.Fatalf("stored prefix = %q", got)
	}
	if e.ShaSum != sum(body[:8]) {
		t.Fatal("shasum is not the SHA-256 of the stored prefix")
	}
}

func TestFileDeduplicated(t *testing.T) {
	w, dir := newTestWriter(t)
	send := func(id string) {
		sess := NewSession(w, id, "198.51.100.7", 40000, "203.0.113.10", 22)
		_ = sess.Uphook(pktOpenConfirm(0, 7))
		_ = sess.Downhook(pktReq(7, "exec", execSpecific("scp -t /tmp/x")))
		body := []byte("identical content")
		stream := append(scpC("0644", "f", len(body)), body...)
		stream = append(stream, 0)
		_ = sess.Downhook(pktData(7, string(stream)))
		sess.Close()
	}
	send("dup-a")
	send("dup-b")
	w.Close(5 * time.Second)

	entries, _ := os.ReadDir(filepath.Join(dir, "files"))
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("stored files = %d, want 1 (deduplicated)", n)
	}
}

func subsystemSpecific(name string) []byte {
	var b []byte
	str(&b, name)
	return b
}
