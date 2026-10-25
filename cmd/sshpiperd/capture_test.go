package main

import (
	"bufio"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tg123/sshpiper/sshkex"
)

func TestCaptureConnReportsHandshakeOnce(t *testing.T) {
	data, err := os.ReadFile("../../sshkex/testdata/ssh-98p1.bin")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := os.ReadFile("../../sshkex/testdata/ssh-98p1.ref")
	if err != nil {
		t.Fatal(err)
	}
	var wantHASSH string
	sc := bufio.NewScanner(strings.NewReader(string(ref)))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSuffix(sc.Text(), "\r"), "hassh: "); ok {
			wantHASSH = v
		}
	}

	client, server := net.Pipe()
	defer client.Close()
	cc := newCaptureConn(server)
	defer cc.Close()

	calls := 0
	var got string
	cc.onHandshake = func(_ string, kex *sshkex.KexInit) {
		calls++
		got = kex.HASSH()
	}

	go func() {
		// the client sends its bytes in small chunks, then more traffic
		for i := 0; i < len(data); i += 13 {
			_, _ = client.Write(data[i:min(i+13, len(data))])
		}
		_, _ = client.Write([]byte("encrypted traffic that must not be parsed"))
		_ = client.Close()
	}()

	_ = cc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 7)
	var read []byte
	for {
		n, err := cc.Read(buf)
		read = append(read, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	if string(read[:len(data)]) != string(data) {
		t.Fatal("captureConn modified the bytes read")
	}
	if calls != 1 {
		t.Fatalf("onHandshake called %d times, want 1", calls)
	}
	if got != wantHASSH {
		t.Fatalf("hassh = %s, want %s", got, wantHASSH)
	}
	if _, _, ok := cc.clientHandshake(); ok {
		t.Fatal("handshake reported twice (fallback after onHandshake)")
	}
	if cc.LocalAddr() != server.LocalAddr() || cc.RemoteAddr() != server.RemoteAddr() {
		t.Fatal("addresses not preserved")
	}
}
