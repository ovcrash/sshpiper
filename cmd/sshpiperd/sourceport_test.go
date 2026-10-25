package main

import (
	"net"
	"runtime"
	"sync"
	"testing"
)

// freePort returns a TCP port that was free a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

func upstreamListener(t *testing.T) (net.Listener, chan net.Addr) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	seen := make(chan net.Addr, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			seen <- c.RemoteAddr()
			_ = c.Close()
		}
	}()
	return l, seen
}

func TestDialKeepsClientSourcePort(t *testing.T) {
	l, seen := upstreamListener(t)
	port := freePort(t)
	client := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: port}

	c, err := dialKeepSourcePort("tcp", l.Addr().String(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if got := c.LocalAddr().(*net.TCPAddr).Port; got != port {
		t.Fatalf("upstream local port = %d, want the client port %d", got, port)
	}
	if got := (<-seen).(*net.TCPAddr).Port; got != port {
		t.Fatalf("upstream sees source port %d, want %d", got, port)
	}
}

func TestDialFallsBackWhenPortBusy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("port conflict semantics differ outside Linux")
	}
	l, _ := upstreamListener(t)

	// occupy the client's port with a listener on all addresses
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port

	c, err := dialKeepSourcePort("tcp", l.Addr().String(), &net.TCPAddr{Port: port})
	if err != nil {
		t.Fatalf("login must not fail because the port is busy: %v", err)
	}
	defer c.Close()
	if got := c.LocalAddr().(*net.TCPAddr).Port; got == port {
		t.Fatalf("expected a fallback port, got the busy one %d", got)
	}
}

func TestDialSecondAttemptSamePort(t *testing.T) {
	// each authentication attempt opens a new upstream connection: the second
	// one from the same client port must still succeed (kept or fallback)
	l, _ := upstreamListener(t)
	client := &net.TCPAddr{Port: freePort(t)}

	for i := range 3 {
		c, err := dialKeepSourcePort("tcp", l.Addr().String(), client)
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		_ = c.Close()
	}
}

// holdingListener accepts connections and keeps them open, like a backend
// waiting for the next authentication message of an abandoned attempt.
func holdingListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	var (
		mu   sync.Mutex
		held []net.Conn
	)
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	return l
}

func TestAbandonedAttemptFreesThePort(t *testing.T) {
	l := holdingListener(t)
	client := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: freePort(t)}

	first, err := dialKeepSourcePort("tcp", l.Addr().String(), client)
	if err != nil {
		t.Fatal(err)
	}
	// the first attempt failed and was abandoned (never closed by its user)
	_ = first

	second, err := dialKeepSourcePort("tcp", l.Addr().String(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := second.LocalAddr().(*net.TCPAddr).Port; got != client.Port {
		t.Fatalf("second attempt uses port %d, want the client port %d", got, client.Port)
	}
	if _, err := first.Write([]byte("x")); err == nil {
		t.Error("the abandoned attempt should have been closed")
	}
}

func TestReleaseUpstreams(t *testing.T) {
	l := holdingListener(t)
	client := &net.TCPAddr{IP: net.ParseIP("198.51.100.8"), Port: freePort(t)}

	c, err := dialKeepSourcePort("tcp", l.Addr().String(), client)
	if err != nil {
		t.Fatal(err)
	}
	releaseUpstreams(client)
	if _, err := c.Write([]byte("x")); err == nil {
		t.Error("connection still open after releaseUpstreams")
	}
	upstreams.mu.Lock()
	n := len(upstreams.m[client.String()])
	upstreams.mu.Unlock()
	if n != 0 {
		t.Errorf("%d tracked connections left", n)
	}
	releaseUpstreams(nil) // must not panic
}

func TestDialWithoutPortUsesEphemeral(t *testing.T) {
	l, _ := upstreamListener(t)
	for _, down := range []net.Addr{nil, &net.UnixAddr{Name: "x", Net: "unix"}} {
		c, err := dialKeepSourcePort("tcp", l.Addr().String(), down)
		if err != nil {
			t.Fatalf("downstream %v: %v", down, err)
		}
		_ = c.Close()
	}
}
