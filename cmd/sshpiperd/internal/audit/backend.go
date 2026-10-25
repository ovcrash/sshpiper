package audit

import (
	"fmt"
	"net"
	"strconv"
)

func hostPort(a net.Addr) (string, int) {
	if a == nil {
		return "", 0
	}
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func (s *Session) backendEvent(id string, local, remote net.Addr) *Event {
	ev := s.newEvent(id)
	ev.BackendIP, ev.BackendPort = hostPort(remote)
	ev.LocalIP, ev.LocalPort = hostPort(local)
	return ev
}

// BackendConnected records an upstream connection opened for this client
// (one per authentication attempt). local is the proxy side: local_port
// correlates with the backend's own logs.
func (s *Session) BackendConnected(local, remote net.Addr) {
	ev := s.backendEvent(EventBackendConnected, local, remote)
	ev.Message = fmt.Sprintf("backend connection %s:%d -> %s:%d", ev.LocalIP, ev.LocalPort, ev.BackendIP, ev.BackendPort)
	s.emit(ev)
}

// BackendDisconnected records the close of an upstream connection.
func (s *Session) BackendDisconnected(local, remote net.Addr) {
	ev := s.backendEvent(EventBackendDisconnected, local, remote)
	ev.Message = fmt.Sprintf("backend connection %s:%d closed", ev.LocalIP, ev.LocalPort)
	s.emit(ev)
}

// BackendConnectError records a failed upstream dial.
func (s *Session) BackendConnectError(addr string, err error) {
	ev := s.newEvent(EventBackendConnectError)
	ev.BackendIP, ev.BackendPort = hostPort(&stringAddr{addr})
	if err != nil {
		ev.Error = err.Error()
	}
	ev.Message = "backend connection failed"
	s.emit(ev)
}

type stringAddr struct{ s string }

func (a *stringAddr) Network() string { return "tcp" }
func (a *stringAddr) String() string  { return a.s }
