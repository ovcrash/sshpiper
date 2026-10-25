//go:build linux

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseAddrControl sets SO_REUSEADDR so that binding the client's port
// succeeds while another socket on that port is in TIME_WAIT; connect still
// fails if the exact same 4-tuple exists, and the caller then falls back.
func reuseAddrControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
