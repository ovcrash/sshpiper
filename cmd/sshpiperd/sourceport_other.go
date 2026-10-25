//go:build !linux

package main

import "syscall"

// reuseAddrControl does nothing outside Linux: the option is meant for the
// Linux production hosts; elsewhere the plain bind is tried, with the same
// fallback to an ephemeral port.
func reuseAddrControl(_, _ string, _ syscall.RawConn) error { return nil }
