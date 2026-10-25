package plugin

import "net"

// DialUpstream opens the TCP connection to an upstream returned by a plugin.
// downstream is the client's address. The default is a plain net.Dial; the
// daemon replaces it (--preserve-source-port, --audit-dir).
var DialUpstream = func(network, addr string, downstream net.Addr) (net.Conn, error) {
	return net.Dial(network, addr)
}

// CopyClientVersion makes the upstream connection announce the version line
// of the downstream client instead of the library default (SSH-2.0-Go).
var CopyClientVersion bool
