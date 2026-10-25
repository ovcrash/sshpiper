package plugin

import "net"

// DialUpstream opens the TCP connection to an upstream returned by a plugin.
// downstream is the client's address. The default is a plain net.Dial; the
// daemon replaces it when --preserve-source-port is set.
var DialUpstream = func(network, addr string, downstream net.Addr) (net.Conn, error) {
	return net.Dial(network, addr)
}
