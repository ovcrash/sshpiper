package plugin

import "golang.org/x/crypto/ssh"

// MetaDstAddr is the connection metadata key holding the local address of
// the accepted socket (ip:port), i.e. the address the client connected to.
// Plugins read it with ConnMetadata.GetMeta.
const MetaDstAddr = "sshpiperd.dst_addr"

// initialMetadata returns the metadata a new connection starts with.
func initialMetadata(conn ssh.ConnMetadata) map[string]string {
	m := make(map[string]string)
	if addr := conn.LocalAddr(); addr != nil {
		m[MetaDstAddr] = addr.String()
	}
	return m
}
