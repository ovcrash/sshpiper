package main

// relay: how the daemon connects to the upstream (backend): client version,
// source port, and the audit of each upstream connection.

import (
	"log/slog"
	"net"

	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/plugin"
	"github.com/urfave/cli/v2"
)

func upstreamFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    "copy-client-version",
			Usage:   "announce the client's own version line to the upstream instead of the library default",
			EnvVars: []string{"SSHPIPERD_COPY_CLIENT_VERSION"},
		},
	}
}

// setupUpstream installs the upstream dialer. Without --preserve-source-port,
// --copy-client-version and --audit-dir it leaves the upstream behavior as is.
func (d *daemon) setupUpstream(ctx *cli.Context) {
	if ctx.Bool("copy-client-version") {
		plugin.CopyClientVersion = true
		slog.Info("upstream connections announce the client's version")
	}

	keepPort := ctx.Bool("preserve-source-port")
	if keepPort {
		slog.Info("upstream connections keep the client source port when possible")
	}
	if !keepPort && d.audit == nil {
		return
	}

	plugin.DialUpstream = func(network, addr string, downstream net.Addr) (net.Conn, error) {
		sess := d.auditSessionForAddr(downstream)

		var onClose func(net.Conn)
		if sess != nil {
			onClose = func(c net.Conn) { sess.BackendDisconnected(c.LocalAddr(), c.RemoteAddr()) }
		}

		var (
			c   net.Conn
			err error
		)
		if keepPort {
			c, err = dialKeepSourcePortHook(network, addr, downstream, onClose)
		} else {
			if c, err = net.Dial(network, addr); err == nil {
				c = withCloseHook(c, onClose)
			}
		}

		if sess != nil {
			if err != nil {
				sess.BackendConnectError(addr, err)
			} else {
				sess.BackendConnected(c.LocalAddr(), c.RemoteAddr())
			}
		}
		return c, err
	}
}
