//go:build full

// traceplugin is a spike helper: it routes password logins to a fixed target
// like the fixed plugin, and logs every callback it receives with the
// connection metadata, so the order and content of the calls can be observed.
package main

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func logConn(event string, conn libplugin.ConnMetadata, args ...any) {
	base := []any{
		"event", event,
		"user", conn.User(),
		"from", conn.RemoteAddr(),
		"uniq_id", conn.UniqueID(),
	}
	slog.Info("trace", append(base, args...)...)
}

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "traceplugin",
		Usage: "spike helper: log every callback, route passwords to a fixed target",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "target",
				Usage:    "target ssh endpoint address",
				EnvVars:  []string{"SSHPIPERD_TRACEPLUGIN_TARGET"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "next-methods",
				Usage:   "comma-separated list returned by NextAuthMethods; empty disables the callback",
				EnvVars: []string{"SSHPIPERD_TRACEPLUGIN_NEXT_METHODS"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			host, port, err := libplugin.SplitHostPortForSSH(c.String("target"))
			if err != nil {
				return nil, err
			}
			uri := fmt.Sprintf("tcp://%v", net.JoinHostPort(host, strconv.Itoa(port)))

			config := &libplugin.SshPiperPluginConfig{
				NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
					logConn("NewConnection", conn)
					return nil
				},
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					logConn("Password", conn, "password_len", len(password))
					return &libplugin.Upstream{
						Uri:  uri,
						Auth: libplugin.CreatePasswordAuth(password),
					}, nil
				},
				PublicKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
					fp := "unparsable"
					if pk, err := ssh.ParsePublicKey(key); err == nil {
						fp = ssh.FingerprintSHA256(pk)
					}
					logConn("PublicKey", conn, "fingerprint", fp)
					return nil, fmt.Errorf("publickey rejected by traceplugin")
				},
				UpstreamAuthFailureCallback: func(conn libplugin.ConnMetadata, method string, err error, allowmethods []string) {
					logConn("UpstreamAuthFailure", conn, "method", method, "error", err, "allowed", allowmethods)
				},
				PipeStartCallback: func(conn libplugin.ConnMetadata) {
					logConn("PipeStart", conn)
				},
				PipeErrorCallback: func(conn libplugin.ConnMetadata, err error) {
					logConn("PipeError", conn, "error", err)
				},
				PipeCreateErrorCallback: func(remoteAddr string, err error) {
					slog.Info("trace", "event", "PipeCreateError", "from", remoteAddr, "error", err)
				},
			}

			if next := c.String("next-methods"); next != "" {
				methods := strings.Split(next, ",")
				config.NextAuthMethodsCallback = func(conn libplugin.ConnMetadata) ([]string, error) {
					logConn("NextAuthMethods", conn, "returned", methods)
					return methods, nil
				}
			}

			return config, nil
		},
	})
}
