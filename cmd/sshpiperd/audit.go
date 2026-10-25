package main

// relay: wiring between the daemon and the audit package.

import (
	"net"
	"os"
	"strconv"

	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/audit"
	"github.com/urfave/cli/v2"
)

// auditFlags returns the audit options. Without --audit-dir nothing is
// recorded by the audit package and the daemon behaves as before.
func auditFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "audit-dir",
			Usage:   "directory for the structured audit (JSONL + asciicast); empty disables it",
			EnvVars: []string{"SSHPIPERD_AUDIT_DIR"},
		},
		&cli.IntFlag{
			Name:    "audit-queue-size",
			Value:   10000,
			Usage:   "bounded audit queue length; records are dropped and counted when it is full",
			EnvVars: []string{"SSHPIPERD_AUDIT_QUEUE_SIZE"},
		},
		&cli.StringFlag{
			Name:    "sensor-name",
			Usage:   "sensor name stamped on every audit event (default: hostname)",
			EnvVars: []string{"SSHPIPERD_SENSOR_NAME"},
		},
	}
}

// setupAudit opens the audit writer when --audit-dir is set.
func (d *daemon) setupAudit(ctx *cli.Context) error {
	dir := ctx.String("audit-dir")
	if dir == "" {
		return nil
	}
	sensor := ctx.String("sensor-name")
	if sensor == "" {
		sensor, _ = os.Hostname()
	}
	w, err := audit.NewWriter(audit.Options{
		Dir:       dir,
		QueueSize: ctx.Int("audit-queue-size"),
		Sensor:    sensor,
	})
	if err != nil {
		return err
	}
	d.audit = w
	d.auditShutdown = ctx.Duration("login-grace-time")
	return nil
}

// startAudit wraps the connection so the client handshake is captured and
// creates the session recorder (which emits piper.session.connect). When
// auditing is off it returns the connection unchanged and a nil session.
func (d *daemon) startAudit(c net.Conn) (*audit.Session, net.Conn) {
	if d.audit == nil {
		return nil, c
	}
	cc := newCaptureConn(c)
	srcIP, srcPort := splitAddr(c.RemoteAddr())
	dstIP, dstPort := splitAddr(c.LocalAddr())
	sess := audit.NewSession(d.audit, cc.sessionID, srcIP, srcPort, dstIP, dstPort)
	return sess, cc
}

// recordHandshake emits the client version and KEXINIT events once the
// handshake bytes have been captured.
func (d *daemon) recordHandshake(sess *audit.Session, c net.Conn) {
	cc, ok := c.(*captureConn)
	if !ok {
		return
	}
	version, kex, ok := cc.clientHandshake()
	if !ok {
		return
	}
	sess.Emit(&audit.Event{EventID: audit.EventVersion, Version: version, Message: "client version " + version})
	ev := &audit.Event{
		EventID:         audit.EventKex,
		HASSH:           kex.HASSH(),
		HASSHAlgorithms: kex.HASSHAlgorithms(),
		KexAlgs:         kex.KexAlgos,
		KeyAlgs:         kex.ServerHostKeyAlgos,
		EncCS:           kex.CiphersClientServer,
		MacCS:           kex.MACsClientServer,
		CompCS:          kex.CompressionClientServer,
		LangCS:          kex.LanguagesClientServer,
	}
	sess.Emit(ev)
}

func splitAddr(a net.Addr) (string, int) {
	if a == nil {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}
