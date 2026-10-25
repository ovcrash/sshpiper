package main

// relay: graceful shutdown on SIGTERM/SIGINT, so the audit queue is flushed.

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// Shutdown stops accepting new connections so run() returns and the deferred
// audit flush (see main) runs. It is idempotent.
func (d *daemon) Shutdown() {
	if d.closing.Swap(true) {
		return
	}
	slog.Info("shutting down")
	_ = d.lis.Close()
}

// installSignalHandler calls Shutdown on the first SIGTERM or SIGINT. A second
// signal aborts immediately, in case a flush hangs.
func (d *daemon) installSignalHandler() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	go func() {
		<-ctx.Done()
		stop() // restore default handling: a second signal kills the process
		d.Shutdown()
	}()
}
