// Command relay-admind exposes a REST/JSON API to fill and drive the relay
// registry (add entries, manage personas, probe, expose, retire) without
// restarting the proxy. It is a separate process from the daemon: the daemon
// reads the registry read-only, relay-admind is the writer.
//
// A VM is created outside this project; the API then registers it and hands
// back the host keys to install on it.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tg123/sshpiper/auditindex"
	"github.com/tg123/sshpiper/registry"
	"github.com/tg123/sshpiper/relayadmin"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "relay-admind",
		Usage: "REST API to register relay entries into the registry",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "registry", Usage: "path of the registry database", EnvVars: []string{"SSHPIPERD_REGISTRY", "RELAY_ADMIN_REGISTRY"}, Required: true},
			&cli.StringFlag{Name: "address", Value: "127.0.0.1:8090", Usage: "listening address", EnvVars: []string{"RELAY_ADMIN_ADDRESS"}},
			&cli.StringFlag{Name: "tls-cert", Usage: "server certificate (PEM); required unless --insecure", EnvVars: []string{"RELAY_ADMIN_TLS_CERT"}},
			&cli.StringFlag{Name: "tls-key", Usage: "server private key (PEM); required unless --insecure", EnvVars: []string{"RELAY_ADMIN_TLS_KEY"}},
			&cli.StringFlag{Name: "api-token-file", Usage: "file holding the bearer token required on every call", EnvVars: []string{"RELAY_ADMIN_TOKEN_FILE"}},
			&cli.StringFlag{Name: "api-token", Usage: "bearer token (prefer --api-token-file)", EnvVars: []string{"RELAY_ADMIN_TOKEN"}},
			&cli.StringFlag{Name: "audit-dir", Usage: "audit directory to browse read-only; enables the /v1/audit/* endpoints and the console's audit views", EnvVars: []string{"SSHPIPERD_AUDIT_DIR", "RELAY_ADMIN_AUDIT_DIR"}},
			&cli.StringFlag{Name: "web-static-path", Usage: "console UI source: empty = embedded (default), 'disable' = API only, or a directory on disk", EnvVars: []string{"RELAY_ADMIN_WEB_STATIC_PATH"}},
			&cli.BoolFlag{Name: "insecure", Usage: "serve plain HTTP (only on a trusted local network)", EnvVars: []string{"RELAY_ADMIN_INSECURE"}},
		},
		Action: run,
	}
	if err := app.Run(os.Args); err != nil {
		slog.Error("relay-admind failed", "error", err)
		os.Exit(1)
	}
}

func run(c *cli.Context) error {
	token, err := loadToken(c)
	if err != nil {
		return err
	}
	tlsCfg, err := loadTLS(c)
	if err != nil {
		return err
	}

	db, err := registry.Open(c.String("registry"), registry.Options{})
	if err != nil {
		return fmt.Errorf("cannot open registry: %w", err)
	}
	defer db.Close()

	srv := &server{svc: relayadmin.New(db), webPath: c.String("web-static-path")}
	if dir := c.String("audit-dir"); dir != "" {
		store, err := auditindex.Open(dir)
		if err != nil {
			return fmt.Errorf("cannot open audit dir: %w", err)
		}
		srv.audit = store
		slog.Info("audit browsing enabled", "dir", dir)
	}
	handler := requireToken(token, srv.routes())

	httpSrv := &http.Server{
		Addr:              c.String("address"),
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shctx)
	}()

	slog.Info("relay-admind listening", "address", c.String("address"), "tls", tlsCfg != nil)
	if tlsCfg != nil {
		err = httpSrv.ListenAndServeTLS("", "")
	} else {
		err = httpSrv.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func loadToken(c *cli.Context) (string, error) {
	if f := c.String("api-token-file"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if t := c.String("api-token"); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("a bearer token is required: set --api-token-file or --api-token")
}

func loadTLS(c *cli.Context) (*tls.Config, error) {
	cert, key := c.String("tls-cert"), c.String("tls-key")
	if c.Bool("insecure") {
		if cert != "" || key != "" {
			return nil, fmt.Errorf("--insecure cannot be combined with --tls-cert/--tls-key")
		}
		slog.Warn("serving plain HTTP: --insecure is only safe on a trusted local network")
		return nil, nil
	}
	if cert == "" || key == "" {
		return nil, fmt.Errorf("--tls-cert and --tls-key are required (or pass --insecure)")
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("cannot load TLS key pair: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}

// requireToken guards every /v1/* call with the bearer token. The health
// check and the static console assets (any path not under /v1/) are open: the
// assets are just HTML/JS and the console sends the token on its own API
// calls.
func requireToken(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/v1/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := []byte(r.Header.Get("Authorization"))
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid or missing bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}
