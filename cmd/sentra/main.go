// Command sentra runs the Sentra WAF as a standalone reverse proxy with the
// management API. For Caddy deployments use the Caddy module instead.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Xwudao/sentra/internal/api"
	"github.com/Xwudao/sentra/internal/defaults"
	"github.com/Xwudao/sentra/internal/engine"
	"github.com/Xwudao/sentra/internal/event"
	"github.com/Xwudao/sentra/internal/httpadapter"
	"github.com/Xwudao/sentra/internal/metrics"
	"github.com/Xwudao/sentra/internal/storage"
)

func main() {
	var (
		dbPath     = flag.String("db", "sentra.db", "SQLite database path")
		listen     = flag.String("listen", "127.0.0.1:8080", "WAF listener address")
		upstream   = flag.String("upstream", "", "upstream URL to reverse proxy to (optional)")
		adminAddr  = flag.String("admin", "127.0.0.1:2020", "management API listen address")
		adminToken = flag.String("admin-token", os.Getenv("SENTRA_ADMIN_TOKEN"), "management API bearer token")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	store, err := storage.Open(*dbPath)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	if err := defaults.Seed(context.Background(), store); err != nil {
		logger.Error("failed to seed defaults", "error", err)
	}

	m := &metrics.Metrics{}
	writer := event.NewWriter(store, m, logger, event.WriterConfig{})
	defer writer.Close()

	eng := engine.New(engine.DefaultConfig(), engine.Options{Metrics: m, Events: writer, Logger: logger})
	defer eng.Close()

	rules, err := store.ListRules(context.Background())
	if err != nil {
		logger.Error("failed to load rules", "error", err)
	} else if _, err := eng.ReloadRules(rules); err != nil {
		logger.Error("failed to compile rules", "error", err)
	}
	if err := api.LoadSettings(eng, store); err != nil {
		logger.Error("failed to load settings", "error", err)
	}

	admin := api.New(eng, store, logger, api.Config{AdminToken: *adminToken, Version: "standalone"})
	adminSrv := &http.Server{Addr: *adminAddr, Handler: admin.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		logger.Info("management API listening", "address", *adminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("admin server error", "error", err)
		}
	}()

	var next http.Handler = http.NotFoundHandler()
	if *upstream != "" {
		u, err := url.Parse(*upstream)
		if err != nil {
			logger.Error("invalid upstream", "error", err)
			os.Exit(1)
		}
		next = httputil.NewSingleHostReverseProxy(u)
	}
	wafSrv := &http.Server{
		Addr:              *listen,
		Handler:           &httpadapter.Handler{Engine: eng, Next: next},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info("WAF listening", "address", *listen, "upstream", *upstream)
		if err := wafSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("waf server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = wafSrv.Shutdown(ctx)
	_ = adminSrv.Shutdown(ctx)
}
