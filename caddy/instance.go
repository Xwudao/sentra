// Package caddymod implements the Caddy v2 HTTP handler adapter for the Sentra
// WAF engine. The engine itself lives in internal/engine and is Caddy-free.
package caddymod

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/Xwudao/sentra/internal/api"
	"github.com/Xwudao/sentra/internal/defaults"
	"github.com/Xwudao/sentra/internal/engine"
	"github.com/Xwudao/sentra/internal/event"
	"github.com/Xwudao/sentra/internal/ipset"
	"github.com/Xwudao/sentra/internal/metrics"
	"github.com/Xwudao/sentra/internal/storage"
)

// instance is the process-wide WAF state shared by every Caddy handler that
// points at the same database.
type instance struct {
	engine *engine.Engine
	store  *storage.SQLite
	writer *event.Writer
	admin  *http.Server
	logger *slog.Logger

	refs int
}

var (
	regMu sync.Mutex
	reg   = map[string]*instance{}
)

type handlerConfig struct {
	dbPath             string
	maxRequestBodySize int64
	bodyLimitAction    engine.BodyLimitAction
	anomalyThreshold   int
	trustedProxies     []netip.Prefix
	clientIPHeader     string
	adminListen        string
	adminToken         string
	version            string
}

func defaultDBPath() string {
	if dir := os.Getenv("SENTRA_DATA_DIR"); dir != "" {
		return filepath.Join(dir, "sentra.db")
	}
	if dir := caddy.AppDataDir(); dir != "" {
		return filepath.Join(dir, "sentra", "sentra.db")
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "sentra", "sentra.db")
	}
	return "sentra.db"
}

func acquire(cfg handlerConfig) (*instance, error) {
	regMu.Lock()
	defer regMu.Unlock()

	key := cfg.dbPath
	if inst, ok := reg[key]; ok {
		inst.refs++
		return inst, nil
	}
	inst, err := buildInstance(cfg)
	if err != nil {
		return nil, err
	}
	reg[key] = inst
	return inst, nil
}

func release(inst *instance) {
	if inst == nil {
		return
	}
	regMu.Lock()
	defer regMu.Unlock()
	inst.refs--
	if inst.refs > 0 {
		return
	}
	delete(reg, inst.store.Path())
	shutdownInstance(inst)
}

func buildInstance(cfg handlerConfig) (*instance, error) {
	if cfg.dbPath == "" {
		cfg.dbPath = defaultDBPath()
	}
	if dir := filepath.Dir(cfg.dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create sentra data dir: %w", err)
		}
	}

	store, err := storage.Open(cfg.dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sentra database: %w", err)
	}

	logger := slog.Default()
	m := &metrics.Metrics{}

	if err := defaults.Seed(context.Background(), store); err != nil {
		logger.Error("failed to seed default rules", "error", err)
	}

	writer := event.NewWriter(store, m, logger, event.WriterConfig{})

	engineCfg := engine.DefaultConfig()
	engineCfg.MaxRequestBodySize = cfg.maxRequestBodySize
	if cfg.maxRequestBodySize <= 0 {
		engineCfg.MaxRequestBodySize = engine.DefaultConfig().MaxRequestBodySize
	}
	engineCfg.BodyLimitAction = cfg.bodyLimitAction
	if engineCfg.BodyLimitAction == "" {
		engineCfg.BodyLimitAction = engine.BodyLimitAllow
	}
	engineCfg.AnomalyThreshold = cfg.anomalyThreshold
	engineCfg.TrustedProxies = cfg.trustedProxies
	engineCfg.ClientIPHeader = cfg.clientIPHeader

	eng := engine.New(engineCfg, engine.Options{Metrics: m, Events: writer, Logger: logger})

	rules, err := store.ListRules(context.Background())
	if err != nil {
		logger.Error("failed to load rules", "error", err)
	}
	if _, err := eng.ReloadRules(rules); err != nil {
		logger.Error("failed to compile rules; starting with empty ruleset", "error", err)
	}

	if err := loadIPRules(context.Background(), eng, store); err != nil {
		logger.Error("failed to load ip rules", "error", err)
	}
	if err := api.LoadSettings(eng, store); err != nil {
		logger.Error("failed to load settings", "error", err)
	}

	inst := &instance{engine: eng, store: store, writer: writer, logger: logger}

	if cfg.adminListen != "off" {
		if err := startAdmin(inst, cfg); err != nil {
			shutdownInstance(inst)
			return nil, err
		}
	}
	return inst, nil
}

func loadIPRules(ctx context.Context, eng *engine.Engine, store storage.Store) error {
	stored, err := store.ListIPRules(ctx)
	if err != nil {
		return err
	}
	entries := make([]ipset.Entry, 0, len(stored))
	for _, e := range stored {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			continue
		}
		action := ipset.ActionBlock
		if e.Action == "allow" {
			action = ipset.ActionAllow
		}
		entries = append(entries, ipset.Entry{ID: e.ID, Prefix: p, Action: action, Note: e.Note})
	}
	return eng.ReloadIPRules(entries)
}

func startAdmin(inst *instance, cfg handlerConfig) error {
	listen := cfg.adminListen
	if listen == "" {
		listen = "127.0.0.1:2020"
	}
	apiSrv := api.New(inst.engine, inst.store, inst.logger, api.Config{
		AdminToken: cfg.adminToken,
		Version:    cfg.version,
	})
	srv := &http.Server{
		Addr:              listen,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on admin address %s: %w", listen, err)
	}
	inst.admin = srv
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			inst.logger.Error("sentra admin server stopped", "error", err)
		}
	}()
	inst.logger.Info("sentra admin API listening", "address", ln.Addr().String())
	return nil
}

func shutdownInstance(inst *instance) {
	if inst.admin != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = inst.admin.Shutdown(ctx)
		cancel()
	}
	if inst.writer != nil {
		inst.writer.Close()
	}
	if inst.engine != nil {
		inst.engine.Close()
	}
	if inst.store != nil {
		_ = inst.store.Close()
	}
}
