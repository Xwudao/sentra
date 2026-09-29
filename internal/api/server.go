// Package api implements the Sentra management API and serves the embedded
// admin SPA. It is control-plane only.
package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/Xwudao/sentra/internal/engine"
	"github.com/Xwudao/sentra/internal/metrics"
	"github.com/Xwudao/sentra/internal/storage"
	"github.com/Xwudao/sentra/internal/webassets"
)

// Config configures the management server.
type Config struct {
	// AdminToken, when non-empty, is required as a bearer token for /api/*.
	AdminToken string
	// Version is reported by the dashboard.
	Version string
}

// Server is the management API.
type Server struct {
	engine *engine.Engine
	store  storage.Store
	logger *slog.Logger
	cfg    Config
	m      *http.ServeMux

	tokenHash [32]byte
	hasToken  bool
}

// New builds a management server.
func New(eng *engine.Engine, store storage.Store, logger *slog.Logger, cfg Config) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{engine: eng, store: store, logger: logger, cfg: cfg, m: http.NewServeMux()}
	if cfg.AdminToken != "" {
		s.tokenHash = sha256.Sum256([]byte(cfg.AdminToken))
		s.hasToken = true
	}
	s.routes()
	return s
}

// Metrics exposes the engine metrics (for the Caddy adapter's /metrics).
func (s *Server) Metrics() *metrics.Metrics { return s.engine.Metrics() }

func (s *Server) routes() {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/dashboard", s.handleDashboard)
	api.HandleFunc("GET /api/metrics", s.handleMetrics)
	api.HandleFunc("GET /api/events", s.handleListEvents)
	api.HandleFunc("GET /api/events/{id}", s.handleGetEvent)
	api.HandleFunc("GET /api/rules", s.handleListRules)
	api.HandleFunc("POST /api/rules", s.handleCreateRule)
	api.HandleFunc("GET /api/rules/{id}", s.handleGetRule)
	api.HandleFunc("PUT /api/rules/{id}", s.handleUpdateRule)
	api.HandleFunc("DELETE /api/rules/{id}", s.handleDeleteRule)
	api.HandleFunc("POST /api/rules/test", s.handleRuleTest)
	api.HandleFunc("GET /api/ip-rules", s.handleListIPRules)
	api.HandleFunc("POST /api/ip-rules", s.handleCreateIPRule)
	api.HandleFunc("DELETE /api/ip-rules/{id}", s.handleDeleteIPRule)
	api.HandleFunc("GET /api/settings", s.handleGetSettings)
	api.HandleFunc("PUT /api/settings", s.handleUpdateSettings)

	s.m.Handle("/api/", s.requireAuth(api))
	s.m.HandleFunc("GET /metrics", s.handlePrometheus)
	s.m.Handle("/", s.spaHandler())
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler { return s.m }

// requireAuth enforces bearer-token auth for /api/*. When no token is
// configured, only loopback clients are permitted.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hasToken {
			if isLoopback(r.RemoteAddr) {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusUnauthorized, "admin token not configured; management API is restricted to loopback")
			return
		}
		auth := r.Header.Get("Authorization")
		tok, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || !s.tokenValid(tok) {
			writeError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) tokenValid(token string) bool {
	if token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], s.tokenHash[:]) == 1
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) spaHandler() http.Handler {
	dist := webassets.Dist()
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if f, err := dist.Open(path); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}

func (s *Server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(s.engine.Metrics().Prometheus()))
}

// ------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Response is already partially written; nothing safe to do.
		_ = err
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func decodeRaw(raw json.RawMessage, v any) error {
	return json.Unmarshal(raw, v)
}

func encodeRaw(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
