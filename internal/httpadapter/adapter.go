// Package httpadapter is a net/http adapter for the Sentra engine. It exists
// to prove the engine is decoupled from Caddy and powers the standalone
// command.
package httpadapter

import (
	"net/http"

	"github.com/Xwudao/sentra/internal/engine"
)

// Handler evaluates requests and forwards allowed traffic to Next.
type Handler struct {
	Engine *engine.Engine
	Next   http.Handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Engine == nil {
		h.next().ServeHTTP(w, r)
		return
	}
	rc := h.Engine.NewContext(r)
	d := h.Engine.Evaluate(rc)
	if d.Blocked {
		status := d.StatusCode
		if status == 0 {
			status = http.StatusForbidden
		}
		w.Header().Set("X-Sentra-Action", "blocked")
		http.Error(w, http.StatusText(status), status)
		return
	}
	h.next().ServeHTTP(w, r)
}

func (h *Handler) next() http.Handler {
	if h.Next == nil {
		return http.NotFoundHandler()
	}
	return h.Next
}
