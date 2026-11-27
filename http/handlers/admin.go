package handlers

import (
	"context"
	"crypto/subtle"
	nethttp "net/http"

	"github.com/boson-chat/pushrelay/http/router"
	"github.com/boson-chat/pushrelay/internal/apperr"
	"github.com/boson-chat/pushrelay/internal/services/mailboxes"
	"github.com/boson-chat/pushrelay/internal/services/ratelimit"
)

// Admin serves the operator API (/admin/v1) on the internal listener.
type Admin struct {
	Mailboxes *mailboxes.Service
	// PerInstall is the hourly push window (current counts).
	PerInstall *ratelimit.Window
	// Token must be sent as X-Internal-Token (or Authorization: Bearer).
	// Empty: the operator API answers 503.
	Token string
}

// Register adds the routes to mux.
func (h *Admin) Register(mux *nethttp.ServeMux) {
	mux.Handle("GET /admin/v1/installs", h.auth(h.installs))
	mux.Handle("GET /admin/v1/installs/{install}", h.auth(h.installs))
	mux.Handle("GET /admin/v1/blocks", h.auth(h.blocks))
	mux.Handle("PUT /admin/v1/blocks/{install}", h.auth(h.block))
	mux.Handle("DELETE /admin/v1/blocks/{install}", h.auth(h.unblock))
	mux.Handle("GET /admin/v1/mailboxes/{id}", h.auth(h.getMailbox))
	mux.Handle("DELETE /admin/v1/mailboxes/{id}", h.auth(h.deleteMailbox))
	mux.Handle("POST /admin/v1/mailboxes/{id}/pause", h.auth(h.pause(true)))
	mux.Handle("POST /admin/v1/mailboxes/{id}/resume", h.auth(h.pause(false)))
	mux.Handle("POST /admin/v1/expire", h.auth(h.expire))
}

var (
	errAdminAuth = apperr.New(nethttp.StatusUnauthorized, "unauthenticated", "send PUSHRELAY_INTERNAL_TOKEN as X-Internal-Token")
	errAdminOff  = apperr.New(nethttp.StatusServiceUnavailable, "admin_disabled", "PUSHRELAY_INTERNAL_TOKEN is not set")
)

func (h *Admin) auth(f nethttp.HandlerFunc) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if h.Token == "" {
			router.WriteError(w, r, errAdminOff)
			return
		}
		tok := r.Header.Get("X-Internal-Token")
		if tok == "" {
			tok = bearer(r)
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(h.Token)) != 1 {
			router.WriteError(w, r, errAdminAuth)
			return
		}
		f(w, r)
	})
}

func (h *Admin) installs(w nethttp.ResponseWriter, r *nethttp.Request) {
	install := r.PathValue("install")
	if install == "" {
		install = r.URL.Query().Get("install")
	}
	out, err := h.Mailboxes.Installs(r.Context(), install, h.PerInstall.Snapshot(), h.PerInstall.Limit())
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	if r.PathValue("install") != "" {
		if len(out) == 0 {
			router.WriteError(w, r, apperr.ErrNotFound)
			return
		}
		router.WriteJSON(w, nethttp.StatusOK, out[0])
		return
	}
	router.WriteJSON(w, nethttp.StatusOK, map[string]any{"installs": out})
}

func (h *Admin) blocks(w nethttp.ResponseWriter, r *nethttp.Request) {
	out, err := h.Mailboxes.Blocks(r.Context())
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	router.WriteJSON(w, nethttp.StatusOK, map[string]any{"blocks": out})
}

func (h *Admin) block(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := router.DecodeOptional(w, r, &in); err != nil {
		router.WriteError(w, r, err)
		return
	}
	n, err := h.Mailboxes.Block(r.Context(), r.PathValue("install"), in.Reason)
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	router.WriteJSON(w, nethttp.StatusOK, map[string]any{"install": r.PathValue("install"), "paused_mailboxes": n})
}

func (h *Admin) unblock(w nethttp.ResponseWriter, r *nethttp.Request) {
	n, err := h.Mailboxes.Unblock(r.Context(), r.PathValue("install"))
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	router.WriteJSON(w, nethttp.StatusOK, map[string]any{"install": r.PathValue("install"), "resumed_mailboxes": n})
}

func (h *Admin) getMailbox(w nethttp.ResponseWriter, r *nethttp.Request) {
	v, err := h.Mailboxes.AdminGet(r.Context(), r.PathValue("id"))
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	router.WriteJSON(w, nethttp.StatusOK, v)
}

func (h *Admin) deleteMailbox(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.Mailboxes.AdminDelete(r.Context(), r.PathValue("id")); err != nil {
		router.WriteError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

func (h *Admin) pause(paused bool) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if err := h.Mailboxes.AdminSetPaused(r.Context(), r.PathValue("id"), paused); err != nil {
			router.WriteError(w, r, err)
			return
		}
		w.WriteHeader(nethttp.StatusNoContent)
	}
}

func (h *Admin) expire(w nethttp.ResponseWriter, r *nethttp.Request) {
	n, err := h.Mailboxes.Expire(context.WithoutCancel(r.Context()))
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	router.WriteJSON(w, nethttp.StatusOK, map[string]any{"expired_mailboxes": n})
}
