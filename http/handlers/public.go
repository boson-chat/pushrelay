// Package handlers maps HTTP requests onto the services: the public API
// (phones and installs) and the operator API on the internal listener.
package handlers

import (
	"context"
	"io"
	nethttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/pushrelay/http/router"
	"github.com/boson-chat/pushrelay/internal/apperr"
	"github.com/boson-chat/pushrelay/internal/reqmeta"
	"github.com/boson-chat/pushrelay/internal/services/mailboxes"
	"github.com/boson-chat/pushrelay/internal/services/push"
	"github.com/boson-chat/pushrelay/internal/services/ratelimit"
)

// Challenger issues attestation challenges (attest.Service).
type Challenger interface {
	NewChallenge(ctx context.Context) (string, time.Time, error)
}

// Public serves /v1/... and health checks.
type Public struct {
	Mailboxes  *mailboxes.Service
	Push       *push.Service
	Challenges Challenger
	// ChallengePerIP limits GET /v1/challenge per client IP (each stores a row).
	ChallengePerIP  *ratelimit.Window
	MaxPayloadBytes int
	PublicURL       string
	Version         string
	Ready           func(ctx context.Context) error
	Now             func() time.Time
}

// Register adds the routes to mux.
func (h *Public) Register(mux *nethttp.ServeMux) {
	mux.HandleFunc("GET /{$}", h.root)
	mux.HandleFunc("GET /v1/challenge", h.challenge)
	mux.HandleFunc("POST /v1/mailboxes", h.createMailbox)
	mux.HandleFunc("PATCH /v1/mailboxes/{id}", h.updateMailbox)
	mux.HandleFunc("DELETE /v1/mailboxes/{id}", h.deleteMailbox)
	mux.HandleFunc("POST /v1/push/{id}", h.push)
	RegisterHealth(mux, h.Ready)
}

// RegisterHealth adds /healthz (process up) and /readyz (database reachable).
func RegisterHealth(mux *nethttp.ServeMux, ready func(ctx context.Context) error) {
	mux.HandleFunc("GET /healthz", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		router.WriteJSON(w, nethttp.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if ready != nil {
			if err := ready(ctx); err != nil {
				router.WriteJSON(w, nethttp.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
				return
			}
		}
		router.WriteJSON(w, nethttp.StatusOK, map[string]string{"status": "ok"})
	})
}

func (h *Public) root(w nethttp.ResponseWriter, _ *nethttp.Request) {
	router.WriteJSON(w, nethttp.StatusOK, map[string]any{
		"service": "boson pushrelay", "version": h.Version, "api": "v1",
		"docs": "https://github.com/boson-chat/pushrelay",
	})
}

var errTooManyChallenges = apperr.New(nethttp.StatusTooManyRequests, "rate_limited", "too many challenges from this address, retry later")

func (h *Public) challenge(w nethttp.ResponseWriter, r *nethttp.Request) {
	if h.ChallengePerIP != nil {
		if _, ok := h.ChallengePerIP.Add(reqmeta.From(r.Context()).IP); !ok {
			router.WriteError(w, r, errTooManyChallenges.WithRetryAfter(time.Minute))
			return
		}
	}
	c, exp, err := h.Challenges.NewChallenge(r.Context())
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	router.WriteJSON(w, nethttp.StatusOK, map[string]any{
		"challenge":  c,
		"expires_at": exp.UTC().Format(time.RFC3339),
		"expires_in": int(exp.Sub(now).Round(time.Second).Seconds()),
	})
}

func (h *Public) createMailbox(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in mailboxes.CreateInput
	if err := router.Decode(w, r, &in); err != nil {
		router.WriteError(w, r, err)
		return
	}
	in.ClientIP = reqmeta.From(r.Context()).IP
	out, err := h.Mailboxes.Create(r.Context(), in)
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	w.Header().Set("Location", out.Endpoint)
	router.WriteJSON(w, nethttp.StatusCreated, out)
}

func bearer(r *nethttp.Request) string {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}

func (h *Public) updateMailbox(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in mailboxes.UpdateInput
	if err := router.DecodeOptional(w, r, &in); err != nil {
		router.WriteError(w, r, err)
		return
	}
	if err := h.Mailboxes.Update(r.Context(), r.PathValue("id"), bearer(r), in); err != nil {
		router.WriteError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

func (h *Public) deleteMailbox(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.Mailboxes.Delete(r.Context(), r.PathValue("id"), bearer(r)); err != nil {
		router.WriteError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

// push is the RFC 8030 push resource. 201 + Location on success.
func (h *Public) push(w nethttp.ResponseWriter, r *nethttp.Request) {
	in := push.Input{
		MailboxID:       r.PathValue("id"),
		Authorization:   r.Header.Get("Authorization"),
		CryptoKey:       r.Header.Get("Crypto-Key"),
		ContentEncoding: r.Header.Get("Content-Encoding"),
		TTL:             r.Header.Get("TTL"),
		Urgency:         r.Header.Get("Urgency"),
		Topic:           r.Header.Get("Topic"),
	}
	if r.ContentLength > int64(h.MaxPayloadBytes) {
		in.BodyTooLarge = true
	} else {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(h.MaxPayloadBytes)+1))
		if err != nil {
			router.WriteError(w, r, apperr.Invalid("could not read the push body"))
			return
		}
		in.Body = body
		in.BodyTooLarge = len(body) > h.MaxPayloadBytes
	}
	res, err := h.Push.Accept(r.Context(), in)
	if err != nil {
		router.WriteError(w, r, err)
		return
	}
	w.Header().Set("TTL", strconv.Itoa(int(res.TTL/time.Second)))
	w.Header().Set("Location", h.PublicURL+"/v1/push/"+in.MailboxID+"/messages/"+res.MessageID)
	w.WriteHeader(nethttp.StatusCreated)
}
