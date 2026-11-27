// Package reqmeta carries the client IP and user agent of the current
// request (and, for the acting API, the service acting on a user's behalf)
// through the context, for sessions and the audit log.
package reqmeta

import "context"

type Meta struct {
	IP        string
	UserAgent string
	// Via names the internal service acting on the user's behalf (e.g.
	// "roleserv"); audit events record it as meta.via.
	Via string
}

type ctxKey struct{}

func With(ctx context.Context, m Meta) context.Context { return context.WithValue(ctx, ctxKey{}, m) }

func From(ctx context.Context) Meta {
	m, _ := ctx.Value(ctxKey{}).(Meta)
	return m
}
