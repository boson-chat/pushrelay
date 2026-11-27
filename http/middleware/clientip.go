// Package middleware holds the HTTP middleware.
package middleware

import (
	"net"
	nethttp "net/http"
	"net/netip"
	"strings"

	"github.com/boson-chat/pushrelay/internal/reqmeta"
)

// ClientIP resolves the client address and stores it, with the user agent,
// in the request context (reqmeta). X-Forwarded-For is only honoured when the
// direct peer is a trusted proxy; then the rightmost untrusted hop wins, so a
// client can't spoof its address by sending its own X-Forwarded-For.
func ClientIP(trusted []netip.Prefix) func(nethttp.Handler) nethttp.Handler {
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return func(next nethttp.Handler) nethttp.Handler {
		return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			ip := ResolveClientIP(r, isTrusted)
			ctx := reqmeta.With(r.Context(), reqmeta.Meta{IP: ip, UserAgent: r.UserAgent()})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ResolveClientIP implements the X-Forwarded-For walk described on ClientIP.
func ResolveClientIP(r *nethttp.Request, isTrusted func(netip.Addr) bool) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !isTrusted(peer) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = a.Unmap()
		if !isTrusted(client) {
			break
		}
	}
	return client.String()
}
