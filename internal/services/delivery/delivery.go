// Package delivery forwards an encrypted Web Push body to APNs or FCM.
// The body is never decrypted; it travels base64-encoded under the
// "boson" key (APNs) or as data fields (FCM), see README "What the app receives".
package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

// PayloadVersion is the "v" field the app checks.
const PayloadVersion = 1

// Message is one push to forward.
type Message struct {
	MailboxID string
	Platform  string
	Token     string
	// Body is the RFC 8291 aes128gcm body, passed through opaque.
	Body []byte
	// TTL from the push (0: deliver now or drop).
	TTL time.Duration
	// Urgency per RFC 8030: very-low, low, normal, high.
	Urgency string
	// Topic per RFC 8030 (optional): pushes with the same topic replace
	// each other on the device.
	Topic string
	// Now is the send time (TTL is relative to it).
	Now time.Time
}

// CollapseID is mailbox id + a topic hash, or "" without a Topic.
func (m Message) CollapseID() string {
	if m.Topic == "" {
		return ""
	}
	h := sha256.Sum256([]byte(m.Topic))
	return m.MailboxID + "." + hex.EncodeToString(h[:8])
}

// HighPriority reports whether the push should wake the device now.
func (m Message) HighPriority() bool { return m.Urgency != "low" && m.Urgency != "very-low" }

// Sender delivers to one push service.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

var (
	// ErrUnregistered: the device token is dead; delete the mailbox, answer 410.
	ErrUnregistered = errors.New("device token unregistered")
	// ErrPayloadTooLarge: the wrapped push exceeds the push service limit.
	ErrPayloadTooLarge = errors.New("payload too large for the push service")
	// ErrPlatformUnavailable: the relay has no credentials for the platform.
	ErrPlatformUnavailable = errors.New("platform not configured")
)

// UpstreamError is any other push service failure.
type UpstreamError struct {
	Service string
	Status  int
	Reason  string
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("%s: HTTP %d %s", e.Service, e.Status, e.Reason)
}

// Router picks the sender by platform.
type Router struct {
	APNs Sender // apns and apns-sandbox
	FCM  Sender
}

// Send implements Sender.
func (r Router) Send(ctx context.Context, m Message) error {
	var s Sender
	switch m.Platform {
	case repo.PlatformAPNs, repo.PlatformAPNsSandbox:
		s = r.APNs
	case repo.PlatformFCM:
		s = r.FCM
	}
	if s == nil {
		return ErrPlatformUnavailable
	}
	return s.Send(ctx, m)
}

// Available reports whether the platform can be delivered to.
func (r Router) Available(platform string) bool {
	switch platform {
	case repo.PlatformAPNs, repo.PlatformAPNsSandbox:
		return r.APNs != nil
	case repo.PlatformFCM:
		return r.FCM != nil
	}
	return false
}

// Service names (metrics labels).
func ServiceName(platform string) string {
	if platform == repo.PlatformFCM {
		return "fcm"
	}
	return "apns"
}

// transportReason drops the request URL (it holds the device token) from
// a client error.
func transportReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return "transport: " + ue.Err.Error()
	}
	return "transport: " + err.Error()
}
