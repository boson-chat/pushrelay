// Package push accepts RFC 8030 pushes from installs (§2.2): checks the
// mailbox, VAPID, size and rate limits, then forwards to APNs / FCM.
package push

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/pushrelay/internal/apperr"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
	"github.com/boson-chat/pushrelay/internal/logger"
	"github.com/boson-chat/pushrelay/internal/services/alert"
	"github.com/boson-chat/pushrelay/internal/services/delivery"
	"github.com/boson-chat/pushrelay/internal/services/mailboxes"
	"github.com/boson-chat/pushrelay/internal/services/ratelimit"
	"github.com/boson-chat/pushrelay/internal/webpush"
	"github.com/boson-chat/pushrelay/metrics"
)

// Deps are the service's dependencies.
type Deps struct {
	Store   repo.MailboxRepository
	Sender  delivery.Sender
	VAPID   webpush.Verifier
	Metrics *metrics.Metrics
	Alerter alert.Alerter
	Now     func() time.Time
	// PerMailbox is the token bucket per mailbox id.
	PerMailbox *ratelimit.Buckets
	// MailboxEvery is the bucket refill interval (Retry-After hint).
	MailboxEvery time.Duration
	// PerInstall counts pushes per install per hour.
	PerInstall      *ratelimit.Window
	MailboxDaily    int
	MaxPayloadBytes int
	DefaultTTL      time.Duration
	MaxTTL          time.Duration
	Timeout         time.Duration
}

// Service is the push service.
type Service struct{ d Deps }

// New returns the service.
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{d: d}
}

// Input is one POST /v1/push/{id}.
type Input struct {
	MailboxID       string
	Authorization   string
	CryptoKey       string
	ContentEncoding string
	TTL             string
	Urgency         string
	Topic           string
	Body            []byte
	// BodyTooLarge: the handler stopped reading above MaxPayloadBytes.
	BodyTooLarge bool
}

// Result is a forwarded push.
type Result struct {
	// TTL actually applied (RFC 8030: echoed in the response).
	TTL time.Duration
	// MessageID names the push message resource (Location); the relay
	// keeps no messages, so it can't be fetched or deleted.
	MessageID string
}

// Client-facing errors (RFC 8030 status codes).
var (
	ErrNotFound      = apperr.New(http.StatusNotFound, "mailbox_not_found", "no such mailbox")
	ErrUnauthorized  = apperr.New(http.StatusUnauthorized, "vapid_invalid", "VAPID authorization missing or invalid")
	ErrBlocked       = apperr.New(http.StatusForbidden, "install_blocked", "this mailbox is paused")
	ErrTooLarge      = apperr.New(http.StatusRequestEntityTooLarge, "payload_too_large", "push body is too large")
	ErrEncoding      = apperr.New(http.StatusUnsupportedMediaType, "unsupported_encoding", "Content-Encoding must be aes128gcm")
	ErrEmpty         = apperr.New(http.StatusBadRequest, "empty_body", "push body is empty")
	ErrBadTTL        = apperr.New(http.StatusBadRequest, "invalid_ttl", "TTL must be a non-negative integer")
	ErrBadUrgency    = apperr.New(http.StatusBadRequest, "invalid_urgency", "Urgency must be very-low, low, normal or high")
	ErrBadTopic      = apperr.New(http.StatusBadRequest, "invalid_topic", "Topic must be at most 32 base64url characters")
	ErrMailboxRate   = apperr.New(http.StatusTooManyRequests, "rate_limited", "too many pushes for this mailbox")
	ErrMailboxDaily  = apperr.New(http.StatusTooManyRequests, "daily_limit", "daily push limit for this mailbox reached")
	ErrInstallRate   = apperr.New(http.StatusTooManyRequests, "install_rate_limited", "hourly push ceiling for this install reached")
	ErrGone          = apperr.New(http.StatusGone, "gone", "the device is no longer registered; drop this subscription")
	ErrUpstream      = apperr.New(http.StatusBadGateway, "upstream_error", "the push service failed, retry later")
	ErrUpstreamBusy  = apperr.New(http.StatusTooManyRequests, "upstream_rate_limited", "the push service is rate limiting, retry later")
	ErrNotDeliverble = apperr.New(http.StatusServiceUnavailable, "platform_unavailable", "the relay cannot deliver to this platform")
)

// Accept validates and forwards a push.
func (s *Service) Accept(ctx context.Context, in Input) (Result, error) {
	m, res, outcome, err := s.accept(ctx, in)
	s.d.Metrics.Push(outcome)
	ev := logger.FromCtx(ctx).Info()
	if err != nil {
		if e, ok := apperr.As(err); !ok || e.Status >= 500 {
			ev = logger.FromCtx(ctx).Warn().Err(err)
		}
	}
	ev = ev.Str("mailbox", in.MailboxID).Int("size", len(in.Body)).Str("outcome", outcome)
	if m != nil {
		ev = ev.Str("install", m.Install).Str("platform", m.Platform)
	}
	ev.Msg("push")
	return res, err
}

func secondsUntilNext(now time.Time, size time.Duration) time.Duration {
	return now.Truncate(size).Add(size).Sub(now).Round(time.Second) + time.Second
}

func (s *Service) accept(ctx context.Context, in Input) (*repo.Mailbox, Result, string, error) {
	m, err := s.d.Store.GetMailbox(ctx, in.MailboxID)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, Result{}, "not_found", ErrNotFound
	}
	if err != nil {
		return nil, Result{}, "error", err
	}
	if m.Paused {
		return m, Result{}, "blocked", ErrBlocked
	}
	auth, err := webpush.ParseAuthorization(in.Authorization, in.CryptoKey)
	if err == nil {
		_, err = s.d.VAPID.Verify(auth, m.VAPIDKey)
	}
	if err != nil {
		return m, Result{}, "unauthorized", &apperr.Error{Status: ErrUnauthorized.Status, Code: ErrUnauthorized.Code,
			Message: ErrUnauthorized.Message + ": " + strings.TrimPrefix(err.Error(), "vapid: ")}
	}
	if in.BodyTooLarge || len(in.Body) > s.d.MaxPayloadBytes {
		return m, Result{}, "too_large", ErrTooLarge
	}
	if !strings.EqualFold(strings.TrimSpace(in.ContentEncoding), "aes128gcm") {
		return m, Result{}, "unsupported_encoding", ErrEncoding
	}
	if len(in.Body) == 0 {
		return m, Result{}, "bad_request", ErrEmpty
	}
	ttl := s.d.DefaultTTL
	if t := strings.TrimSpace(in.TTL); t != "" {
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil || n < 0 {
			return m, Result{}, "bad_request", ErrBadTTL
		}
		if n > int64(s.d.MaxTTL/time.Second) {
			n = int64(s.d.MaxTTL / time.Second)
		}
		ttl = time.Duration(n) * time.Second
	}
	urgency := strings.ToLower(strings.TrimSpace(in.Urgency))
	switch urgency {
	case "":
		urgency = "normal"
	case "very-low", "low", "normal", "high":
	default:
		return m, Result{}, "bad_request", ErrBadUrgency
	}
	topic := strings.TrimSpace(in.Topic)
	if !validTopic(topic) {
		return m, Result{}, "bad_request", ErrBadTopic
	}

	now := s.d.Now()
	if !s.d.PerMailbox.Allow(m.ID) {
		return m, Result{}, "rate_limited_mailbox", ErrMailboxRate.WithRetryAfter(s.d.MailboxEvery)
	}
	if n, ok := s.d.PerInstall.Add(m.Install); !ok {
		if n == s.d.PerInstall.Limit()+1 {
			s.d.Metrics.InstallAlert()
			s.d.Alerter.Alert(ctx, alert.Alert{Kind: "install_hourly_ceiling", Install: m.Install, Count: n,
				Limit: s.d.PerInstall.Limit(), Time: now, Message: "install above its hourly push ceiling; pushes get 429 until the hour ends"})
		}
		return m, Result{}, "rate_limited_install", ErrInstallRate.WithRetryAfter(secondsUntilNext(now, time.Hour))
	}
	n, err := s.d.Store.CountPush(ctx, m.ID, mailboxes.Day(now), now)
	if errors.Is(err, repo.ErrNotFound) {
		return m, Result{}, "not_found", ErrNotFound
	}
	if err != nil {
		return m, Result{}, "error", err
	}
	if n > s.d.MailboxDaily {
		return m, Result{}, "rate_limited_daily", ErrMailboxDaily.WithRetryAfter(secondsUntilNext(now.UTC(), 24*time.Hour))
	}

	msg := delivery.Message{
		MailboxID: m.ID, Platform: m.Platform, Token: m.Token, Body: in.Body,
		TTL: ttl, Urgency: urgency, Topic: topic, Now: now,
	}
	sctx, cancel := context.WithTimeout(ctx, s.d.Timeout)
	defer cancel()
	start := time.Now()
	err = s.d.Sender.Send(sctx, msg)
	svc := delivery.ServiceName(m.Platform)
	var ue *delivery.UpstreamError
	switch {
	case err == nil:
		s.d.Metrics.Upstream(svc, "ok", time.Since(start))
		s.d.Metrics.PushBytes(len(in.Body))
		return m, Result{TTL: ttl, MessageID: messageID()}, "accepted", nil
	case errors.Is(err, delivery.ErrUnregistered):
		s.d.Metrics.Upstream(svc, "unregistered", time.Since(start))
		if _, derr := s.d.Store.DeleteMailbox(ctx, m.ID); derr != nil {
			return m, Result{}, "error", derr
		}
		s.d.PerMailbox.Forget(m.ID)
		return m, Result{}, "gone", ErrGone
	case errors.Is(err, delivery.ErrPayloadTooLarge):
		s.d.Metrics.Upstream(svc, "too_large", time.Since(start))
		return m, Result{}, "too_large", ErrTooLarge
	case errors.Is(err, delivery.ErrPlatformUnavailable):
		return m, Result{}, "platform_unavailable", ErrNotDeliverble
	case errors.As(err, &ue):
		s.d.Metrics.Upstream(svc, "error_"+strconv.Itoa(ue.Status), time.Since(start))
		if ue.Status == http.StatusTooManyRequests {
			return m, Result{}, "upstream_rate_limited", ErrUpstreamBusy.WithRetryAfter(time.Minute)
		}
		return m, Result{}, "upstream_error", &apperr.Error{Status: ErrUpstream.Status, Code: ErrUpstream.Code,
			Message: ErrUpstream.Message + " (" + ue.Error() + ")"}
	default:
		s.d.Metrics.Upstream(svc, "error", time.Since(start))
		return m, Result{}, "upstream_error", ErrUpstream
	}
}

// validTopic: RFC 8030 §5.4, at most 32 characters of the URL and
// filename safe base64 alphabet.
func validTopic(t string) bool {
	if len(t) > 32 {
		return false
	}
	for _, r := range t {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func messageID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
