// Package mailboxes creates, updates, deletes and expires mailboxes
// (§2.1, §2.3) and holds the operator controls (§2.4).
package mailboxes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/boson-chat/pushrelay/internal/apperr"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
	"github.com/boson-chat/pushrelay/internal/logger"
	"github.com/boson-chat/pushrelay/internal/services/attest"
	"github.com/boson-chat/pushrelay/internal/services/ratelimit"
	"github.com/boson-chat/pushrelay/internal/webpush"
	"github.com/boson-chat/pushrelay/metrics"
)

// Attester verifies mailbox requests (attest.Service).
type Attester interface {
	Verify(ctx context.Context, req attest.Request) (attest.Result, error)
}

// Platforms reports which platforms the relay can deliver to (delivery.Router).
type Platforms interface {
	Available(platform string) bool
}

// Deps are the service's dependencies.
type Deps struct {
	Store     repo.Store
	Attest    Attester
	Platforms Platforms
	Metrics   *metrics.Metrics
	Now       func() time.Time
	// PublicURL is the relay's base URL; endpoints are PublicURL/v1/push/<id>.
	PublicURL string
	// Apps maps platform → the app id requests must name (bundle id / package).
	Apps map[string]string
	// CreatePerIP limits creations per client IP.
	CreatePerIP *ratelimit.Window
	// MaxPerInstall caps mailboxes per install (0: unlimited).
	MaxPerInstall int
	// Expiry deletes mailboxes unused this long.
	Expiry time.Duration
	// OnDelete is called with ids of deleted mailboxes (rate limiter cleanup).
	OnDelete func(ids ...string)
}

// Service is the mailbox service.
type Service struct{ d Deps }

// New returns the service.
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.OnDelete == nil {
		d.OnDelete = func(...string) {}
	}
	return &Service{d: d}
}

// CreateInput is POST /v1/mailboxes.
type CreateInput struct {
	Platform          string `json:"platform"`
	Token             string `json:"token"`
	App               string `json:"app"`
	Attestation       string `json:"attestation"`
	VAPID             string `json:"vapid"`
	Install           string `json:"install"`
	Challenge         string `json:"challenge,omitempty"`
	KeyID             string `json:"key_id,omitempty"`
	AttestationObject string `json:"attestation_object,omitempty"`
	ClientIP          string `json:"-"`
}

// Created is the POST /v1/mailboxes response.
type Created struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Secret   string `json:"secret"`
}

// Client-facing errors.
var (
	ErrNotFound          = apperr.New(http.StatusNotFound, "mailbox_not_found", "no such mailbox")
	ErrNoSecret          = apperr.New(http.StatusUnauthorized, "secret_required", "send the mailbox secret as Authorization: Bearer <secret>")
	ErrBadSecret         = apperr.New(http.StatusForbidden, "secret_invalid", "wrong mailbox secret")
	ErrInstallBlocked    = apperr.New(http.StatusForbidden, "install_blocked", "this install is blocked on the relay")
	ErrTooManyCreates    = apperr.New(http.StatusTooManyRequests, "rate_limited", "too many mailboxes created from this address, retry later")
	ErrInstallFull       = apperr.New(http.StatusTooManyRequests, "install_mailbox_limit", "this install has too many mailboxes")
	ErrPlatformNotOnline = apperr.New(http.StatusServiceUnavailable, "platform_unavailable", "the relay cannot deliver to this platform")
)

// NormalizeInstall lowercases and checks an install domain (a DNS name).
func NormalizeInstall(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 {
		return "", apperr.Invalid("install must be the install's domain name")
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", apperr.Invalid("install must be the install's domain name")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", apperr.Invalid("install must be the install's domain name")
			}
		}
	}
	return s, nil
}

func validToken(platform, t string) bool {
	if t == "" || len(t) > 4096 {
		return false
	}
	for _, r := range t {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		case platform == repo.PlatformFCM && (r >= 'g' && r <= 'z' || r >= 'G' && r <= 'Z' || r == ':' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSecret is how management secrets are stored.
func HashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// Endpoint is the push URL of a mailbox.
func (s *Service) Endpoint(id string) string { return s.d.PublicURL + "/v1/push/" + id }

// Create verifies the attestation and creates (or replaces) the mailbox
// for (platform, token, install).
func (s *Service) Create(ctx context.Context, in CreateInput) (*Created, error) {
	out, err := s.create(ctx, in)
	outcome := "ok"
	if err != nil {
		outcome = "error"
		if e, ok := apperr.As(err); ok {
			outcome = e.Code
		}
	}
	s.d.Metrics.MailboxOp("create", outcome)
	return out, err
}

func (s *Service) create(ctx context.Context, in CreateInput) (*Created, error) {
	if !repo.ValidPlatform(in.Platform) {
		return nil, apperr.Invalid("platform must be apns, apns-sandbox or fcm")
	}
	if !validToken(in.Platform, in.Token) {
		return nil, apperr.Invalid("token is not a device token for this platform")
	}
	if want := s.d.Apps[in.Platform]; in.App != want {
		return nil, apperr.New(http.StatusBadRequest, "app_mismatch", "app must be "+want)
	}
	vapid, err := webpush.CanonicalKey(in.VAPID)
	if err != nil {
		return nil, apperr.Invalid("vapid must be the install's VAPID public key (base64url P-256 point)")
	}
	install, err := NormalizeInstall(in.Install)
	if err != nil {
		return nil, err
	}
	if !s.d.Platforms.Available(in.Platform) {
		return nil, ErrPlatformNotOnline
	}
	if _, ok := s.d.CreatePerIP.Add(in.ClientIP); !ok {
		return nil, ErrTooManyCreates
	}
	blocked, err := s.d.Store.IsInstallBlocked(ctx, install)
	if err != nil {
		return nil, err
	}
	if blocked {
		return nil, ErrInstallBlocked
	}
	if s.d.MaxPerInstall > 0 {
		n, err := s.d.Store.CountMailboxesForInstall(ctx, install)
		if err != nil {
			return nil, err
		}
		if n >= int64(s.d.MaxPerInstall) {
			return nil, ErrInstallFull
		}
	}
	res, err := s.d.Attest.Verify(ctx, attest.Request{
		Platform: in.Platform, App: in.App, Token: in.Token, VAPID: in.VAPID, Install: in.Install,
		Challenge: in.Challenge, Attestation: in.Attestation, KeyID: in.KeyID, AttestationObject: in.AttestationObject,
	})
	method := methodFor(in.Platform)
	if err != nil {
		s.d.Metrics.Attestation(method, "rejected")
		logger.FromCtx(ctx).Info().Err(err).Str("platform", in.Platform).Str("install", install).Msg("attestation rejected")
		return nil, err
	}
	s.d.Metrics.Attestation(res.Method, "ok")
	id, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	secret, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	m := &repo.Mailbox{
		ID: id, Platform: in.Platform, Token: in.Token, VAPIDKey: vapid, Install: install,
		SecretHash: HashSecret(secret), CreatedAt: now, UpdatedAt: now, LastUsedAt: now,
	}
	replaced, err := s.d.Store.CreateMailbox(ctx, m)
	if err != nil {
		return nil, err
	}
	s.d.OnDelete(replaced...)
	logger.FromCtx(ctx).Info().Str("mailbox", id).Str("install", install).Str("platform", in.Platform).
		Str("attestation", res.Method).Int("replaced", len(replaced)).Msg("mailbox created")
	return &Created{ID: id, Endpoint: s.Endpoint(id), Secret: secret}, nil
}

func methodFor(platform string) string {
	if platform == repo.PlatformFCM {
		return attest.MethodPlayIntegrity
	}
	return attest.MethodAppAttest
}

func (s *Service) authorize(ctx context.Context, id, secret string) (*repo.Mailbox, error) {
	if secret == "" {
		return nil, ErrNoSecret
	}
	m, err := s.d.Store.GetMailbox(ctx, id)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(m.SecretHash, HashSecret(secret)) != 1 {
		return nil, ErrBadSecret
	}
	return m, nil
}

// UpdateInput is PATCH /v1/mailboxes/{id}. A missing token only renews
// the mailbox (resets the unused-expiry clock).
type UpdateInput struct {
	Token *string `json:"token,omitempty"`
}

// Update sets a new device token and/or renews the mailbox.
func (s *Service) Update(ctx context.Context, id, secret string, in UpdateInput) error {
	err := s.update(ctx, id, secret, in)
	s.d.Metrics.MailboxOp("update", outcomeOf(err))
	return err
}

func (s *Service) update(ctx context.Context, id, secret string, in UpdateInput) error {
	m, err := s.authorize(ctx, id, secret)
	if err != nil {
		return err
	}
	now := s.d.Now()
	if in.Token == nil || *in.Token == m.Token {
		return s.d.Store.TouchMailbox(ctx, id, now)
	}
	if !validToken(m.Platform, *in.Token) {
		return apperr.Invalid("token is not a device token for this platform")
	}
	replaced, err := s.d.Store.UpdateMailboxToken(ctx, id, *in.Token, now)
	if errors.Is(err, repo.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	s.d.OnDelete(replaced...)
	logger.FromCtx(ctx).Info().Str("mailbox", id).Str("install", m.Install).Msg("mailbox token updated")
	return nil
}

// Delete removes a mailbox (sign-out, server removed, push turned off).
func (s *Service) Delete(ctx context.Context, id, secret string) error {
	err := s.delete(ctx, id, secret)
	s.d.Metrics.MailboxOp("delete", outcomeOf(err))
	return err
}

func (s *Service) delete(ctx context.Context, id, secret string) error {
	m, err := s.authorize(ctx, id, secret)
	if err != nil {
		return err
	}
	if _, err := s.d.Store.DeleteMailbox(ctx, id); err != nil {
		return err
	}
	s.d.OnDelete(id)
	logger.FromCtx(ctx).Info().Str("mailbox", id).Str("install", m.Install).Msg("mailbox deleted")
	return nil
}

func outcomeOf(err error) string {
	if err == nil {
		return "ok"
	}
	if e, ok := apperr.As(err); ok {
		return e.Code
	}
	return "error"
}

// Expire deletes mailboxes unused for the expiry and expired challenges.
func (s *Service) Expire(ctx context.Context) (int64, error) {
	now := s.d.Now()
	n, err := s.d.Store.DeleteMailboxesUnusedSince(ctx, now.Add(-s.d.Expiry))
	if err != nil {
		return 0, err
	}
	if _, err := s.d.Store.DeleteExpiredChallenges(ctx, now); err != nil {
		return n, err
	}
	s.d.Metrics.Expired(n)
	if counts, err := s.d.Store.CountMailboxesByPlatform(ctx); err == nil {
		s.d.Metrics.SetMailboxes(counts)
	}
	return n, nil
}

// RefreshGauges updates the mailboxes-by-platform gauge.
func (s *Service) RefreshGauges(ctx context.Context) error {
	counts, err := s.d.Store.CountMailboxesByPlatform(ctx)
	if err != nil {
		return err
	}
	s.d.Metrics.SetMailboxes(counts)
	return nil
}
