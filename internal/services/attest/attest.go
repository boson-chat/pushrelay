// Package attest decides whether a mailbox request comes from the genuine
// official app on a real device: App Attest (iOS), Play Integrity
// (Android), or a configured development allowlist.
package attest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/boson-chat/pushrelay/internal/apperr"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

// Methods reported in Result.
const (
	MethodAppAttest     = "app-attest"
	MethodPlayIntegrity = "play-integrity"
	MethodDev           = "dev"
)

// Request is what a mailbox creation carries for attestation.
type Request struct {
	Platform string
	// Values exactly as sent in the request body; ClientData binds them.
	App       string
	Token     string
	VAPID     string
	Install   string
	Challenge string
	// iOS: App Attest assertion (base64 CBOR). Android: Play Integrity
	// token. Development builds: an allowlisted dev token.
	Attestation string
	// iOS: App Attest key id (base64, as DCAppAttestService returns it).
	KeyID string
	// iOS: App Attest attestation object (base64 CBOR), sent when the key
	// is not registered with the relay yet.
	AttestationObject string
}

// ClientData is the byte string the app hashes (SHA-256) into App Attest's
// clientDataHash and Play Integrity's requestHash / nonce. It binds the
// challenge to the mailbox being created.
func (r Request) ClientData() []byte {
	return []byte("boson-push-v1\n" + r.Challenge + "\n" + r.Platform + "\n" + r.Token + "\n" + r.VAPID + "\n" + r.Install)
}

// ClientDataHash is SHA-256(ClientData()).
func (r Request) ClientDataHash() []byte {
	h := sha256.Sum256(r.ClientData())
	return h[:]
}

// Result says how a request was attested.
type Result struct {
	Method string
}

// Verifier is one attestation mechanism. clientDataHash is Request.ClientDataHash().
type Verifier interface {
	Verify(ctx context.Context, req Request, clientDataHash []byte) error
}

// Errors (client-facing).
var (
	ErrChallenge   = apperr.New(http.StatusUnauthorized, "challenge_invalid", "challenge missing, unknown, used or expired: GET /v1/challenge first")
	ErrFailed      = apperr.New(http.StatusUnauthorized, "attestation_failed", "attestation did not verify")
	ErrKeyUnknown  = apperr.New(http.StatusUnauthorized, "attest_key_unknown", "App Attest key not registered: send attestation_object")
	ErrMissing     = apperr.New(http.StatusBadRequest, "attestation_missing", "attestation is required")
	ErrUnavailable = apperr.New(http.StatusServiceUnavailable, "attestation_unavailable", "attestation for this platform is not configured on the relay")
	ErrUpstream    = apperr.New(http.StatusServiceUnavailable, "attestation_upstream", "attestation service unavailable, retry later")
)

func failed(format string, args ...any) error {
	return &wrapped{public: ErrFailed, detail: fmt.Sprintf(format, args...)}
}

// wrapped is a client-facing error carrying an internal detail for logs.
type wrapped struct {
	public *apperr.Error
	detail string
}

func (w *wrapped) Error() string { return w.public.Error() + " (" + w.detail + ")" }
func (w *wrapped) Unwrap() error { return w.public }

// Service checks the dev allowlist, the challenge, then the platform's verifier.
type Service struct {
	AppAttest     Verifier // apns, apns-sandbox; nil: unavailable
	PlayIntegrity Verifier // fcm; nil: unavailable
	// DevAllowlist entries let a request on DevPlatforms in without
	// attestation when they equal its attestation value or its device token.
	DevAllowlist []string
	DevPlatforms []string
	Challenges   repo.ChallengeRepository
	ChallengeTTL time.Duration
	Now          func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// NewChallenge stores and returns a single-use random challenge.
func (s *Service) NewChallenge(ctx context.Context) (string, time.Time, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	c := base64.RawURLEncoding.EncodeToString(b)
	exp := s.now().Add(s.ChallengeTTL)
	h := sha256.Sum256([]byte(c))
	if err := s.Challenges.PutChallenge(ctx, h[:], exp); err != nil {
		return "", time.Time{}, err
	}
	return c, exp, nil
}

func (s *Service) isDev(req Request) bool {
	platformOK := false
	for _, p := range s.DevPlatforms {
		platformOK = platformOK || p == req.Platform
	}
	if !platformOK {
		return false
	}
	ok := false
	for _, t := range s.DevAllowlist {
		if t == "" {
			continue
		}
		if req.Attestation != "" && subtle.ConstantTimeCompare([]byte(t), []byte(req.Attestation)) == 1 {
			ok = true
		}
		if req.Token != "" && subtle.ConstantTimeCompare([]byte(t), []byte(req.Token)) == 1 {
			ok = true
		}
	}
	return ok
}

// Verify attests a mailbox request.
func (s *Service) Verify(ctx context.Context, req Request) (Result, error) {
	if s.isDev(req) {
		return Result{Method: MethodDev}, nil
	}
	if req.Attestation == "" && req.AttestationObject == "" {
		return Result{}, ErrMissing
	}
	var v Verifier
	method := ""
	switch req.Platform {
	case repo.PlatformAPNs, repo.PlatformAPNsSandbox:
		v, method = s.AppAttest, MethodAppAttest
	case repo.PlatformFCM:
		v, method = s.PlayIntegrity, MethodPlayIntegrity
	}
	if v == nil {
		return Result{}, ErrUnavailable
	}
	if req.Challenge == "" {
		return Result{}, ErrChallenge
	}
	h := sha256.Sum256([]byte(req.Challenge))
	ok, err := s.Challenges.ConsumeChallenge(ctx, h[:], s.now())
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, ErrChallenge
	}
	if err := v.Verify(ctx, req, req.ClientDataHash()); err != nil {
		return Result{}, err
	}
	return Result{Method: method}, nil
}

// decodeB64 accepts standard or URL base64, padded or not.
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}
