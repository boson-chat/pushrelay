package attest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boson-chat/pushrelay/internal/db/memstore"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

type stubVerifier struct {
	err   error
	calls int
	last  []byte
}

func (s *stubVerifier) Verify(_ context.Context, _ Request, h []byte) error {
	s.calls++
	s.last = h
	return s.err
}

func newService() (*Service, *stubVerifier, *stubVerifier, *time.Time) {
	now := testNow
	ios, android := &stubVerifier{}, &stubVerifier{}
	return &Service{
		AppAttest: ios, PlayIntegrity: android,
		DevAllowlist: []string{"dev-secret", "devicetoken0"}, DevPlatforms: []string{repo.PlatformAPNsSandbox},
		Challenges: memstore.New(), ChallengeTTL: 5 * time.Minute, Now: func() time.Time { return now },
	}, ios, android, &now
}

func TestDevAllowlist(t *testing.T) {
	s, ios, _, _ := newService()
	ctx := context.Background()
	res, err := s.Verify(ctx, Request{Platform: repo.PlatformAPNsSandbox, Attestation: "dev-secret"})
	require.NoError(t, err)
	assert.Equal(t, MethodDev, res.Method)
	assert.Zero(t, ios.calls)

	// Not for platforms outside DevPlatforms: falls through to the real check.
	_, err = s.Verify(ctx, Request{Platform: repo.PlatformAPNs, Attestation: "dev-secret"})
	assert.ErrorIs(t, err, ErrChallenge)
	// Wrong token.
	_, err = s.Verify(ctx, Request{Platform: repo.PlatformAPNsSandbox, Attestation: "dev-secretx"})
	assert.ErrorIs(t, err, ErrChallenge)
	// A listed device token.
	res, err = s.Verify(ctx, Request{Platform: repo.PlatformAPNsSandbox, Token: "devicetoken0"})
	require.NoError(t, err)
	assert.Equal(t, MethodDev, res.Method)
	// Empty allowlist entries never match.
	s.DevAllowlist = []string{""}
	_, err = s.Verify(ctx, Request{Platform: repo.PlatformAPNsSandbox, Attestation: ""})
	assert.ErrorIs(t, err, ErrMissing)
}

func TestChallengeFlow(t *testing.T) {
	s, ios, android, now := newService()
	ctx := context.Background()
	c, exp, err := s.NewChallenge(ctx)
	require.NoError(t, err)
	assert.Len(t, c, 43)
	assert.Equal(t, testNow.Add(5*time.Minute), exp)

	req := Request{Platform: repo.PlatformFCM, Token: "t", Challenge: c, Attestation: "integrity"}
	res, err := s.Verify(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, MethodPlayIntegrity, res.Method)
	assert.Equal(t, 1, android.calls)
	assert.Equal(t, req.ClientDataHash(), android.last)

	// Single use.
	_, err = s.Verify(ctx, req)
	assert.ErrorIs(t, err, ErrChallenge)

	// Expired.
	c2, _, err := s.NewChallenge(ctx)
	require.NoError(t, err)
	*now = now.Add(6 * time.Minute)
	_, err = s.Verify(ctx, Request{Platform: repo.PlatformAPNs, Challenge: c2, Attestation: "a"})
	assert.ErrorIs(t, err, ErrChallenge)
	assert.Zero(t, ios.calls)

	// Missing challenge.
	_, err = s.Verify(ctx, Request{Platform: repo.PlatformAPNs, Attestation: "a"})
	assert.ErrorIs(t, err, ErrChallenge)

	// Verifier failure passes through; the challenge is burnt anyway.
	ios.err = failed("nope")
	c3, _, _ := s.NewChallenge(ctx)
	_, err = s.Verify(ctx, Request{Platform: repo.PlatformAPNs, Challenge: c3, AttestationObject: "x"})
	assert.ErrorIs(t, err, ErrFailed)
	ios.err = nil
	_, err = s.Verify(ctx, Request{Platform: repo.PlatformAPNs, Challenge: c3, AttestationObject: "x"})
	assert.ErrorIs(t, err, ErrChallenge)
}

func TestUnavailable(t *testing.T) {
	s, _, _, _ := newService()
	s.AppAttest, s.PlayIntegrity = nil, nil
	_, err := s.Verify(context.Background(), Request{Platform: repo.PlatformAPNs, Attestation: "x"})
	assert.ErrorIs(t, err, ErrUnavailable)
	_, err = s.Verify(context.Background(), Request{Platform: repo.PlatformFCM, Attestation: "x"})
	assert.ErrorIs(t, err, ErrUnavailable)
	_, err = s.Verify(context.Background(), Request{Platform: "web", Attestation: "x"})
	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestClientData(t *testing.T) {
	r := Request{Challenge: "C", Platform: "fcm", Token: "T", VAPID: "V", Install: "I"}
	assert.Equal(t, "boson-push-v1\nC\nfcm\nT\nV\nI", string(r.ClientData()))
	assert.Len(t, r.ClientDataHash(), 32)
	w := failed("detail %d", 1)
	assert.Contains(t, w.Error(), "detail 1")
	assert.True(t, errors.Is(w, ErrFailed))
	_, err := decodeB64("***")
	assert.Error(t, err)
}
