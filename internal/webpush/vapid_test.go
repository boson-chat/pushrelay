package webpush

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const origin = "https://push.example"

var now = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ek, err := k.PublicKey.ECDH()
	require.NoError(t, err)
	return k, base64.RawURLEncoding.EncodeToString(ek.Bytes())
}

func sign(t *testing.T, k *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(k)
	require.NoError(t, err)
	return s
}

func verifier() Verifier {
	return Verifier{Origin: origin, MaxExp: 24 * time.Hour, Leeway: time.Minute, Now: func() time.Time { return now }}
}

func header(tok, key string) string { return "vapid t=" + tok + ", k=" + key }

func TestVerifyValid(t *testing.T) {
	k, pub := newKey(t)
	tok := sign(t, k, jwt.MapClaims{"aud": origin, "exp": now.Add(12 * time.Hour).Unix(), "sub": "https://irc.example/"})
	a, err := ParseAuthorization(header(tok, pub), "")
	require.NoError(t, err)
	sub, err := verifier().Verify(a, pub)
	require.NoError(t, err)
	assert.Equal(t, "https://irc.example/", sub)

	// aud as an array, with a trailing slash; key with padding.
	tok = sign(t, k, jwt.MapClaims{"aud": []string{"https://other", origin + "/"}, "exp": now.Add(time.Hour).Unix()})
	a, err = ParseAuthorization(header(tok, pub+"="), "")
	require.NoError(t, err)
	_, err = verifier().Verify(a, pub)
	require.NoError(t, err)
}

func TestVerifyLegacyWebPushScheme(t *testing.T) {
	k, pub := newKey(t)
	tok := sign(t, k, jwt.MapClaims{"aud": origin, "exp": now.Add(time.Hour).Unix()})
	a, err := ParseAuthorization("WebPush "+tok, "dh=abc; p256ecdsa="+pub)
	require.NoError(t, err)
	_, err = verifier().Verify(a, pub)
	require.NoError(t, err)
}

func TestVerifyRejects(t *testing.T) {
	k, pub := newKey(t)
	other, otherPub := newKey(t)
	good := jwt.MapClaims{"aud": origin, "exp": now.Add(time.Hour).Unix()}
	cases := []struct {
		name   string
		tok    string
		k      string
		bound  string
		expect error
	}{
		{"wrong key", sign(t, other, good), otherPub, pub, ErrKeyMismatch},
		{"signed by another key", sign(t, other, good), pub, pub, ErrBadSignature},
		{"expired", sign(t, k, jwt.MapClaims{"aud": origin, "exp": now.Add(-time.Hour).Unix()}), pub, pub, ErrExpired},
		{"wrong aud", sign(t, k, jwt.MapClaims{"aud": "https://evil.example", "exp": now.Add(time.Hour).Unix()}), pub, pub, ErrAudience},
		{"no aud", sign(t, k, jwt.MapClaims{"exp": now.Add(time.Hour).Unix()}), pub, pub, ErrAudience},
		{"exp too far", sign(t, k, jwt.MapClaims{"aud": origin, "exp": now.Add(25 * time.Hour).Unix()}), pub, pub, ErrExpTooFar},
		{"no exp", sign(t, k, jwt.MapClaims{"aud": origin}), pub, pub, ErrMalformed},
		{"garbage token", "not.a.jwt", pub, pub, ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := ParseAuthorization(header(c.tok, c.k), "")
			require.NoError(t, err)
			_, err = verifier().Verify(a, c.bound)
			assert.ErrorIs(t, err, c.expect)
		})
	}
}

func TestVerifyRejectsHS256(t *testing.T) {
	_, pub := newKey(t)
	raw, _ := DecodeKey(pub)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"aud": origin, "exp": now.Add(time.Hour).Unix()}).SignedString(raw)
	require.NoError(t, err)
	a, err := ParseAuthorization(header(tok, pub), "")
	require.NoError(t, err)
	_, err = verifier().Verify(a, pub)
	assert.ErrorIs(t, err, ErrBadSignature)
}

func TestParseAuthorizationErrors(t *testing.T) {
	_, pub := newKey(t)
	for name, c := range map[string]struct {
		auth, crypto string
		want         error
	}{
		"empty":         {"", "", ErrNoAuth},
		"basic":         {"Basic abc", "", ErrMalformed},
		"no t":          {"vapid k=" + pub, "", ErrMalformed},
		"no k":          {"vapid t=abc", "", ErrMalformed},
		"junk part":     {"vapid t=abc, junk", "", ErrMalformed},
		"bad key":       {"vapid t=abc, k=AAAA", "", ErrBadKey},
		"webpush no ck": {"WebPush abc", "", ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAuthorization(c.auth, c.crypto)
			assert.ErrorIs(t, err, c.want)
		})
	}
}

func TestKeys(t *testing.T) {
	_, pub := newKey(t)
	raw, err := DecodeKey(pub)
	require.NoError(t, err)
	// standard base64 with padding is accepted and canonicalised
	std := base64.StdEncoding.EncodeToString(raw)
	c, err := CanonicalKey(std)
	require.NoError(t, err)
	assert.Equal(t, pub, c)

	_, err = CanonicalKey("!!!")
	assert.ErrorIs(t, err, ErrBadKey)
	// a valid-length but off-curve point
	bad := make([]byte, 65)
	bad[0] = 4
	_, err = DecodeKey(base64.RawURLEncoding.EncodeToString(bad))
	assert.ErrorIs(t, err, ErrBadKey)
	_, err = ECDSAKey(bad)
	assert.ErrorIs(t, err, ErrBadKey)
	_, err = ECDSAKey(raw[:10])
	assert.ErrorIs(t, err, ErrBadKey)
	pk, err := ECDSAKey(raw)
	require.NoError(t, err)
	ek, _ := pk.ECDH()
	assert.Equal(t, raw, ek.Bytes())
	_ = ecdh.P256()
}
