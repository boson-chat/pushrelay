// Package webpush holds the Web Push pieces the relay checks: VAPID
// (RFC 8292) Authorization headers and P-256 application server keys.
package webpush

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Errors from VerifyVAPID. All of them mean 401 to the push sender, except
// ErrKeyMismatch which callers may treat the same way.
var (
	ErrNoAuth       = errors.New("vapid: missing Authorization")
	ErrMalformed    = errors.New("vapid: malformed Authorization")
	ErrBadKey       = errors.New("vapid: k is not a P-256 public key")
	ErrKeyMismatch  = errors.New("vapid: k is not the mailbox's key")
	ErrBadSignature = errors.New("vapid: JWT does not verify")
	ErrAudience     = errors.New("vapid: aud is not this relay")
	ErrExpired      = errors.New("vapid: JWT expired")
	ErrExpTooFar    = errors.New("vapid: exp is more than 24h ahead")
)

// DecodeKey parses a base64url (padding optional; standard base64 also
// accepted) uncompressed P-256 point, as browsers and Ergo's ISUPPORT VAPID=
// publish it.
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrBadKey
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, ErrBadKey
	}
	return raw, nil
}

// CanonicalKey returns the canonical (base64url, no padding) form of a
// VAPID public key.
func CanonicalKey(s string) (string, error) {
	raw, err := DecodeKey(s)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ECDSAKey turns an uncompressed P-256 point into an ECDSA public key.
func ECDSAKey(raw []byte) (*ecdsa.PublicKey, error) {
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, ErrBadKey
	}
	return k, nil
}

// Auth is a parsed VAPID credential.
type Auth struct {
	Token string
	// Key as sent (k=), canonical base64url.
	Key string
}

// ParseAuthorization reads RFC 8292 `Authorization: vapid t=<JWT>, k=<key>`.
// The older draft form `Authorization: WebPush <JWT>` with
// `Crypto-Key: p256ecdsa=<key>` is accepted too.
func ParseAuthorization(authorization, cryptoKey string) (Auth, error) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return Auth{}, ErrNoAuth
	}
	scheme, rest, _ := strings.Cut(authorization, " ")
	var a Auth
	switch strings.ToLower(scheme) {
	case "vapid":
		for _, part := range strings.Split(rest, ",") {
			k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				return Auth{}, ErrMalformed
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "t":
				a.Token = strings.TrimSpace(v)
			case "k":
				a.Key = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	case "webpush":
		a.Token = strings.TrimSpace(rest)
		for _, part := range strings.Split(cryptoKey, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(k, "p256ecdsa") {
				a.Key = strings.Trim(v, `"`)
			}
		}
	default:
		return Auth{}, ErrMalformed
	}
	if a.Token == "" || a.Key == "" {
		return Auth{}, ErrMalformed
	}
	canon, err := CanonicalKey(a.Key)
	if err != nil {
		return Auth{}, err
	}
	a.Key = canon
	return a, nil
}

// Verifier checks VAPID credentials against a mailbox's bound key.
type Verifier struct {
	// Origin is the relay origin (scheme://host) aud must equal.
	Origin string
	// MaxExp bounds how far ahead exp may be (24h).
	MaxExp time.Duration
	// Leeway for clock skew on exp (past) and the MaxExp bound.
	Leeway time.Duration
	Now    func() time.Time
}

// Verify checks a = mailbox key boundKey (canonical base64url), the JWT
// signature (ES256), aud and exp. It returns the JWT sub claim.
func (v Verifier) Verify(a Auth, boundKey string) (string, error) {
	if a.Key != boundKey {
		return "", ErrKeyMismatch
	}
	raw, err := DecodeKey(a.Key)
	if err != nil {
		return "", err
	}
	pub, err := ECDSAKey(raw)
	if err != nil {
		return "", err
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	claims := jwt.MapClaims{}
	_, err = jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithTimeFunc(now),
		jwt.WithLeeway(v.Leeway),
		jwt.WithExpirationRequired(),
	).ParseWithClaims(a.Token, claims, func(*jwt.Token) (any, error) { return pub, nil })
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "", ErrExpired
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing), errors.Is(err, jwt.ErrTokenMalformed):
		return "", ErrMalformed
	case err != nil:
		return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if !audienceMatches(claims, v.Origin) {
		return "", ErrAudience
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return "", ErrMalformed
	}
	if exp.After(now().Add(v.MaxExp + v.Leeway)) {
		return "", ErrExpTooFar
	}
	sub, _ := claims["sub"].(string)
	return sub, nil
}

func audienceMatches(claims jwt.MapClaims, origin string) bool {
	aud, err := claims.GetAudience()
	if err != nil {
		return false
	}
	origin = strings.TrimRight(origin, "/")
	for _, a := range aud {
		if strings.EqualFold(strings.TrimRight(a, "/"), origin) {
			return true
		}
	}
	return false
}
