package attest

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boson-chat/pushrelay/internal/apperr"
	"github.com/boson-chat/pushrelay/internal/db/memstore"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

const appID = "TEAMID1234.chat.boson.app"

func newAppAttest(t *testing.T) (*AppAttest, *fakeApple, *memstore.Store) {
	f := newFakeApple(t, appID)
	st := memstore.New()
	return &AppAttest{AppID: appID, Roots: f.roots, Keys: st, Now: func() time.Time { return testNow }}, f, st
}

func iosReq(platform string, d *device) Request {
	return Request{Platform: platform, App: "chat.boson.app", Token: "abcd", VAPID: "BVAPID", Install: "irc.example",
		Challenge: "c1", KeyID: d.KeyID()}
}

func code(err error) string {
	if e, ok := apperr.As(err); ok {
		return e.Code
	}
	return ""
}

func TestAppAttestRegisterThenAssert(t *testing.T) {
	a, f, st := newAppAttest(t)
	ctx := context.Background()
	d := f.newDevice()
	req := iosReq(repo.PlatformAPNs, d)
	h := req.ClientDataHash()

	// First use: attestation object (and an assertion in the same call).
	req.AttestationObject = f.attest(d, h, attestOpts{})
	req.Attestation = f.assert(d, h, 1, "")
	require.NoError(t, a.Verify(ctx, req, h))
	k, err := st.GetAppAttestKey(ctx, d.KeyID())
	require.NoError(t, err)
	assert.Equal(t, EnvProduction, k.Environment)
	assert.Equal(t, uint32(1), k.Counter)

	// Later: assertion only.
	req2 := iosReq(repo.PlatformAPNs, d)
	req2.Challenge = "c2"
	h2 := req2.ClientDataHash()
	req2.Attestation = f.assert(d, h2, 2, "")
	require.NoError(t, a.Verify(ctx, req2, h2))

	// Replay (same counter) fails.
	assert.Equal(t, "attestation_failed", code(a.Verify(ctx, req2, h2)))

	// Assertion over other request data fails.
	req3 := iosReq(repo.PlatformAPNs, d)
	req3.Attestation = f.assert(d, h2, 3, "")
	assert.Equal(t, "attestation_failed", code(a.Verify(ctx, req3, req3.ClientDataHash())))

	// Assertion for another app fails.
	req4 := iosReq(repo.PlatformAPNs, d)
	h4 := req4.ClientDataHash()
	req4.Attestation = f.assert(d, h4, 4, "OTHER.app")
	assert.Equal(t, "attestation_failed", code(a.Verify(ctx, req4, h4)))

	// Assertion signed by another key fails.
	other := f.newDevice()
	req5 := iosReq(repo.PlatformAPNs, d)
	h5 := req5.ClientDataHash()
	req5.Attestation = f.assert(other, h5, 5, "")
	assert.Equal(t, "attestation_failed", code(a.Verify(ctx, req5, h5)))
}

func TestAppAttestObjectOnly(t *testing.T) {
	a, f, _ := newAppAttest(t)
	d := f.newDevice()
	req := iosReq(repo.PlatformAPNs, d)
	h := req.ClientDataHash()
	req.AttestationObject = f.attest(d, h, attestOpts{})
	require.NoError(t, a.Verify(context.Background(), req, h))
}

func TestAppAttestUnknownKey(t *testing.T) {
	a, f, _ := newAppAttest(t)
	d := f.newDevice()
	req := iosReq(repo.PlatformAPNs, d)
	h := req.ClientDataHash()
	req.Attestation = f.assert(d, h, 1, "")
	assert.Equal(t, "attest_key_unknown", code(a.Verify(context.Background(), req, h)))

	req.Attestation = ""
	assert.Equal(t, "attestation_missing", code(a.Verify(context.Background(), req, h)))
}

func TestAppAttestDevelopmentEnvironment(t *testing.T) {
	a, f, _ := newAppAttest(t)
	ctx := context.Background()
	d := f.newDevice()

	// PUSHRELAY_APP_ATTEST_ENV=production: development keys never count.
	req0 := iosReq(repo.PlatformAPNsSandbox, d)
	h0 := req0.ClientDataHash()
	req0.AttestationObject = f.attest(d, h0, attestOpts{aaguid: aaguidDevelopment})
	assert.Equal(t, "attestation_failed", code(a.Verify(ctx, req0, h0)))
	a.AllowDevelopment = true

	// Development keys are refused for production APNs ...
	req := iosReq(repo.PlatformAPNs, d)
	h := req.ClientDataHash()
	req.AttestationObject = f.attest(d, h, attestOpts{aaguid: aaguidDevelopment})
	assert.Equal(t, "attestation_failed", code(a.Verify(ctx, req, h)))

	// ... and accepted for the sandbox.
	req = iosReq(repo.PlatformAPNsSandbox, d)
	h = req.ClientDataHash()
	req.AttestationObject = f.attest(d, h, attestOpts{aaguid: aaguidDevelopment})
	require.NoError(t, a.Verify(ctx, req, h))

	// A registered development key can't assert for production either.
	req = iosReq(repo.PlatformAPNs, d)
	h = req.ClientDataHash()
	req.Attestation = f.assert(d, h, 1, "")
	assert.Equal(t, "attestation_failed", code(a.Verify(ctx, req, h)))
}

func TestAppAttestBadAttestations(t *testing.T) {
	a, f, _ := newAppAttest(t)
	d := f.newDevice()
	other := f.newDevice()
	otherApple := newFakeApple(t, appID)
	base := iosReq(repo.PlatformAPNs, d)
	h := base.ClientDataHash()
	cases := map[string]string{
		"wrong nonce":         f.attest(d, h, attestOpts{nonce: make([]byte, 32)}),
		"other client data":   f.attest(d, []byte("something else"), attestOpts{}),
		"wrong app":           f.attest(d, h, attestOpts{appID: "OTHER.app"}),
		"nonzero counter":     f.attest(d, h, attestOpts{counter: 1}),
		"unknown aaguid":      f.attest(d, h, attestOpts{aaguid: []byte("0123456789abcdef")}),
		"cred id mismatch":    f.attest(d, h, attestOpts{credID: other.keyID}),
		"certified other key": f.attest(d, h, attestOpts{leafKey: other.key}),
		"wrong fmt":           f.attest(d, h, attestOpts{fmt: "packed"}),
		"no intermediate":     f.attest(d, h, attestOpts{dropInter: true}),
		"untrusted root":      otherApple.attest(d, h, attestOpts{}),
		"not cbor":            base64.StdEncoding.EncodeToString([]byte("nope")),
		"not base64":          "%%%",
	}
	for name, obj := range cases {
		t.Run(name, func(t *testing.T) {
			req := base
			req.AttestationObject = obj
			err := a.Verify(context.Background(), req, h)
			assert.Equal(t, "attestation_failed", code(err), "%v", err)
		})
	}
	t.Run("bad key id", func(t *testing.T) {
		req := base
		req.KeyID = "short"
		req.AttestationObject = f.attest(d, h, attestOpts{})
		assert.Equal(t, "attestation_failed", code(a.Verify(context.Background(), req, h)))
	})
	t.Run("assertion not base64 / not cbor", func(t *testing.T) {
		req := base
		req.AttestationObject = f.attest(d, h, attestOpts{})
		req.Attestation = "%%%"
		assert.Equal(t, "attestation_failed", code(a.Verify(context.Background(), req, h)))
		req.Attestation = base64.StdEncoding.EncodeToString([]byte{0xff})
		assert.Equal(t, "attestation_failed", code(a.Verify(context.Background(), req, h)))
	})
}

func TestAppAttestExpiredChain(t *testing.T) {
	a, f, _ := newAppAttest(t)
	a.Now = func() time.Time { return testNow.Add(10 * 365 * 24 * time.Hour) }
	d := f.newDevice()
	req := iosReq(repo.PlatformAPNs, d)
	h := req.ClientDataHash()
	req.AttestationObject = f.attest(d, h, attestOpts{})
	assert.Equal(t, "attestation_failed", code(a.Verify(context.Background(), req, h)))
}

func TestAppleRoots(t *testing.T) {
	pool, err := AppleRoots("")
	require.NoError(t, err)
	assert.NotNil(t, pool)

	dir := t.TempDir()
	_, err = AppleRoots(filepath.Join(dir, "missing.pem"))
	require.Error(t, err)
	bad := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not pem"), 0o600))
	_, err = AppleRoots(bad)
	require.Error(t, err)
	good := filepath.Join(dir, "good.pem")
	require.NoError(t, os.WriteFile(good, appleRootPEM, 0o600))
	_, err = AppleRoots(good)
	require.NoError(t, err)
}

func TestParseAuthDataShort(t *testing.T) {
	_, err := parseAuthData(make([]byte, 10), false)
	require.Error(t, err)
	_, err = parseAuthData(make([]byte, 40), true)
	require.Error(t, err)
	b := make([]byte, 37+18)
	b[37+16] = 0
	b[37+17] = 50
	_, err = parseAuthData(b, true)
	require.Error(t, err)
	assert.True(t, errors.Is(failed("x"), ErrFailed))
}
