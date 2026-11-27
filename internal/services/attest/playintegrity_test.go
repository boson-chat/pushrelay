package attest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

const pkg = "chat.boson.app"

var certDigest = sha256.Sum256([]byte("signing cert"))

// fakePlay answers decodeIntegrityToken with verdicts keyed by token.
func fakePlay(t *testing.T, verdicts map[string]any) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/"+pkg+":decodeIntegrityToken", r.URL.Path)
		var body struct {
			Token string `json:"integrity_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		v, ok := verdicts[body.Token]
		switch {
		case !ok:
			w.WriteHeader(http.StatusBadRequest)
		case v == "500":
			w.WriteHeader(http.StatusInternalServerError)
		case v == "junk":
			_, _ = w.Write([]byte("{"))
		default:
			_ = json.NewEncoder(w).Encode(v)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type verdictOpts struct {
	pkg, hash, nonce, app string
	device                []string
	ts                    time.Time
	cert                  []byte
}

func verdict(o verdictOpts) map[string]any {
	if o.pkg == "" {
		o.pkg = pkg
	}
	if o.app == "" {
		o.app = "PLAY_RECOGNIZED"
	}
	if o.device == nil {
		o.device = []string{"MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"}
	}
	if o.ts.IsZero() {
		o.ts = testNow.Add(-time.Minute)
	}
	if o.cert == nil {
		o.cert = certDigest[:]
	}
	return map[string]any{"tokenPayloadExternal": map[string]any{
		"requestDetails": map[string]any{
			"requestPackageName": o.pkg, "requestHash": o.hash, "nonce": o.nonce,
			"timestampMillis": strconv.FormatInt(o.ts.UnixMilli(), 10),
		},
		"appIntegrity": map[string]any{
			"appRecognitionVerdict": o.app, "packageName": o.pkg,
			"certificateSha256Digest": []string{base64.RawURLEncoding.EncodeToString(o.cert)},
		},
		"deviceIntegrity": map[string]any{"deviceRecognitionVerdict": o.device},
	}}
}

func TestPlayIntegrity(t *testing.T) {
	req := Request{Platform: repo.PlatformFCM, App: pkg, Token: "fcm:tok", VAPID: "BV", Install: "irc.example", Challenge: "c"}
	h := req.ClientDataHash()
	want := base64.RawURLEncoding.EncodeToString(h)
	srv := fakePlay(t, map[string]any{
		"good":         verdict(verdictOpts{hash: want}),
		"good-nonce":   verdict(verdictOpts{nonce: want + "="}),
		"strong":       verdict(verdictOpts{hash: want, device: []string{"MEETS_STRONG_INTEGRITY"}}),
		"wrong-hash":   verdict(verdictOpts{hash: "nope"}),
		"wrong-pkg":    verdict(verdictOpts{hash: want, pkg: "evil.app"}),
		"old":          verdict(verdictOpts{hash: want, ts: testNow.Add(-time.Hour)}),
		"unrecognized": verdict(verdictOpts{hash: want, app: "UNRECOGNIZED_VERSION"}),
		"no-device":    verdict(verdictOpts{hash: want, device: []string{"MEETS_BASIC_INTEGRITY"}}),
		"wrong-cert":   verdict(verdictOpts{hash: want, cert: make([]byte, 32)}),
		"no-ts": map[string]any{"tokenPayloadExternal": map[string]any{"requestDetails": map[string]any{
			"requestPackageName": pkg, "requestHash": want}, "appIntegrity": map[string]any{"packageName": pkg}}},
		"down": "500",
		"junk": "junk",
	})
	p := &PlayIntegrity{
		Package: pkg, CertDigests: [][]byte{certDigest[:]}, Endpoint: srv.URL, Client: srv.Client(),
		MaxAge: 10 * time.Minute, Now: func() time.Time { return testNow },
	}
	ctx := context.Background()
	for tok, wantCode := range map[string]string{
		"good": "", "good-nonce": "", "strong": "",
		"wrong-hash": "attestation_failed", "wrong-pkg": "attestation_failed", "old": "attestation_failed",
		"unrecognized": "attestation_failed", "no-device": "attestation_failed", "wrong-cert": "attestation_failed",
		"no-ts": "attestation_failed", "unknown-token": "attestation_failed",
		"down": "attestation_upstream", "junk": "attestation_upstream",
	} {
		t.Run(tok, func(t *testing.T) {
			r := req
			r.Attestation = tok
			err := p.Verify(ctx, r, h)
			if wantCode == "" {
				require.NoError(t, err)
			} else {
				assert.Equal(t, wantCode, code(err), "%v", err)
			}
		})
	}

	// Without configured digests the certificate isn't checked.
	p.CertDigests = nil
	r := req
	r.Attestation = "wrong-cert"
	require.NoError(t, p.Verify(ctx, r, h))

	// Unreachable service.
	srv.Close()
	r.Attestation = "good"
	assert.Equal(t, "attestation_upstream", code(p.Verify(ctx, r, h)))
}

func TestParseCertDigests(t *testing.T) {
	hexd := hex.EncodeToString(certDigest[:])
	colon := ""
	for i := 0; i < len(hexd); i += 2 {
		if i > 0 {
			colon += ":"
		}
		colon += hexd[i : i+2]
	}
	out, err := ParseCertDigests([]string{hexd, colon, base64.RawURLEncoding.EncodeToString(certDigest[:])})
	require.NoError(t, err)
	require.Len(t, out, 3)
	for _, d := range out {
		assert.Equal(t, certDigest[:], d)
	}
	_, err = ParseCertDigests([]string{"abc"})
	require.Error(t, err)
}
