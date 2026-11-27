package attest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PlayIntegrity decodes a Play Integrity token server-side
// (playintegrity.googleapis.com decodeIntegrityToken) and checks the verdict.
//
// The app requests the token with requestHash (standard requests) or nonce
// (classic requests) set to base64url(SHA-256(ClientData)), no padding.
type PlayIntegrity struct {
	Package string
	// CertDigests are allowed SHA-256 digests of the app signing
	// certificate. Empty: not checked.
	CertDigests [][]byte
	// Endpoint is https://playintegrity.googleapis.com (overridable for tests).
	Endpoint string
	// Client carries the service account's OAuth2 bearer token.
	Client *http.Client
	MaxAge time.Duration
	Now    func() time.Time
}

// ParseCertDigests reads hex or base64(url) SHA-256 digests.
func ParseCertDigests(list []string) ([][]byte, error) {
	var out [][]byte
	for _, s := range list {
		clean := strings.ReplaceAll(s, ":", "")
		if b, err := hex.DecodeString(clean); err == nil && len(b) == 32 {
			out = append(out, b)
			continue
		}
		if b, err := decodeB64(s); err == nil && len(b) == 32 {
			out = append(out, b)
			continue
		}
		return nil, fmt.Errorf("PUSHRELAY_PLAY_INTEGRITY_CERT_DIGESTS: %q is not a SHA-256 digest", s)
	}
	return out, nil
}

type integrityPayload struct {
	TokenPayloadExternal struct {
		RequestDetails struct {
			RequestPackageName string `json:"requestPackageName"`
			Nonce              string `json:"nonce"`
			RequestHash        string `json:"requestHash"`
			TimestampMillis    string `json:"timestampMillis"`
		} `json:"requestDetails"`
		AppIntegrity struct {
			AppRecognitionVerdict   string   `json:"appRecognitionVerdict"`
			PackageName             string   `json:"packageName"`
			CertificateSha256Digest []string `json:"certificateSha256Digest"`
		} `json:"appIntegrity"`
		DeviceIntegrity struct {
			DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
		} `json:"deviceIntegrity"`
	} `json:"tokenPayloadExternal"`
}

func (p *PlayIntegrity) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Verify decodes req.Attestation and checks package, request binding,
// freshness, Play recognition, signing certificate and device integrity.
func (p *PlayIntegrity) Verify(ctx context.Context, req Request, clientDataHash []byte) error {
	body, _ := json.Marshal(map[string]string{"integrity_token": req.Attestation})
	u := strings.TrimRight(p.Endpoint, "/") + "/v1/" + url.PathEscape(p.Package) + ":decodeIntegrityToken"
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := p.Client.Do(hreq)
	if err != nil {
		return &wrapped{public: ErrUpstream, detail: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusBadRequest:
		return failed("play integrity rejected the token")
	case resp.StatusCode != http.StatusOK:
		return &wrapped{public: ErrUpstream, detail: "play integrity: " + resp.Status}
	}
	var pl integrityPayload
	if err := json.Unmarshal(raw, &pl); err != nil {
		return &wrapped{public: ErrUpstream, detail: "play integrity: bad JSON"}
	}
	t := pl.TokenPayloadExternal
	if t.RequestDetails.RequestPackageName != p.Package || t.AppIntegrity.PackageName != p.Package {
		return failed("package %q / %q", t.RequestDetails.RequestPackageName, t.AppIntegrity.PackageName)
	}
	want := base64.RawURLEncoding.EncodeToString(clientDataHash)
	if strings.TrimRight(t.RequestDetails.RequestHash, "=") != want && strings.TrimRight(t.RequestDetails.Nonce, "=") != want {
		return failed("request hash does not bind this request")
	}
	ms, err := strconv.ParseInt(t.RequestDetails.TimestampMillis, 10, 64)
	if err != nil {
		return failed("no timestamp")
	}
	if age := p.now().Sub(time.UnixMilli(ms)); age > p.MaxAge || age < -time.Minute {
		return failed("verdict is %s old", age.Round(time.Second))
	}
	if t.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		return failed("app verdict %q", t.AppIntegrity.AppRecognitionVerdict)
	}
	if len(p.CertDigests) > 0 && !certMatches(t.AppIntegrity.CertificateSha256Digest, p.CertDigests) {
		return failed("signing certificate not allowed")
	}
	device := false
	for _, v := range t.DeviceIntegrity.DeviceRecognitionVerdict {
		device = device || v == "MEETS_DEVICE_INTEGRITY" || v == "MEETS_STRONG_INTEGRITY"
	}
	if !device {
		return failed("device verdict %v", t.DeviceIntegrity.DeviceRecognitionVerdict)
	}
	return nil
}

func certMatches(got []string, allowed [][]byte) bool {
	for _, g := range got {
		b, err := decodeB64(g)
		if err != nil {
			continue
		}
		for _, a := range allowed {
			if bytes.Equal(a, b) {
				return true
			}
		}
	}
	return false
}
