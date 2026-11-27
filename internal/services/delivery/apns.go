package delivery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

// MaxAPNsPayload is APNs' limit for a regular push.
const MaxAPNsPayload = 4096

// APNs sends through the HTTP/2 provider API with token (.p8) auth.
type APNs struct {
	Key    *ecdsa.PrivateKey
	KeyID  string
	TeamID string
	// Topic is the app's bundle id.
	Topic string
	// Production and Sandbox base URLs (https://api.push.apple.com,
	// https://api.sandbox.push.apple.com).
	Production string
	Sandbox    string
	// FallbackBody is the visible alert if the service extension can't run.
	FallbackBody string
	// Client must speak HTTP/2 (net/http does over TLS).
	Client *http.Client
	Now    func() time.Time

	mu       sync.Mutex
	token    string
	tokenIat time.Time
}

// tokenLifetime: Apple wants provider tokens refreshed no more than once
// every 20 minutes and rejects ones older than an hour.
const tokenLifetime = 40 * time.Minute

// LoadAPNsKey reads an AuthKey_XXXX.p8 file (PKCS#8 EC key in PEM).
func LoadAPNsKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("apns key: %w", err)
	}
	return ParseAPNsKey(b)
}

// ParseAPNsKey parses a .p8 key.
func ParseAPNsKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("apns key: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apns key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apns key: not an EC key")
	}
	return ek, nil
}

func (a *APNs) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *APNs) providerToken(force bool) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if !force && a.token != "" && now.Sub(a.tokenIat) < tokenLifetime {
		return a.token, nil
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": a.TeamID, "iat": now.Unix()})
	t.Header["kid"] = a.KeyID
	s, err := t.SignedString(a.Key)
	if err != nil {
		return "", err
	}
	a.token, a.tokenIat = s, now
	return s, nil
}

type apnsPayload struct {
	APS   apnsAPS     `json:"aps"`
	Boson bosonFields `json:"boson"`
}

type apnsAPS struct {
	Alert          apnsAlert `json:"alert"`
	MutableContent int       `json:"mutable-content"`
	Sound          string    `json:"sound,omitempty"`
}

type apnsAlert struct {
	Body string `json:"body"`
}

// bosonFields is what the app decrypts (APNs: under "boson").
type bosonFields struct {
	V       int    `json:"v"`
	Mailbox string `json:"mailbox"`
	// Payload is the aes128gcm body, standard base64.
	Payload string `json:"payload"`
}

// BuildAPNsPayload is the JSON body sent to APNs.
func (a *APNs) BuildAPNsPayload(m Message) ([]byte, error) {
	b, err := json.Marshal(apnsPayload{
		APS:   apnsAPS{Alert: apnsAlert{Body: a.FallbackBody}, MutableContent: 1, Sound: "default"},
		Boson: bosonFields{V: PayloadVersion, Mailbox: m.MailboxID, Payload: base64.StdEncoding.EncodeToString(m.Body)},
	})
	if err != nil {
		return nil, err
	}
	if len(b) > MaxAPNsPayload {
		return nil, ErrPayloadTooLarge
	}
	return b, nil
}

// Send implements Sender.
func (a *APNs) Send(ctx context.Context, m Message) error {
	body, err := a.BuildAPNsPayload(m)
	if err != nil {
		return err
	}
	base := a.Production
	if m.Platform == repo.PlatformAPNsSandbox {
		base = a.Sandbox
	}
	err = a.post(ctx, base, m, body, false)
	var ue *UpstreamError
	if errors.As(err, &ue) && ue.Status == http.StatusForbidden &&
		(ue.Reason == "ExpiredProviderToken" || ue.Reason == "InvalidProviderToken") {
		err = a.post(ctx, base, m, body, true)
	}
	return err
}

func (a *APNs) post(ctx context.Context, base string, m Message, body []byte, refresh bool) error {
	tok, err := a.providerToken(refresh)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+url.PathEscape(m.Token), bytes.NewReader(body))
	if err != nil {
		return err
	}
	h := req.Header
	h.Set("authorization", "bearer "+tok)
	h.Set("apns-topic", a.Topic)
	h.Set("apns-push-type", "alert")
	h.Set("content-type", "application/json")
	if m.HighPriority() {
		h.Set("apns-priority", "10")
	} else {
		h.Set("apns-priority", "5")
	}
	// apns-expiration 0: deliver once, now, or drop.
	exp := int64(0)
	if m.TTL > 0 {
		exp = m.Now.Add(m.TTL).Unix()
	}
	h.Set("apns-expiration", strconv.FormatInt(exp, 10))
	if c := m.CollapseID(); c != "" {
		h.Set("apns-collapse-id", c)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return &UpstreamError{Service: "apns", Reason: transportReason(err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	var r struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&r)
	switch {
	case resp.StatusCode == http.StatusGone,
		resp.StatusCode == http.StatusBadRequest && (r.Reason == "BadDeviceToken" || r.Reason == "DeviceTokenNotForTopic"):
		return ErrUnregistered
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		return ErrPayloadTooLarge
	}
	return &UpstreamError{Service: "apns", Status: resp.StatusCode, Reason: r.Reason}
}
