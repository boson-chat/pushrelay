package delivery_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boson-chat/pushrelay/internal/googleauth"
	"github.com/boson-chat/pushrelay/internal/googleauth/googleauthtest"
	"github.com/boson-chat/pushrelay/internal/services/delivery"
	"github.com/boson-chat/pushrelay/internal/services/delivery/deliverytest"
)

var t0 = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

func p8(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newAPNs(t *testing.T) (*delivery.APNs, *deliverytest.Fake, *deliverytest.Fake, *time.Time) {
	k, _ := p8(t)
	prod, sandbox := deliverytest.NewAPNs(t), deliverytest.NewAPNs(t)
	now := t0
	return &delivery.APNs{
		Key: k, KeyID: "KEYID12345", TeamID: "TEAMID1234", Topic: "chat.boson.app",
		Production: prod.URL, Sandbox: sandbox.URL, FallbackBody: "New message",
		Client: prod.Client(), Now: func() time.Time { return now },
	}, prod, sandbox, &now
}

func msg(platform string) delivery.Message {
	return delivery.Message{MailboxID: "mbx1", Platform: platform, Token: "abcdef0123", Body: []byte("ciphertext"),
		TTL: time.Hour, Urgency: "normal", Now: t0}
}

func TestAPNsSend(t *testing.T) {
	a, prod, sandbox, now := newAPNs(t)
	ctx := context.Background()
	m := msg("apns")
	m.Topic = "chan1"
	require.NoError(t, a.Send(ctx, m))
	reqs := prod.Requests()
	require.Len(t, reqs, 1)
	r := reqs[0]
	assert.Equal(t, "HTTP/2.0", r.Proto)
	assert.Equal(t, "/3/device/abcdef0123", r.Path)
	assert.Equal(t, "chat.boson.app", r.Header.Get("apns-topic"))
	assert.Equal(t, "alert", r.Header.Get("apns-push-type"))
	assert.Equal(t, "10", r.Header.Get("apns-priority"))
	assert.Equal(t, "1795784400", r.Header.Get("apns-expiration"))
	assert.Equal(t, m.CollapseID(), r.Header.Get("apns-collapse-id"))
	assert.True(t, strings.HasPrefix(m.CollapseID(), "mbx1."))
	assert.LessOrEqual(t, len(m.CollapseID()), 64)

	// Provider token: ES256, kid, iss, iat.
	tok := strings.TrimPrefix(r.Header.Get("authorization"), "bearer ")
	parsed, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return &a.Key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithTimeFunc(func() time.Time { return t0 }))
	require.NoError(t, err)
	assert.Equal(t, "KEYID12345", parsed.Header["kid"])
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "TEAMID1234", claims["iss"])
	assert.EqualValues(t, t0.Unix(), claims["iat"])

	var body struct {
		APS struct {
			Alert          map[string]string `json:"alert"`
			MutableContent int               `json:"mutable-content"`
		} `json:"aps"`
		Boson struct {
			V       int    `json:"v"`
			Mailbox string `json:"mailbox"`
			Payload string `json:"payload"`
		} `json:"boson"`
	}
	require.NoError(t, json.Unmarshal(r.Body, &body))
	assert.Equal(t, "New message", body.APS.Alert["body"])
	assert.Equal(t, 1, body.APS.MutableContent)
	assert.Equal(t, 1, body.Boson.V)
	assert.Equal(t, "mbx1", body.Boson.Mailbox)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("ciphertext")), body.Boson.Payload)

	// Low urgency, TTL 0, no topic, sandbox; token reused within its lifetime.
	m = msg("apns-sandbox")
	m.Urgency, m.TTL = "low", 0
	require.NoError(t, a.Send(ctx, m))
	sr := sandbox.Requests()
	require.Len(t, sr, 1)
	assert.Equal(t, "5", sr[0].Header.Get("apns-priority"))
	assert.Equal(t, "0", sr[0].Header.Get("apns-expiration"))
	assert.Empty(t, sr[0].Header.Get("apns-collapse-id"))
	assert.Equal(t, r.Header.Get("authorization"), sr[0].Header.Get("authorization"))

	// After 40 minutes a fresh provider token.
	*now = now.Add(41 * time.Minute)
	require.NoError(t, a.Send(ctx, msg("apns")))
	reqs = prod.Requests()
	assert.NotEqual(t, reqs[0].Header.Get("authorization"), reqs[1].Header.Get("authorization"))
}

func TestAPNsErrors(t *testing.T) {
	a, prod, _, _ := newAPNs(t)
	ctx := context.Background()
	cases := []struct {
		resp deliverytest.Response
		want error
		code int
	}{
		{deliverytest.APNsReason(http.StatusGone, "Unregistered"), delivery.ErrUnregistered, 0},
		{deliverytest.APNsReason(http.StatusBadRequest, "BadDeviceToken"), delivery.ErrUnregistered, 0},
		{deliverytest.APNsReason(http.StatusBadRequest, "DeviceTokenNotForTopic"), delivery.ErrUnregistered, 0},
		{deliverytest.APNsReason(http.StatusRequestEntityTooLarge, "PayloadTooLarge"), delivery.ErrPayloadTooLarge, 0},
		{deliverytest.APNsReason(http.StatusTooManyRequests, "TooManyRequests"), nil, 429},
		{deliverytest.APNsReason(http.StatusInternalServerError, "InternalServerError"), nil, 500},
		{deliverytest.APNsReason(http.StatusBadRequest, "BadTopic"), nil, 400},
	}
	for _, c := range cases {
		prod.SetRespond(func(deliverytest.Request) deliverytest.Response { return c.resp })
		err := a.Send(ctx, msg("apns"))
		if c.want != nil {
			assert.ErrorIs(t, err, c.want, c.resp.Body)
			continue
		}
		var ue *delivery.UpstreamError
		require.True(t, errors.As(err, &ue), "%v", err)
		assert.Equal(t, c.code, ue.Status)
		assert.Equal(t, "apns", ue.Service)
	}
}

func TestAPNsRefreshesExpiredProviderToken(t *testing.T) {
	a, prod, _, _ := newAPNs(t)
	calls := 0
	prod.SetRespond(func(deliverytest.Request) deliverytest.Response {
		calls++
		if calls == 1 {
			return deliverytest.APNsReason(http.StatusForbidden, "ExpiredProviderToken")
		}
		return deliverytest.Response{Status: 200}
	})
	require.NoError(t, a.Send(context.Background(), msg("apns")))
	assert.Equal(t, 2, calls)
}

func TestAPNsTooLargeAndTransport(t *testing.T) {
	a, prod, _, _ := newAPNs(t)
	m := msg("apns")
	m.Body = make([]byte, 3500) // base64 → 4668 bytes
	assert.ErrorIs(t, a.Send(context.Background(), m), delivery.ErrPayloadTooLarge)
	assert.Empty(t, prod.Requests())

	prod.Close()
	err := a.Send(context.Background(), msg("apns"))
	var ue *delivery.UpstreamError
	require.True(t, errors.As(err, &ue))
	assert.NotContains(t, ue.Error(), "abcdef0123", "no device token in errors")
}

func TestLoadAPNsKey(t *testing.T) {
	_, pemKey := p8(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "AuthKey.p8")
	require.NoError(t, os.WriteFile(path, pemKey, 0o600))
	k, err := delivery.LoadAPNsKey(path)
	require.NoError(t, err)
	assert.NotNil(t, k)

	_, err = delivery.LoadAPNsKey(filepath.Join(dir, "missing"))
	require.Error(t, err)
	_, err = delivery.ParseAPNsKey([]byte("nope"))
	require.Error(t, err)
	_, err = delivery.ParseAPNsKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}))
	require.Error(t, err)
}

func newFCM(t *testing.T) (*delivery.FCM, *deliverytest.Fake) {
	ts := googleauthtest.New(t)
	creds, err := googleauth.Parse(context.Background(), ts.KeyFile(t, "boson-test"), googleauth.Options{})
	require.NoError(t, err)
	f := deliverytest.NewFCM(t)
	return &delivery.FCM{ProjectID: creds.ProjectID, Endpoint: f.URL, Client: creds.Client(f.Client())}, f
}

func TestFCMSend(t *testing.T) {
	s, f := newFCM(t)
	m := msg("fcm")
	m.Topic = "t"
	require.NoError(t, s.Send(context.Background(), m))
	reqs := f.Requests()
	require.Len(t, reqs, 1)
	r := reqs[0]
	assert.Equal(t, "/v1/projects/boson-test/messages:send", r.Path)
	assert.Equal(t, "Bearer "+googleauthtest.AccessToken, r.Header.Get("Authorization"))
	var body struct {
		Message struct {
			Token        string            `json:"token"`
			Data         map[string]string `json:"data"`
			Notification any               `json:"notification"`
			Android      map[string]string `json:"android"`
		} `json:"message"`
	}
	require.NoError(t, json.Unmarshal(r.Body, &body))
	assert.Equal(t, "abcdef0123", body.Message.Token)
	assert.Nil(t, body.Message.Notification, "data-only")
	assert.Equal(t, map[string]string{"v": "1", "mailbox": "mbx1", "payload": base64.StdEncoding.EncodeToString([]byte("ciphertext"))}, body.Message.Data)
	assert.Equal(t, "HIGH", body.Message.Android["priority"])
	assert.Equal(t, "3600s", body.Message.Android["ttl"])
	assert.Equal(t, m.CollapseID(), body.Message.Android["collapse_key"])

	m = msg("fcm")
	m.Urgency = "very-low"
	require.NoError(t, s.Send(context.Background(), m))
	require.NoError(t, json.Unmarshal(f.Requests()[1].Body, &body))
	assert.Equal(t, "NORMAL", body.Message.Android["priority"])
}

func TestFCMErrors(t *testing.T) {
	s, f := newFCM(t)
	ctx := context.Background()
	for _, c := range []struct {
		resp deliverytest.Response
		want error
		code int
	}{
		{deliverytest.FCMError(404, "NOT_FOUND", "UNREGISTERED"), delivery.ErrUnregistered, 0},
		{deliverytest.FCMError(403, "PERMISSION_DENIED", "SENDER_ID_MISMATCH"), delivery.ErrUnregistered, 0},
		{deliverytest.Response{Status: 404, Body: `{"error":{"status":"NOT_FOUND"}}`}, delivery.ErrUnregistered, 0},
		{deliverytest.FCMError(429, "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED"), nil, 429},
		{deliverytest.FCMError(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT"), nil, 400},
		{deliverytest.Response{Status: 503, Body: "busy"}, nil, 503},
	} {
		f.SetRespond(func(deliverytest.Request) deliverytest.Response { return c.resp })
		err := s.Send(ctx, msg("fcm"))
		if c.want != nil {
			assert.ErrorIs(t, err, c.want)
			continue
		}
		var ue *delivery.UpstreamError
		require.True(t, errors.As(err, &ue), "%v", err)
		assert.Equal(t, c.code, ue.Status)
	}

	m := msg("fcm")
	m.Body = make([]byte, 3500)
	assert.ErrorIs(t, s.Send(ctx, m), delivery.ErrPayloadTooLarge)

	f.Close()
	var ue *delivery.UpstreamError
	require.True(t, errors.As(s.Send(ctx, msg("fcm")), &ue))
}

type recordSender struct{ got []delivery.Message }

func (r *recordSender) Send(_ context.Context, m delivery.Message) error {
	r.got = append(r.got, m)
	return nil
}

func TestRouter(t *testing.T) {
	a, f := &recordSender{}, &recordSender{}
	r := delivery.Router{APNs: a, FCM: f}
	ctx := context.Background()
	require.NoError(t, r.Send(ctx, msg("apns")))
	require.NoError(t, r.Send(ctx, msg("apns-sandbox")))
	require.NoError(t, r.Send(ctx, msg("fcm")))
	assert.Len(t, a.got, 2)
	assert.Len(t, f.got, 1)
	assert.ErrorIs(t, r.Send(ctx, msg("web")), delivery.ErrPlatformUnavailable)
	assert.True(t, r.Available("apns") && r.Available("apns-sandbox") && r.Available("fcm"))
	assert.False(t, r.Available("web"))
	assert.False(t, delivery.Router{}.Available("fcm"))
	assert.ErrorIs(t, delivery.Router{}.Send(ctx, msg("fcm")), delivery.ErrPlatformUnavailable)
	assert.Equal(t, "fcm", delivery.ServiceName("fcm"))
	assert.Equal(t, "apns", delivery.ServiceName("apns-sandbox"))
	assert.Empty(t, msg("fcm").CollapseID())
}
