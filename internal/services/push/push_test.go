package push_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boson-chat/pushrelay/internal/apperr"
	"github.com/boson-chat/pushrelay/internal/db/memstore"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
	"github.com/boson-chat/pushrelay/internal/services/alert"
	"github.com/boson-chat/pushrelay/internal/services/delivery"
	"github.com/boson-chat/pushrelay/internal/services/push"
	"github.com/boson-chat/pushrelay/internal/services/ratelimit"
	"github.com/boson-chat/pushrelay/internal/webpush"
	"github.com/boson-chat/pushrelay/metrics"
)

const origin = "https://push.example"

var t0 = time.Date(2026, 11, 27, 12, 30, 0, 0, time.UTC)

type sender struct {
	err error
	got []delivery.Message
}

func (s *sender) Send(_ context.Context, m delivery.Message) error {
	s.got = append(s.got, m)
	return s.err
}

type alerts struct{ got []alert.Alert }

func (a *alerts) Alert(_ context.Context, al alert.Alert) { a.got = append(a.got, al) }

type env struct {
	svc     *push.Service
	store   *memstore.Store
	sender  *sender
	alerts  *alerts
	metrics *metrics.Metrics
	now     *time.Time
	key     *ecdsa.PrivateKey
	pub     string
}

func newEnv(t *testing.T, installHourly, daily int) *env {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ek, _ := k.PublicKey.ECDH()
	now := t0
	e := &env{store: memstore.New(), sender: &sender{}, alerts: &alerts{}, metrics: metrics.New(), now: &now,
		key: k, pub: base64.RawURLEncoding.EncodeToString(ek.Bytes())}
	clock := func() time.Time { return *e.now }
	e.svc = push.New(push.Deps{
		Store: e.store, Sender: e.sender, Metrics: e.metrics, Alerter: e.alerts, Now: clock,
		VAPID:      webpush.Verifier{Origin: origin, MaxExp: 24 * time.Hour, Leeway: time.Minute, Now: clock},
		PerMailbox: ratelimit.NewBuckets(10, 6*time.Second, clock), MailboxEvery: 6 * time.Second,
		PerInstall: ratelimit.NewWindow(installHourly, time.Hour, clock), MailboxDaily: daily,
		MaxPayloadBytes: 4096, DefaultTTL: 24 * time.Hour, MaxTTL: 28 * 24 * time.Hour, Timeout: time.Second,
	})
	return e
}

func (e *env) addMailbox(t *testing.T, id, install string) {
	_, err := e.store.CreateMailbox(context.Background(), &repo.Mailbox{
		ID: id, Platform: "apns", Token: "tok-" + id, VAPIDKey: e.pub, Install: install,
		CreatedAt: t0, UpdatedAt: t0, LastUsedAt: t0,
	})
	require.NoError(t, err)
}

func (e *env) auth(t *testing.T, claims jwt.MapClaims) string {
	if claims == nil {
		claims = jwt.MapClaims{"aud": origin, "exp": e.now.Add(12 * time.Hour).Unix(), "sub": "mailto:ops@irc.example"}
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(e.key)
	require.NoError(t, err)
	return "vapid t=" + tok + ", k=" + e.pub
}

func (e *env) in(t *testing.T, id string) push.Input {
	return push.Input{MailboxID: id, Authorization: e.auth(t, nil), ContentEncoding: "aes128gcm", TTL: "604800",
		Urgency: "high", Body: []byte("encrypted-bytes")}
}

func code(err error) string {
	if e, ok := apperr.As(err); ok {
		return e.Code
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func TestAcceptForwards(t *testing.T) {
	e := newEnv(t, 100, 300)
	e.addMailbox(t, "m1", "irc.example")
	in := e.in(t, "m1")
	in.Topic = "chan-abc"
	res, err := e.svc.Accept(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, 604800*time.Second, res.TTL)
	assert.Len(t, res.MessageID, 16)
	require.Len(t, e.sender.got, 1)
	m := e.sender.got[0]
	assert.Equal(t, "m1", m.MailboxID)
	assert.Equal(t, "tok-m1", m.Token)
	assert.Equal(t, []byte("encrypted-bytes"), m.Body)
	assert.Equal(t, "high", m.Urgency)
	assert.Equal(t, "chan-abc", m.Topic)
	assert.Equal(t, 1.0, testutil.ToFloat64(e.metrics.PushCount("accepted")))

	// Defaults and caps: no TTL → default; huge TTL → max; no urgency → normal.
	in = e.in(t, "m1")
	in.TTL, in.Urgency = "", ""
	res, err = e.svc.Accept(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, res.TTL)
	assert.Equal(t, "normal", e.sender.got[1].Urgency)
	in = e.in(t, "m1")
	in.TTL = "999999999"
	res, err = e.svc.Accept(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, 28*24*time.Hour, res.TTL)

	m1, _ := e.store.GetMailbox(context.Background(), "m1")
	assert.Equal(t, 3, m1.PushDayCount)
}

func TestAcceptRejects(t *testing.T) {
	e := newEnv(t, 100, 300)
	e.addMailbox(t, "m1", "irc.example")
	e.addMailbox(t, "paused", "irc.example")
	require.NoError(t, e.store.SetMailboxPaused(context.Background(), "paused", true))
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ek, _ := other.PublicKey.ECDH()
	otherPub := base64.RawURLEncoding.EncodeToString(ek.Bytes())
	otherTok, _ := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"aud": origin, "exp": t0.Add(time.Hour).Unix()}).SignedString(other)

	cases := map[string]struct {
		mod    func(*push.Input)
		code   string
		status int
	}{
		"unknown mailbox": {func(i *push.Input) { i.MailboxID = "nope" }, "mailbox_not_found", 404},
		"paused":          {func(i *push.Input) { i.MailboxID = "paused" }, "install_blocked", 403},
		"no auth":         {func(i *push.Input) { i.Authorization = "" }, "vapid_invalid", 401},
		"other install's key": {func(i *push.Input) { i.Authorization = "vapid t=" + otherTok + ", k=" + otherPub },
			"vapid_invalid", 401},
		"expired": {func(i *push.Input) {
			i.Authorization = e.auth(t, jwt.MapClaims{"aud": origin, "exp": t0.Add(-2 * time.Minute).Unix()})
		}, "vapid_invalid", 401},
		"wrong aud": {func(i *push.Input) {
			i.Authorization = e.auth(t, jwt.MapClaims{"aud": "https://fcm.googleapis.com", "exp": t0.Add(time.Hour).Unix()})
		}, "vapid_invalid", 401},
		"exp > 24h": {func(i *push.Input) {
			i.Authorization = e.auth(t, jwt.MapClaims{"aud": origin, "exp": t0.Add(48 * time.Hour).Unix()})
		}, "vapid_invalid", 401},
		"too large":      {func(i *push.Input) { i.Body = make([]byte, 4097) }, "payload_too_large", 413},
		"too large flag": {func(i *push.Input) { i.BodyTooLarge = true }, "payload_too_large", 413},
		"aesgcm":         {func(i *push.Input) { i.ContentEncoding = "aesgcm" }, "unsupported_encoding", 415},
		"empty":          {func(i *push.Input) { i.Body = nil }, "empty_body", 400},
		"bad ttl":        {func(i *push.Input) { i.TTL = "-1" }, "invalid_ttl", 400},
		"bad ttl text":   {func(i *push.Input) { i.TTL = "soon" }, "invalid_ttl", 400},
		"bad urgency":    {func(i *push.Input) { i.Urgency = "urgent" }, "invalid_urgency", 400},
		"bad topic":      {func(i *push.Input) { i.Topic = "has space" }, "invalid_topic", 400},
		"long topic":     {func(i *push.Input) { i.Topic = strings.Repeat("a", 33) }, "invalid_topic", 400},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := e.in(t, "m1")
			c.mod(&in)
			_, err := e.svc.Accept(context.Background(), in)
			assert.Equal(t, c.code, code(err))
			ae, ok := apperr.As(err)
			require.True(t, ok)
			assert.Equal(t, c.status, ae.Status)
		})
	}
	assert.Empty(t, e.sender.got)
}

func TestMailboxRateLimit(t *testing.T) {
	e := newEnv(t, 1000, 300)
	e.addMailbox(t, "m1", "irc.example")
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		_, err := e.svc.Accept(ctx, e.in(t, "m1"))
		require.NoError(t, err, "burst %d", i)
	}
	_, err := e.svc.Accept(ctx, e.in(t, "m1"))
	assert.Equal(t, "rate_limited", code(err))
	ae, _ := apperr.As(err)
	assert.Equal(t, 6*time.Second, ae.RetryAfter)
	*e.now = e.now.Add(6 * time.Second)
	_, err = e.svc.Accept(ctx, e.in(t, "m1"))
	require.NoError(t, err)
	_, err = e.svc.Accept(ctx, e.in(t, "m1"))
	assert.Equal(t, "rate_limited", code(err))
}

func TestDailyLimit(t *testing.T) {
	e := newEnv(t, 1000, 3)
	e.addMailbox(t, "m1", "irc.example")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err := e.svc.Accept(ctx, e.in(t, "m1"))
		require.NoError(t, err)
	}
	_, err := e.svc.Accept(ctx, e.in(t, "m1"))
	assert.Equal(t, "daily_limit", code(err))
	ae, _ := apperr.As(err)
	assert.Equal(t, 11*time.Hour+30*time.Minute+time.Second, ae.RetryAfter)
	// Next UTC day.
	*e.now = time.Date(2026, 11, 28, 0, 0, 1, 0, time.UTC)
	_, err = e.svc.Accept(ctx, e.in(t, "m1"))
	require.NoError(t, err)
}

func TestInstallCeilingAndAlert(t *testing.T) {
	e := newEnv(t, 3, 300)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		e.addMailbox(t, "m"+string(rune('a'+i)), "busy.example")
	}
	e.addMailbox(t, "quiet", "quiet.example")
	for i := 0; i < 3; i++ {
		_, err := e.svc.Accept(ctx, e.in(t, "m"+string(rune('a'+i))))
		require.NoError(t, err)
	}
	_, err := e.svc.Accept(ctx, e.in(t, "md"))
	assert.Equal(t, "install_rate_limited", code(err))
	ae, _ := apperr.As(err)
	assert.Equal(t, 30*time.Minute+time.Second, ae.RetryAfter)
	_, err = e.svc.Accept(ctx, e.in(t, "me"))
	assert.Equal(t, "install_rate_limited", code(err))
	require.Len(t, e.alerts.got, 1, "one alert per window")
	assert.Equal(t, "busy.example", e.alerts.got[0].Install)
	assert.Equal(t, 4, e.alerts.got[0].Count)
	_, err = e.svc.Accept(ctx, e.in(t, "quiet"))
	require.NoError(t, err, "other installs unaffected")

	*e.now = e.now.Add(31 * time.Minute)
	_, err = e.svc.Accept(ctx, e.in(t, "md"))
	require.NoError(t, err)
}

func TestUpstreamOutcomes(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		err    error
		code   string
		status int
	}{
		"unregistered": {delivery.ErrUnregistered, "gone", 410},
		"too large":    {delivery.ErrPayloadTooLarge, "payload_too_large", 413},
		"unavailable":  {delivery.ErrPlatformUnavailable, "platform_unavailable", 503},
		"429":          {&delivery.UpstreamError{Service: "apns", Status: 429}, "upstream_rate_limited", 429},
		"500":          {&delivery.UpstreamError{Service: "apns", Status: 500, Reason: "InternalServerError"}, "upstream_error", 502},
		"other":        {errors.New("boom"), "upstream_error", 502},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 100, 300)
			e.addMailbox(t, "m1", "irc.example")
			e.sender.err = c.err
			_, err := e.svc.Accept(ctx, e.in(t, "m1"))
			assert.Equal(t, c.code, code(err))
			ae, _ := apperr.As(err)
			assert.Equal(t, c.status, ae.Status)
			_, gerr := e.store.GetMailbox(ctx, "m1")
			if c.status == 410 {
				assert.ErrorIs(t, gerr, repo.ErrNotFound, "dead token deletes the mailbox")
				_, err = e.svc.Accept(ctx, e.in(t, "m1"))
				assert.Equal(t, "mailbox_not_found", code(err))
			} else {
				assert.NoError(t, gerr)
			}
		})
	}
}
