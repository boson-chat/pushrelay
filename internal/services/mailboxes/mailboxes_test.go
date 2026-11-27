package mailboxes_test

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boson-chat/pushrelay/internal/apperr"
	"github.com/boson-chat/pushrelay/internal/db/memstore"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
	"github.com/boson-chat/pushrelay/internal/services/attest"
	"github.com/boson-chat/pushrelay/internal/services/mailboxes"
	"github.com/boson-chat/pushrelay/internal/services/ratelimit"
	"github.com/boson-chat/pushrelay/metrics"
)

var t0 = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

type fakeAttester struct {
	err  error
	last attest.Request
}

func (f *fakeAttester) Verify(_ context.Context, r attest.Request) (attest.Result, error) {
	f.last = r
	return attest.Result{Method: attest.MethodDev}, f.err
}

type platforms map[string]bool

func (p platforms) Available(pl string) bool { return p[pl] }

type env struct {
	svc     *mailboxes.Service
	store   *memstore.Store
	att     *fakeAttester
	now     *time.Time
	deleted []string
}

func newEnv(t *testing.T, mod func(*mailboxes.Deps)) *env {
	e := &env{store: memstore.New(), att: &fakeAttester{}}
	now := t0
	e.now = &now
	d := mailboxes.Deps{
		Store: e.store, Attest: e.att, Platforms: platforms{"apns": true, "apns-sandbox": true, "fcm": true},
		Metrics: metrics.New(), Now: func() time.Time { return *e.now }, PublicURL: "https://push.example",
		Apps:        map[string]string{"apns": "chat.boson.app", "apns-sandbox": "chat.boson.app", "fcm": "chat.boson.app"},
		CreatePerIP: ratelimit.NewWindow(20, time.Hour, func() time.Time { return *e.now }),
		Expiry:      60 * 24 * time.Hour,
		OnDelete:    func(ids ...string) { e.deleted = append(e.deleted, ids...) },
	}
	if mod != nil {
		mod(&d)
	}
	e.svc = mailboxes.New(d)
	return e
}

func vapidKey(t *testing.T) string {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ek, _ := k.PublicKey.ECDH()
	return base64.RawURLEncoding.EncodeToString(ek.Bytes())
}

func input(t *testing.T) mailboxes.CreateInput {
	return mailboxes.CreateInput{
		Platform: "apns", Token: strings.Repeat("ab", 32), App: "chat.boson.app", Attestation: "x",
		VAPID: vapidKey(t), Install: "Boson.IRCForever.org.", ClientIP: "203.0.113.5", Challenge: "c",
	}
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

func TestMailboxLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	in := input(t)
	out, err := e.svc.Create(ctx, in)
	require.NoError(t, err)
	assert.Len(t, out.ID, 22, "128-bit base64url id")
	assert.Equal(t, "https://push.example/v1/push/"+out.ID, out.Endpoint)
	assert.Len(t, out.Secret, 43)
	assert.Equal(t, in.VAPID, e.att.last.VAPID, "attestation binds values as sent")
	assert.Equal(t, in.Install, e.att.last.Install)

	m, err := e.store.GetMailbox(ctx, out.ID)
	require.NoError(t, err)
	assert.Equal(t, "boson.ircforever.org", m.Install)
	assert.Equal(t, mailboxes.HashSecret(out.Secret), m.SecretHash)
	assert.NotContains(t, string(m.SecretHash), out.Secret)

	// Same device + install again: replaces the old mailbox.
	out2, err := e.svc.Create(ctx, in)
	require.NoError(t, err)
	assert.NotEqual(t, out.ID, out2.ID)
	assert.Equal(t, []string{out.ID}, e.deleted)
	_, err = e.store.GetMailbox(ctx, out.ID)
	assert.ErrorIs(t, err, repo.ErrNotFound)

	// PATCH: wrong / missing secret, renew, new token.
	assert.Equal(t, "secret_required", code(e.svc.Update(ctx, out2.ID, "", mailboxes.UpdateInput{})))
	assert.Equal(t, "secret_invalid", code(e.svc.Update(ctx, out2.ID, "wrong", mailboxes.UpdateInput{})))
	assert.Equal(t, "mailbox_not_found", code(e.svc.Update(ctx, "nope", "x", mailboxes.UpdateInput{})))
	*e.now = t0.Add(time.Hour)
	require.NoError(t, e.svc.Update(ctx, out2.ID, out2.Secret, mailboxes.UpdateInput{}))
	m, _ = e.store.GetMailbox(ctx, out2.ID)
	assert.True(t, m.LastUsedAt.Equal(t0.Add(time.Hour)))
	newTok := strings.Repeat("cd", 32)
	require.NoError(t, e.svc.Update(ctx, out2.ID, out2.Secret, mailboxes.UpdateInput{Token: &newTok}))
	m, _ = e.store.GetMailbox(ctx, out2.ID)
	assert.Equal(t, newTok, m.Token)
	same := newTok
	require.NoError(t, e.svc.Update(ctx, out2.ID, out2.Secret, mailboxes.UpdateInput{Token: &same}))
	bad := "not hex!"
	assert.Equal(t, "invalid_request", code(e.svc.Update(ctx, out2.ID, out2.Secret, mailboxes.UpdateInput{Token: &bad})))

	// DELETE.
	assert.Equal(t, "secret_invalid", code(e.svc.Delete(ctx, out2.ID, "wrong")))
	require.NoError(t, e.svc.Delete(ctx, out2.ID, out2.Secret))
	assert.Equal(t, "mailbox_not_found", code(e.svc.Delete(ctx, out2.ID, out2.Secret)))
	assert.Contains(t, e.deleted, out2.ID)
}

func TestCreateValidation(t *testing.T) {
	e := newEnv(t, func(d *mailboxes.Deps) { d.Platforms = platforms{"apns": true} })
	ctx := context.Background()
	for name, c := range map[string]struct {
		mod  func(*mailboxes.CreateInput)
		code string
	}{
		"platform":        {func(i *mailboxes.CreateInput) { i.Platform = "web" }, "invalid_request"},
		"apns token":      {func(i *mailboxes.CreateInput) { i.Token = "xyz" }, "invalid_request"},
		"empty token":     {func(i *mailboxes.CreateInput) { i.Token = "" }, "invalid_request"},
		"app":             {func(i *mailboxes.CreateInput) { i.App = "other.app" }, "app_mismatch"},
		"vapid":           {func(i *mailboxes.CreateInput) { i.VAPID = "AAAA" }, "invalid_request"},
		"install empty":   {func(i *mailboxes.CreateInput) { i.Install = "" }, "invalid_request"},
		"install url":     {func(i *mailboxes.CreateInput) { i.Install = "https://x.example/" }, "invalid_request"},
		"install label":   {func(i *mailboxes.CreateInput) { i.Install = "-x.example" }, "invalid_request"},
		"install dots":    {func(i *mailboxes.CreateInput) { i.Install = "a..b" }, "invalid_request"},
		"install long":    {func(i *mailboxes.CreateInput) { i.Install = strings.Repeat("a", 64) + ".example" }, "invalid_request"},
		"fcm unavailable": {func(i *mailboxes.CreateInput) { i.Platform = "fcm"; i.Token = "fcm:Tok_en-1" }, "platform_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			in := input(t)
			c.mod(&in)
			_, err := e.svc.Create(ctx, in)
			assert.Equal(t, c.code, code(err))
		})
	}
}

func TestCreateLimitsAndBlocks(t *testing.T) {
	e := newEnv(t, func(d *mailboxes.Deps) {
		d.CreatePerIP = ratelimit.NewWindow(3, time.Hour, nil)
		d.MaxPerInstall = 2
	})
	ctx := context.Background()
	in := input(t)
	_, err := e.svc.Create(ctx, in)
	require.NoError(t, err)
	in2 := input(t)
	in2.Token = strings.Repeat("ef", 32)
	_, err = e.svc.Create(ctx, in2)
	require.NoError(t, err)
	in3 := input(t)
	in3.Token = strings.Repeat("01", 32)
	_, err = e.svc.Create(ctx, in3)
	assert.Equal(t, "install_mailbox_limit", code(err))
	_, err = e.svc.Create(ctx, in3)
	assert.Equal(t, "rate_limited", code(err), "4th creation from the IP this hour")
	in3.ClientIP = "198.51.100.1"

	// Attestation failure.
	e.att.err = attest.ErrFailed
	in4 := input(t)
	in4.Install, in4.ClientIP = "other.example", "198.51.100.2"
	_, err = e.svc.Create(ctx, in4)
	assert.Equal(t, "attestation_failed", code(err))
	e.att.err = nil

	// Blocked install.
	n, err := e.svc.Block(ctx, "Boson.IRCForever.org", "spam")
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	_, err = e.svc.Create(ctx, in3)
	assert.Equal(t, "install_blocked", code(err))
	blocks, err := e.svc.Blocks(ctx)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "boson.ircforever.org", blocks[0].Install)
	n, err = e.svc.Unblock(ctx, "boson.ircforever.org")
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	_, err = e.svc.Unblock(ctx, "boson.ircforever.org")
	assert.Equal(t, "not_blocked", code(err))
	_, err = e.svc.Block(ctx, "not a domain", "")
	assert.Equal(t, "invalid_request", code(err))
	_, err = e.svc.Block(ctx, "x.example", strings.Repeat("r", 501))
	assert.Equal(t, "invalid_request", code(err))
	_, err = e.svc.Unblock(ctx, "")
	assert.Equal(t, "invalid_request", code(err))
}

func TestExpiry(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	old, err := e.svc.Create(ctx, input(t))
	require.NoError(t, err)
	*e.now = t0.Add(30 * 24 * time.Hour)
	in := input(t)
	in.Token = strings.Repeat("ee", 32)
	fresh, err := e.svc.Create(ctx, in)
	require.NoError(t, err)
	require.NoError(t, e.store.PutChallenge(ctx, []byte("c"), t0))

	*e.now = t0.Add(61 * 24 * time.Hour)
	n, err := e.svc.Expire(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	_, err = e.store.GetMailbox(ctx, old.ID)
	assert.ErrorIs(t, err, repo.ErrNotFound)
	_, err = e.store.GetMailbox(ctx, fresh.ID)
	assert.NoError(t, err)
	ok, _ := e.store.ConsumeChallenge(ctx, []byte("c"), t0.Add(-time.Hour))
	assert.False(t, ok, "expired challenges are deleted")
	require.NoError(t, e.svc.RefreshGauges(ctx))
}

func TestAdmin(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	in := input(t)
	out, err := e.svc.Create(ctx, in)
	require.NoError(t, err)
	in.Platform, in.Token = "fcm", "fcm-token:xyz"
	_, err = e.svc.Create(ctx, in)
	require.NoError(t, err)
	_, err = e.store.CountPush(ctx, out.ID, mailboxes.Day(t0), t0)
	require.NoError(t, err)

	v, err := e.svc.AdminGet(ctx, out.ID)
	require.NoError(t, err)
	assert.Equal(t, "abababab…", v.Token)
	assert.Equal(t, 1, v.PushesToday)
	_, err = e.svc.AdminGet(ctx, "nope")
	assert.Equal(t, "mailbox_not_found", code(err))

	require.NoError(t, e.svc.AdminSetPaused(ctx, out.ID, true))
	v, _ = e.svc.AdminGet(ctx, out.ID)
	assert.True(t, v.Paused)
	assert.Equal(t, "mailbox_not_found", code(e.svc.AdminSetPaused(ctx, "nope", true)))

	_, err = e.svc.Block(ctx, "blocked.example", "")
	require.NoError(t, err)
	list, err := e.svc.Installs(ctx, "", map[string]int{"boson.ircforever.org": 7, "gone.example": 2}, 10000)
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, "blocked.example", list[0].Install)
	assert.True(t, list[0].Blocked)
	assert.Equal(t, "boson.ircforever.org", list[1].Install)
	assert.Equal(t, int64(2), list[1].Mailboxes)
	assert.Equal(t, map[string]int64{"apns": 1, "fcm": 1}, list[1].ByPlatform)
	assert.Equal(t, int64(1), list[1].Paused)
	assert.Equal(t, int64(1), list[1].PushesToday)
	assert.Equal(t, 7, list[1].PushesThisHour)
	assert.Equal(t, 10000, list[1].HourlyCeiling)
	assert.Equal(t, "gone.example", list[2].Install)
	one, err := e.svc.Installs(ctx, "BOSON.ircforever.org", nil, 1)
	require.NoError(t, err)
	require.Len(t, one, 1)
	_, err = e.svc.Installs(ctx, "bad domain", nil, 1)
	assert.Error(t, err)

	require.NoError(t, e.svc.AdminDelete(ctx, out.ID))
	assert.Equal(t, "mailbox_not_found", code(e.svc.AdminDelete(ctx, out.ID)))
	assert.Equal(t, "short", mailboxes.ShortToken("short"))
}

type failingStore struct {
	*memstore.Store
}

var errDB = errors.New("db down")

func (failingStore) IsInstallBlocked(context.Context, string) (bool, error) { return false, errDB }

func TestStoreErrors(t *testing.T) {
	e := newEnv(t, func(d *mailboxes.Deps) { d.Store = failingStore{memstore.New()} })
	_, err := e.svc.Create(context.Background(), input(t))
	assert.ErrorIs(t, err, errDB)
}
