// Package storetest is the contract test both stores (Postgres, memory) run.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

var t0 = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

func mailbox(id, platform, token, install string) *repo.Mailbox {
	return &repo.Mailbox{
		ID: id, Platform: platform, Token: token, VAPIDKey: "key-" + install, Install: install,
		SecretHash: []byte("hash-" + id), CreatedAt: t0, UpdatedAt: t0, LastUsedAt: t0,
	}
}

// Run runs the contract against stores made by newStore (a fresh, empty one per call).
func Run(t *testing.T, newStore func(t *testing.T) repo.Store) {
	ctx := context.Background()

	t.Run("mailbox lifecycle", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.Ping(ctx))
		replaced, err := s.CreateMailbox(ctx, mailbox("a", repo.PlatformAPNs, "tok1", "irc.one"))
		require.NoError(t, err)
		assert.Empty(t, replaced)

		got, err := s.GetMailbox(ctx, "a")
		require.NoError(t, err)
		assert.Equal(t, "tok1", got.Token)
		assert.Equal(t, "key-irc.one", got.VAPIDKey)
		assert.Equal(t, []byte("hash-a"), got.SecretHash)
		assert.True(t, got.LastUsedAt.Equal(t0))

		_, err = s.GetMailbox(ctx, "nope")
		assert.ErrorIs(t, err, repo.ErrNotFound)

		// Same (platform, token, install) replaces; another install doesn't.
		replaced, err = s.CreateMailbox(ctx, mailbox("b", repo.PlatformAPNs, "tok1", "irc.one"))
		require.NoError(t, err)
		assert.Equal(t, []string{"a"}, replaced)
		replaced, err = s.CreateMailbox(ctx, mailbox("c", repo.PlatformAPNs, "tok1", "irc.two"))
		require.NoError(t, err)
		assert.Empty(t, replaced)
		_, err = s.GetMailbox(ctx, "a")
		assert.ErrorIs(t, err, repo.ErrNotFound)

		// Token update deletes a mailbox of the same install holding that token.
		_, err = s.CreateMailbox(ctx, mailbox("d", repo.PlatformAPNs, "tok2", "irc.one"))
		require.NoError(t, err)
		t1 := t0.Add(time.Hour)
		replaced, err = s.UpdateMailboxToken(ctx, "b", "tok2", t1)
		require.NoError(t, err)
		assert.Equal(t, []string{"d"}, replaced)
		got, err = s.GetMailbox(ctx, "b")
		require.NoError(t, err)
		assert.Equal(t, "tok2", got.Token)
		assert.True(t, got.UpdatedAt.Equal(t1))
		assert.True(t, got.LastUsedAt.Equal(t1))
		_, err = s.UpdateMailboxToken(ctx, "nope", "x", t1)
		assert.ErrorIs(t, err, repo.ErrNotFound)

		t2 := t0.Add(2 * time.Hour)
		require.NoError(t, s.TouchMailbox(ctx, "c", t2))
		got, _ = s.GetMailbox(ctx, "c")
		assert.True(t, got.LastUsedAt.Equal(t2))
		assert.ErrorIs(t, s.TouchMailbox(ctx, "nope", t2), repo.ErrNotFound)

		ok, err := s.DeleteMailbox(ctx, "c")
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = s.DeleteMailbox(ctx, "c")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("push counts", func(t *testing.T) {
		s := newStore(t)
		_, err := s.CreateMailbox(ctx, mailbox("a", repo.PlatformFCM, "tok", "irc.one"))
		require.NoError(t, err)
		for i := 1; i <= 3; i++ {
			n, err := s.CountPush(ctx, "a", "2026-11-27", t0.Add(time.Duration(i)*time.Minute))
			require.NoError(t, err)
			assert.Equal(t, i, n)
		}
		n, err := s.CountPush(ctx, "a", "2026-11-28", t0.Add(24*time.Hour))
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		got, _ := s.GetMailbox(ctx, "a")
		assert.True(t, got.LastUsedAt.Equal(t0.Add(24*time.Hour)))
		_, err = s.CountPush(ctx, "nope", "2026-11-28", t0)
		assert.ErrorIs(t, err, repo.ErrNotFound)

		stats, err := s.InstallStats(ctx, "", "2026-11-28")
		require.NoError(t, err)
		require.Len(t, stats, 1)
		assert.Equal(t, int64(1), stats[0].PushesToday)
	})

	t.Run("pause, expiry, stats", func(t *testing.T) {
		s := newStore(t)
		for _, m := range []*repo.Mailbox{
			mailbox("a", repo.PlatformAPNs, "t1", "irc.one"),
			mailbox("b", repo.PlatformFCM, "t2", "irc.one"),
			mailbox("c", repo.PlatformAPNsSandbox, "t3", "irc.two"),
		} {
			_, err := s.CreateMailbox(ctx, m)
			require.NoError(t, err)
		}
		require.NoError(t, s.SetMailboxPaused(ctx, "c", true))
		assert.ErrorIs(t, s.SetMailboxPaused(ctx, "nope", true), repo.ErrNotFound)
		n, err := s.SetInstallPaused(ctx, "irc.one", true)
		require.NoError(t, err)
		assert.Equal(t, int64(2), n)
		n, err = s.SetInstallPaused(ctx, "irc.one", true)
		require.NoError(t, err)
		assert.Equal(t, int64(0), n)

		cnt, err := s.CountMailboxesForInstall(ctx, "irc.one")
		require.NoError(t, err)
		assert.Equal(t, int64(2), cnt)

		byp, err := s.CountMailboxesByPlatform(ctx)
		require.NoError(t, err)
		assert.Equal(t, map[string]int64{"apns": 1, "fcm": 1, "apns-sandbox": 1}, byp)

		stats, err := s.InstallStats(ctx, "", "2026-11-27")
		require.NoError(t, err)
		require.Len(t, stats, 2)
		assert.Equal(t, "irc.one", stats[0].Install)
		assert.Equal(t, int64(2), stats[0].Mailboxes)
		assert.Equal(t, int64(2), stats[0].Paused)
		assert.Equal(t, map[string]int64{"apns": 1, "fcm": 1}, stats[0].ByPlatform)
		one, err := s.InstallStats(ctx, "irc.two", "2026-11-27")
		require.NoError(t, err)
		require.Len(t, one, 1)
		assert.Equal(t, int64(1), one[0].Paused)

		require.NoError(t, s.TouchMailbox(ctx, "a", t0.Add(48*time.Hour)))
		del, err := s.DeleteMailboxesUnusedSince(ctx, t0.Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, int64(2), del)
		_, err = s.GetMailbox(ctx, "a")
		assert.NoError(t, err)
	})

	t.Run("blocks", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.BlockInstall(ctx, repo.Block{Install: "bad.example", Reason: "spam", CreatedAt: t0}))
		require.NoError(t, s.BlockInstall(ctx, repo.Block{Install: "bad.example", Reason: "spam 2", CreatedAt: t0.Add(time.Hour)}))
		ok, err := s.IsInstallBlocked(ctx, "bad.example")
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = s.IsInstallBlocked(ctx, "good.example")
		require.NoError(t, err)
		assert.False(t, ok)
		list, err := s.ListBlocks(ctx)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "spam 2", list[0].Reason)
		assert.True(t, list[0].CreatedAt.Equal(t0))
		ok, err = s.UnblockInstall(ctx, "bad.example")
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = s.UnblockInstall(ctx, "bad.example")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("challenges", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.PutChallenge(ctx, []byte("h1"), t0.Add(time.Minute)))
		require.NoError(t, s.PutChallenge(ctx, []byte("h2"), t0.Add(time.Minute)))
		require.NoError(t, s.PutChallenge(ctx, []byte("h3"), t0.Add(-time.Minute)))
		ok, err := s.ConsumeChallenge(ctx, []byte("h1"), t0)
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = s.ConsumeChallenge(ctx, []byte("h1"), t0)
		require.NoError(t, err)
		assert.False(t, ok, "single use")
		ok, err = s.ConsumeChallenge(ctx, []byte("h2"), t0.Add(2*time.Minute))
		require.NoError(t, err)
		assert.False(t, ok, "expired")
		n, err := s.DeleteExpiredChallenges(ctx, t0)
		require.NoError(t, err)
		assert.Equal(t, int64(1), n)
	})

	t.Run("app attest keys", func(t *testing.T) {
		s := newStore(t)
		_, err := s.GetAppAttestKey(ctx, "k")
		assert.ErrorIs(t, err, repo.ErrNotFound)
		require.NoError(t, s.PutAppAttestKey(ctx, &repo.AppAttestKey{KeyID: "k", PublicKey: []byte{4, 1}, Environment: "production", CreatedAt: t0, LastUsedAt: t0}))
		ok, err := s.AdvanceAppAttestCounter(ctx, "k", 1, t0)
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = s.AdvanceAppAttestCounter(ctx, "k", 1, t0)
		require.NoError(t, err)
		assert.False(t, ok, "replay")
		ok, err = s.AdvanceAppAttestCounter(ctx, "missing", 1, t0)
		require.NoError(t, err)
		assert.False(t, ok)
		k, err := s.GetAppAttestKey(ctx, "k")
		require.NoError(t, err)
		assert.Equal(t, uint32(1), k.Counter)
		assert.Equal(t, []byte{4, 1}, k.PublicKey)
		// re-attestation replaces the key and resets the counter
		require.NoError(t, s.PutAppAttestKey(ctx, &repo.AppAttestKey{KeyID: "k", PublicKey: []byte{4, 2}, Environment: "development", CreatedAt: t0.Add(time.Hour), LastUsedAt: t0}))
		k, err = s.GetAppAttestKey(ctx, "k")
		require.NoError(t, err)
		assert.Equal(t, uint32(0), k.Counter)
		assert.Equal(t, "development", k.Environment)
		assert.True(t, k.CreatedAt.Equal(t0))
	})
}
