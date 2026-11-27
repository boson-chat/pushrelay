// Package memstore is an in-memory repositories.Store for tests and
// development (PUSHRELAY_DATABASE_URL=memory). Nothing survives a restart.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

// Store is the in-memory store.
type Store struct {
	mu         sync.Mutex
	mailboxes  map[string]repo.Mailbox
	blocks     map[string]repo.Block
	challenges map[string]time.Time
	keys       map[string]repo.AppAttestKey
}

// New returns an empty store.
func New() *Store {
	return &Store{
		mailboxes:  map[string]repo.Mailbox{},
		blocks:     map[string]repo.Block{},
		challenges: map[string]time.Time{},
		keys:       map[string]repo.AppAttestKey{},
	}
}

func (s *Store) Ping(context.Context) error { return nil }
func (s *Store) Close()                     {}

func (s *Store) deleteWhere(keep func(repo.Mailbox) bool) []string {
	var ids []string
	for id, m := range s.mailboxes {
		if !keep(m) {
			ids = append(ids, id)
			delete(s.mailboxes, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (s *Store) CreateMailbox(_ context.Context, m *repo.Mailbox) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	replaced := s.deleteWhere(func(o repo.Mailbox) bool {
		return o.Platform != m.Platform || o.Token != m.Token || o.Install != m.Install
	})
	s.mailboxes[m.ID] = *m
	return replaced, nil
}

func (s *Store) GetMailbox(_ context.Context, id string) (*repo.Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mailboxes[id]
	if !ok {
		return nil, repo.ErrNotFound
	}
	return &m, nil
}

func (s *Store) UpdateMailboxToken(_ context.Context, id, token string, now time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mailboxes[id]
	if !ok {
		return nil, repo.ErrNotFound
	}
	replaced := s.deleteWhere(func(o repo.Mailbox) bool {
		return o.ID == id || o.Platform != m.Platform || o.Token != token || o.Install != m.Install
	})
	m.Token, m.UpdatedAt, m.LastUsedAt = token, now, now
	s.mailboxes[id] = m
	return replaced, nil
}

func (s *Store) update(id string, f func(*repo.Mailbox)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mailboxes[id]
	if !ok {
		return repo.ErrNotFound
	}
	f(&m)
	s.mailboxes[id] = m
	return nil
}

func (s *Store) TouchMailbox(_ context.Context, id string, now time.Time) error {
	return s.update(id, func(m *repo.Mailbox) { m.LastUsedAt = now })
}

func (s *Store) DeleteMailbox(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.mailboxes[id]
	delete(s.mailboxes, id)
	return ok, nil
}

func (s *Store) CountPush(_ context.Context, id, day string, now time.Time) (int, error) {
	var n int
	err := s.update(id, func(m *repo.Mailbox) {
		m.LastUsedAt = now
		if m.PushDay == day {
			m.PushDayCount++
		} else {
			m.PushDay, m.PushDayCount = day, 1
		}
		n = m.PushDayCount
	})
	return n, err
}

func (s *Store) SetMailboxPaused(_ context.Context, id string, paused bool) error {
	return s.update(id, func(m *repo.Mailbox) { m.Paused = paused })
}

func (s *Store) SetInstallPaused(_ context.Context, install string, paused bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, m := range s.mailboxes {
		if m.Install == install && m.Paused != paused {
			m.Paused = paused
			s.mailboxes[id] = m
			n++
		}
	}
	return n, nil
}

func (s *Store) DeleteMailboxesUnusedSince(_ context.Context, t time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.deleteWhere(func(m repo.Mailbox) bool { return !m.LastUsedAt.Before(t) }))), nil
}

func (s *Store) CountMailboxesForInstall(_ context.Context, install string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, m := range s.mailboxes {
		if m.Install == install {
			n++
		}
	}
	return n, nil
}

func (s *Store) InstallStats(_ context.Context, install, day string) ([]repo.InstallStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	by := map[string]*repo.InstallStats{}
	for _, m := range s.mailboxes {
		if install != "" && m.Install != install {
			continue
		}
		st := by[m.Install]
		if st == nil {
			st = &repo.InstallStats{Install: m.Install, ByPlatform: map[string]int64{}}
			by[m.Install] = st
		}
		st.Mailboxes++
		st.ByPlatform[m.Platform]++
		if m.Paused {
			st.Paused++
		}
		if m.PushDay == day {
			st.PushesToday += int64(m.PushDayCount)
		}
	}
	out := make([]repo.InstallStats, 0, len(by))
	for _, st := range by {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Install < out[j].Install })
	return out, nil
}

func (s *Store) CountMailboxesByPlatform(context.Context) (map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int64{}
	for _, m := range s.mailboxes {
		out[m.Platform]++
	}
	return out, nil
}

func (s *Store) BlockInstall(_ context.Context, b repo.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.blocks[b.Install]; ok {
		b.CreatedAt = old.CreatedAt
	}
	s.blocks[b.Install] = b
	return nil
}

func (s *Store) UnblockInstall(_ context.Context, install string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.blocks[install]
	delete(s.blocks, install)
	return ok, nil
}

func (s *Store) IsInstallBlocked(_ context.Context, install string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.blocks[install]
	return ok, nil
}

func (s *Store) ListBlocks(context.Context) ([]repo.Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]repo.Block, 0, len(s.blocks))
	for _, b := range s.blocks {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Install < out[j].Install })
	return out, nil
}

func (s *Store) PutChallenge(_ context.Context, hash []byte, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[string(hash)] = expires
	return nil
}

func (s *Store) ConsumeChallenge(_ context.Context, hash []byte, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.challenges[string(hash)]
	delete(s.challenges, string(hash))
	return ok && now.Before(exp), nil
}

func (s *Store) DeleteExpiredChallenges(_ context.Context, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for h, exp := range s.challenges {
		if !now.Before(exp) {
			delete(s.challenges, h)
			n++
		}
	}
	return n, nil
}

func (s *Store) GetAppAttestKey(_ context.Context, keyID string) (*repo.AppAttestKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, repo.ErrNotFound
	}
	k.PublicKey = append([]byte(nil), k.PublicKey...)
	return &k, nil
}

func (s *Store) PutAppAttestKey(_ context.Context, k *repo.AppAttestKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.keys[k.KeyID]; ok {
		k.CreatedAt = old.CreatedAt
	}
	s.keys[k.KeyID] = *k
	return nil
}

func (s *Store) AdvanceAppAttestCounter(_ context.Context, keyID string, next uint32, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok || k.Counter >= next {
		return false, nil
	}
	k.Counter, k.LastUsedAt = next, now
	s.keys[keyID] = k
	return true, nil
}

var _ repo.Store = (*Store)(nil)
