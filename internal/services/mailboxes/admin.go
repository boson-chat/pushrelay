package mailboxes

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/boson-chat/pushrelay/internal/apperr"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
	"github.com/boson-chat/pushrelay/internal/logger"
)

// MailboxView is a mailbox as the operator sees it (token shortened).
type MailboxView struct {
	ID          string    `json:"id"`
	Platform    string    `json:"platform"`
	Install     string    `json:"install"`
	Token       string    `json:"token"`
	Paused      bool      `json:"paused"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	PushesToday int       `json:"pushes_today"`
}

// ShortToken keeps the first 8 characters of a device token (logs, admin).
func ShortToken(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "…"
}

// Day is the UTC day key for the daily push count.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// AdminGet shows one mailbox.
func (s *Service) AdminGet(ctx context.Context, id string) (*MailboxView, error) {
	m, err := s.d.Store.GetMailbox(ctx, id)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v := &MailboxView{ID: m.ID, Platform: m.Platform, Install: m.Install, Token: ShortToken(m.Token),
		Paused: m.Paused, CreatedAt: m.CreatedAt, LastUsedAt: m.LastUsedAt}
	if m.PushDay == Day(s.d.Now()) {
		v.PushesToday = m.PushDayCount
	}
	return v, nil
}

// AdminDelete deletes a mailbox without its secret.
func (s *Service) AdminDelete(ctx context.Context, id string) error {
	ok, err := s.d.Store.DeleteMailbox(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	s.d.OnDelete(id)
	logger.FromCtx(ctx).Warn().Str("mailbox", id).Msg("operator deleted mailbox")
	return nil
}

// AdminSetPaused pauses or resumes one mailbox.
func (s *Service) AdminSetPaused(ctx context.Context, id string, paused bool) error {
	err := s.d.Store.SetMailboxPaused(ctx, id, paused)
	if errors.Is(err, repo.ErrNotFound) {
		return ErrNotFound
	}
	if err == nil {
		logger.FromCtx(ctx).Warn().Str("mailbox", id).Bool("paused", paused).Msg("operator paused/resumed mailbox")
	}
	return err
}

// Block blocks an install domain: its pushes get 403, its mailboxes are
// paused and it can't create new ones. Returns how many were paused.
func (s *Service) Block(ctx context.Context, install, reason string) (int64, error) {
	install, err := NormalizeInstall(install)
	if err != nil {
		return 0, err
	}
	if len(reason) > 500 {
		return 0, apperr.Invalid("reason is too long")
	}
	if err := s.d.Store.BlockInstall(ctx, repo.Block{Install: install, Reason: reason, CreatedAt: s.d.Now()}); err != nil {
		return 0, err
	}
	n, err := s.d.Store.SetInstallPaused(ctx, install, true)
	if err != nil {
		return 0, err
	}
	logger.FromCtx(ctx).Warn().Str("install", install).Int64("paused", n).Str("reason", reason).Msg("operator blocked install")
	return n, nil
}

// ErrNotBlocked is Unblock of an install that isn't blocked.
var ErrNotBlocked = apperr.New(http.StatusNotFound, "not_blocked", "install is not blocked")

// Unblock lifts a block and resumes the install's mailboxes.
func (s *Service) Unblock(ctx context.Context, install string) (int64, error) {
	install, err := NormalizeInstall(install)
	if err != nil {
		return 0, err
	}
	ok, err := s.d.Store.UnblockInstall(ctx, install)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, ErrNotBlocked
	}
	n, err := s.d.Store.SetInstallPaused(ctx, install, false)
	if err != nil {
		return 0, err
	}
	logger.FromCtx(ctx).Warn().Str("install", install).Int64("resumed", n).Msg("operator unblocked install")
	return n, nil
}

// Blocks lists blocked installs.
func (s *Service) Blocks(ctx context.Context) ([]repo.Block, error) {
	return s.d.Store.ListBlocks(ctx)
}

// InstallView is per-install counts for the operator.
type InstallView struct {
	repo.InstallStats
	PushesThisHour int  `json:"pushes_this_hour"`
	HourlyCeiling  int  `json:"hourly_ceiling"`
	Blocked        bool `json:"blocked"`
}

// Installs lists per-install counts (one install when install != "").
// hourly is the current hour's push counts by install.
func (s *Service) Installs(ctx context.Context, install string, hourly map[string]int, ceiling int) ([]InstallView, error) {
	if install != "" {
		var err error
		if install, err = NormalizeInstall(install); err != nil {
			return nil, err
		}
	}
	stats, err := s.d.Store.InstallStats(ctx, install, Day(s.d.Now()))
	if err != nil {
		return nil, err
	}
	blocks, err := s.d.Store.ListBlocks(ctx)
	if err != nil {
		return nil, err
	}
	blocked := map[string]bool{}
	for _, b := range blocks {
		blocked[b.Install] = true
	}
	seen := map[string]bool{}
	out := make([]InstallView, 0, len(stats))
	for _, st := range stats {
		seen[st.Install] = true
		out = append(out, InstallView{InstallStats: st, PushesThisHour: hourly[st.Install], HourlyCeiling: ceiling, Blocked: blocked[st.Install]})
	}
	// Installs that pushed this hour or are blocked but have no mailboxes left.
	extra := func(inst string) {
		if !seen[inst] && (install == "" || inst == install) {
			seen[inst] = true
			out = append(out, InstallView{InstallStats: repo.InstallStats{Install: inst, ByPlatform: map[string]int64{}},
				PushesThisHour: hourly[inst], HourlyCeiling: ceiling, Blocked: blocked[inst]})
		}
	}
	for inst := range hourly {
		extra(inst)
	}
	for inst := range blocked {
		extra(inst)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Install < out[j].Install })
	return out, nil
}
