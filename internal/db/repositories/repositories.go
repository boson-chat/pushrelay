// Package repositories defines the relay's storage: models and the Store
// interface, implemented for Postgres (postgres.go) and in memory
// (internal/db/memstore, tests and development).
package repositories

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Platforms a mailbox can deliver to.
const (
	PlatformAPNs        = "apns"
	PlatformAPNsSandbox = "apns-sandbox"
	PlatformFCM         = "fcm"
)

// ValidPlatform reports whether p is a known platform.
func ValidPlatform(p string) bool {
	return p == PlatformAPNs || p == PlatformAPNsSandbox || p == PlatformFCM
}

// Mailbox is one (device, install) binding.
type Mailbox struct {
	ID       string
	Platform string
	// APNs device token or FCM registration token.
	Token string
	// The install's VAPID public key, base64url (no padding) of the
	// uncompressed P-256 point.
	VAPIDKey string
	// Install domain, lowercase.
	Install string
	// SHA-256 of the management secret.
	SecretHash []byte
	Paused     bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	// Last push or management call; mailboxes unused for the expiry are deleted.
	LastUsedAt time.Time
	// UTC day (YYYY-MM-DD) PushDayCount counts pushes for.
	PushDay      string
	PushDayCount int
}

// InstallStats is per-install counts for the operator.
type InstallStats struct {
	Install     string           `json:"install"`
	Mailboxes   int64            `json:"mailboxes"`
	ByPlatform  map[string]int64 `json:"by_platform"`
	Paused      int64            `json:"paused"`
	PushesToday int64            `json:"pushes_today"`
}

// Block is an operator block of an install domain.
type Block struct {
	Install   string    `json:"install"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// AppAttestKey is an App Attest key registered with an attestation object.
type AppAttestKey struct {
	KeyID string
	// Uncompressed P-256 point.
	PublicKey []byte
	Counter   uint32
	// "production" or "development" (the attestation's aaguid).
	Environment string
	CreatedAt   time.Time
	LastUsedAt  time.Time
}

// MailboxRepository stores mailboxes.
type MailboxRepository interface {
	// CreateMailbox inserts m, replacing a mailbox with the same (platform,
	// token, install). It returns the replaced ids.
	CreateMailbox(ctx context.Context, m *Mailbox) (replaced []string, err error)
	GetMailbox(ctx context.Context, id string) (*Mailbox, error)
	// UpdateMailboxToken sets a new device token (deleting another mailbox
	// of the same install that already had it) and touches the mailbox.
	UpdateMailboxToken(ctx context.Context, id, token string, now time.Time) (replaced []string, err error)
	TouchMailbox(ctx context.Context, id string, now time.Time) error
	DeleteMailbox(ctx context.Context, id string) (bool, error)
	// CountPush touches the mailbox and adds one to its count for day,
	// returning the new count.
	CountPush(ctx context.Context, id, day string, now time.Time) (int, error)
	SetMailboxPaused(ctx context.Context, id string, paused bool) error
	SetInstallPaused(ctx context.Context, install string, paused bool) (int64, error)
	DeleteMailboxesUnusedSince(ctx context.Context, t time.Time) (int64, error)
	CountMailboxesForInstall(ctx context.Context, install string) (int64, error)
	// InstallStats lists per-install counts (one install when install != "").
	InstallStats(ctx context.Context, install, day string) ([]InstallStats, error)
	CountMailboxesByPlatform(ctx context.Context) (map[string]int64, error)
}

// BlockRepository stores install blocks.
type BlockRepository interface {
	BlockInstall(ctx context.Context, b Block) error
	UnblockInstall(ctx context.Context, install string) (bool, error)
	IsInstallBlocked(ctx context.Context, install string) (bool, error)
	ListBlocks(ctx context.Context) ([]Block, error)
}

// ChallengeRepository stores single-use attestation challenges by hash.
type ChallengeRepository interface {
	PutChallenge(ctx context.Context, hash []byte, expires time.Time) error
	// ConsumeChallenge deletes the challenge and reports whether it existed
	// and had not expired at now.
	ConsumeChallenge(ctx context.Context, hash []byte, now time.Time) (bool, error)
	DeleteExpiredChallenges(ctx context.Context, now time.Time) (int64, error)
}

// AppAttestKeyRepository stores App Attest keys.
type AppAttestKeyRepository interface {
	GetAppAttestKey(ctx context.Context, keyID string) (*AppAttestKey, error)
	// PutAppAttestKey inserts or replaces a key (a fresh attestation wins).
	PutAppAttestKey(ctx context.Context, k *AppAttestKey) error
	// AdvanceAppAttestCounter sets the counter to next if it is still below
	// next, reporting whether it did (assertion replay protection).
	AdvanceAppAttestCounter(ctx context.Context, keyID string, next uint32, now time.Time) (bool, error)
}

// Store is all of the relay's storage.
type Store interface {
	MailboxRepository
	BlockRepository
	ChallengeRepository
	AppAttestKeyRepository
	Ping(ctx context.Context) error
	Close()
}
