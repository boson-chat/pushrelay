package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the Store on a pgx pool.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a pool on dsn and pings it.
func NewPostgres(ctx context.Context, dsn string, maxConns int32) (*Postgres, error) {
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	if maxConns > 0 {
		pc.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }
func (p *Postgres) Close()                         { p.pool.Close() }

const mailboxCols = `id, platform, token, vapid_key, install, secret_hash, paused, created_at, updated_at, last_used_at, push_day, push_day_count`

func scanMailbox(row pgx.Row) (*Mailbox, error) {
	var m Mailbox
	err := row.Scan(&m.ID, &m.Platform, &m.Token, &m.VAPIDKey, &m.Install, &m.SecretHash, &m.Paused,
		&m.CreatedAt, &m.UpdatedAt, &m.LastUsedAt, &m.PushDay, &m.PushDayCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func collectIDs(rows pgx.Rows) ([]string, error) {
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func (p *Postgres) CreateMailbox(ctx context.Context, m *Mailbox) ([]string, error) {
	var replaced []string
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `DELETE FROM mailboxes WHERE platform = $1 AND token = $2 AND install = $3 RETURNING id`,
			m.Platform, m.Token, m.Install)
		if err != nil {
			return err
		}
		if replaced, err = collectIDs(rows); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO mailboxes (`+mailboxCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			m.ID, m.Platform, m.Token, m.VAPIDKey, m.Install, m.SecretHash, m.Paused,
			m.CreatedAt, m.UpdatedAt, m.LastUsedAt, m.PushDay, m.PushDayCount)
		return err
	})
	return replaced, err
}

func (p *Postgres) GetMailbox(ctx context.Context, id string) (*Mailbox, error) {
	return scanMailbox(p.pool.QueryRow(ctx, `SELECT `+mailboxCols+` FROM mailboxes WHERE id = $1`, id))
}

func (p *Postgres) UpdateMailboxToken(ctx context.Context, id, token string, now time.Time) ([]string, error) {
	var replaced []string
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		m, err := scanMailbox(tx.QueryRow(ctx, `SELECT `+mailboxCols+` FROM mailboxes WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `DELETE FROM mailboxes WHERE platform = $1 AND token = $2 AND install = $3 AND id <> $4 RETURNING id`,
			m.Platform, token, m.Install, id)
		if err != nil {
			return err
		}
		if replaced, err = collectIDs(rows); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE mailboxes SET token = $2, updated_at = $3, last_used_at = $3 WHERE id = $1`, id, token, now)
		return err
	})
	return replaced, err
}

func (p *Postgres) TouchMailbox(ctx context.Context, id string, now time.Time) error {
	tag, err := p.pool.Exec(ctx, `UPDATE mailboxes SET last_used_at = $2 WHERE id = $1`, id, now)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) DeleteMailbox(ctx context.Context, id string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, id)
	return err == nil && tag.RowsAffected() > 0, err
}

func (p *Postgres) CountPush(ctx context.Context, id, day string, now time.Time) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx, `UPDATE mailboxes SET last_used_at = $3,
		push_day_count = CASE WHEN push_day = $2 THEN push_day_count + 1 ELSE 1 END, push_day = $2
		WHERE id = $1 RETURNING push_day_count`, id, day, now).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}

func (p *Postgres) SetMailboxPaused(ctx context.Context, id string, paused bool) error {
	tag, err := p.pool.Exec(ctx, `UPDATE mailboxes SET paused = $2 WHERE id = $1`, id, paused)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) SetInstallPaused(ctx context.Context, install string, paused bool) (int64, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE mailboxes SET paused = $2 WHERE install = $1 AND paused <> $2`, install, paused)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) DeleteMailboxesUnusedSince(ctx context.Context, t time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM mailboxes WHERE last_used_at < $1`, t)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) CountMailboxesForInstall(ctx context.Context, install string) (int64, error) {
	var n int64
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM mailboxes WHERE install = $1`, install).Scan(&n)
	return n, err
}

func (p *Postgres) InstallStats(ctx context.Context, install, day string) ([]InstallStats, error) {
	rows, err := p.pool.Query(ctx, `SELECT install, platform, count(*), count(*) FILTER (WHERE paused),
		coalesce(sum(push_day_count) FILTER (WHERE push_day = $2), 0)
		FROM mailboxes WHERE ($1 = '' OR install = $1) GROUP BY install, platform ORDER BY install, platform`, install, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstallStats
	for rows.Next() {
		var inst, platform string
		var n, paused, pushes int64
		if err := rows.Scan(&inst, &platform, &n, &paused, &pushes); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].Install != inst {
			out = append(out, InstallStats{Install: inst, ByPlatform: map[string]int64{}})
		}
		s := &out[len(out)-1]
		s.Mailboxes += n
		s.ByPlatform[platform] = n
		s.Paused += paused
		s.PushesToday += pushes
	}
	return out, rows.Err()
}

func (p *Postgres) CountMailboxesByPlatform(ctx context.Context) (map[string]int64, error) {
	rows, err := p.pool.Query(ctx, `SELECT platform, count(*) FROM mailboxes GROUP BY platform`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var platform string
		var n int64
		if err := rows.Scan(&platform, &n); err != nil {
			return nil, err
		}
		out[platform] = n
	}
	return out, rows.Err()
}

func (p *Postgres) BlockInstall(ctx context.Context, b Block) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO blocked_installs (install, reason, created_at) VALUES ($1, $2, $3)
		ON CONFLICT (install) DO UPDATE SET reason = EXCLUDED.reason`, b.Install, b.Reason, b.CreatedAt)
	return err
}

func (p *Postgres) UnblockInstall(ctx context.Context, install string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM blocked_installs WHERE install = $1`, install)
	return err == nil && tag.RowsAffected() > 0, err
}

func (p *Postgres) IsInstallBlocked(ctx context.Context, install string) (bool, error) {
	var ok bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM blocked_installs WHERE install = $1)`, install).Scan(&ok)
	return ok, err
}

func (p *Postgres) ListBlocks(ctx context.Context) ([]Block, error) {
	rows, err := p.pool.Query(ctx, `SELECT install, reason, created_at FROM blocked_installs ORDER BY install`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Block, error) {
		var b Block
		err := r.Scan(&b.Install, &b.Reason, &b.CreatedAt)
		return b, err
	})
}

func (p *Postgres) PutChallenge(ctx context.Context, hash []byte, expires time.Time) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO challenges (hash, expires_at) VALUES ($1, $2)`, hash, expires)
	return err
}

func (p *Postgres) ConsumeChallenge(ctx context.Context, hash []byte, now time.Time) (bool, error) {
	var exp time.Time
	err := p.pool.QueryRow(ctx, `DELETE FROM challenges WHERE hash = $1 RETURNING expires_at`, hash).Scan(&exp)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return now.Before(exp), nil
}

func (p *Postgres) DeleteExpiredChallenges(ctx context.Context, now time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM challenges WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) GetAppAttestKey(ctx context.Context, keyID string) (*AppAttestKey, error) {
	var k AppAttestKey
	var counter int64
	err := p.pool.QueryRow(ctx, `SELECT key_id, public_key, counter, environment, created_at, last_used_at
		FROM app_attest_keys WHERE key_id = $1`, keyID).
		Scan(&k.KeyID, &k.PublicKey, &counter, &k.Environment, &k.CreatedAt, &k.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.Counter = uint32(counter)
	return &k, nil
}

func (p *Postgres) PutAppAttestKey(ctx context.Context, k *AppAttestKey) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO app_attest_keys (key_id, public_key, counter, environment, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (key_id) DO UPDATE SET public_key = EXCLUDED.public_key, counter = EXCLUDED.counter,
		environment = EXCLUDED.environment, last_used_at = EXCLUDED.last_used_at`,
		k.KeyID, k.PublicKey, int64(k.Counter), k.Environment, k.CreatedAt, k.LastUsedAt)
	return err
}

func (p *Postgres) AdvanceAppAttestCounter(ctx context.Context, keyID string, next uint32, now time.Time) (bool, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE app_attest_keys SET counter = $2, last_used_at = $3 WHERE key_id = $1 AND counter < $2`,
		keyID, int64(next), now)
	return err == nil && tag.RowsAffected() > 0, err
}

var _ Store = (*Postgres)(nil)
