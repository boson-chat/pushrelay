package repositories_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/boson-chat/pushrelay/db"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
	"github.com/boson-chat/pushrelay/internal/db/storetest"
)

// newTestDB creates a throwaway database from TEST_DATABASE_URL, migrates
// it, and drops it at the end. Skips without TEST_DATABASE_URL.
func newTestDB(t *testing.T) string {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "pushrelay_test_" + hex.EncodeToString(b)
	admin, err := pgx.Connect(ctx, base)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	u, err := url.Parse(base)
	require.NoError(t, err)
	u.Path = "/" + name
	dsn := u.String()
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	require.NoError(t, db.MigrateUp(dsn))
	return dsn
}

func TestPostgresContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) repo.Store {
		dsn := newTestDB(t)
		s, err := repo.NewPostgres(context.Background(), dsn, 4)
		require.NoError(t, err)
		t.Cleanup(s.Close)
		return s
	})
}

func TestMigrateDown(t *testing.T) {
	dsn := newTestDB(t)
	require.NoError(t, db.MigrateDown(dsn, 1))
	require.NoError(t, db.MigrateUp(dsn))
	require.NoError(t, db.MigrateDown(dsn, 0))
}

func TestNewPostgresBadURL(t *testing.T) {
	_, err := repo.NewPostgres(context.Background(), "postgres://%zz", 1)
	require.Error(t, err)
}
