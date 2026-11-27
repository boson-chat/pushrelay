// Package db holds the embedded SQL migrations.
package db

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

//go:embed migrations/*.sql
var migrations embed.FS

// newMigrate opens its own connection: migrate closes the *sql.DB it is given.
// golang-migrate takes a Postgres advisory lock, so concurrent replicas are safe.
func newMigrate(dsn string) (*migrate.Migrate, error) {
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	drv, err := migratepgx.WithInstance(sqlDB, &migratepgx.Config{MigrationsTable: "schema_migrations"})
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	src, err := iofs.New(migrations, "migrations")
	if err != nil {
		return nil, err
	}
	return migrate.NewWithInstance("iofs", src, "pgx", drv)
}

// MigrateUp applies all pending migrations.
func MigrateUp(dsn string) error {
	m, err := newMigrate(dsn)
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// MigrateDown rolls back steps migrations (all when steps <= 0).
func MigrateDown(dsn string, steps int) error {
	m, err := newMigrate(dsn)
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()
	if steps > 0 {
		err = m.Steps(-steps)
	} else {
		err = m.Down()
	}
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
