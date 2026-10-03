// Package postgres is the production Store implementation.
//
// All statements are parameterised. No query is ever assembled by string
// concatenation from a caller-supplied value, because a filter value that
// reaches SQL as text is an injection sink regardless of how it was validated.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/halimi/halimisoc/internal/storage"
)

// Store is the PostgreSQL-backed Store.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL and verifies connectivity.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}

	// A small pool is correct for a single-node MVP: more connections would
	// increase database load without increasing throughput on one host.
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Ping implements storage.Store.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Close implements storage.Store.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Migrate applies every embedded migration that has not been applied yet.
//
// Each migration runs inside a transaction together with the bookkeeping insert,
// so a failure leaves neither a half-applied schema nor a false record of
// success. Migrations are applied in filename order.
func Migrate(ctx context.Context, s *Store, fsys fs.FS) error {
	entries, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return fmt.Errorf("postgres: list migrations: %w", err)
	}
	sort.Strings(entries)

	// Finding no migrations is a deployment mistake, not a valid state: the
	// process would otherwise start against an empty schema and fail later with
	// a confusing "relation does not exist" on the first request.
	if len(entries) == 0 {
		return errors.New("postgres: no migration files found")
	}

	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("postgres: ensure schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("postgres: read applied migrations: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("postgres: scan applied migration: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: iterate applied migrations: %w", err)
	}

	for _, name := range entries {
		if applied[name] {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("postgres: read migration %s: %w", name, err)
		}

		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("postgres: begin migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("postgres: apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("postgres: record migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("postgres: commit migration %s: %w", name, err)
		}
	}
	return nil
}

// --- Shared helpers -------------------------------------------------------

// mapNotFound translates pgx's no-rows sentinel into the storage error the rest
// of the application expects, so callers never import pgx to check for absence.
func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.ErrNotFound
	}
	return err
}

// clampLimit bounds a page size. A non-positive limit falls back to the default
// rather than meaning "unlimited", because an unbounded query is exactly the
// failure mode the resource limits exist to prevent.
func clampLimit(limit, def, max int) int {
	if limit <= 0 {
		return def
	}
	if limit > max {
		return max
	}
	return limit
}
