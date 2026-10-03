// Package postgres_test verifies the production Store against a real database.
//
// These tests are skipped unless HALIMISOC_TEST_DATABASE_URL is set, following
// the same rule as the black-box suite: a test that needs a database must
// never fail in an environment that does not have one. The truncate guard
// mirrors tests/reset_test.go — the database name must end in _test, so a
// wrong connection string cannot destroy real telemetry.
package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/storage/postgres"
)

// migrationsFS reads the same migration files the server embeds, so the test
// verifies the real upgrade path rather than a copy of it.
var migrationsFS = os.DirFS("../../../apps/api/migrations")

func requireTestStore(t *testing.T) (*postgres.Store, *pgx.Conn, context.Context) {
	t.Helper()
	dsn := os.Getenv("HALIMISOC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set HALIMISOC_TEST_DATABASE_URL to run the PostgreSQL contract tests")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test dsn: %v", err)
	}
	if !strings.HasSuffix(cfg.Database, "_test") {
		t.Fatalf("refusing to test against database %q: the name must end in _test", cfg.Database)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })

	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := postgres.Migrate(ctx, store, migrationsFS); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	if _, err := admin.Exec(ctx,
		`TRUNCATE TABLE audit_logs, incidents, alerts, events, agent_tokens, agents, sessions, users RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate test tables: %v", err)
	}
	return store, admin, ctx
}

func TestMigrationsApplyFromEmpty(t *testing.T) {
	_, admin, ctx := requireTestStore(t)

	rows, err := admin.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	defer rows.Close()
	var versions []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"0001_init.sql", "0002_incident_lifecycle.sql", "0003_incident_source_ips.sql"} {
		found := false
		for _, v := range versions {
			if v == want {
				found = true
			}
		}
		if !found {
			t.Errorf("migration %s not applied (have %v)", want, versions)
		}
	}

	// The 0003 column must exist: the incident write path selects it.
	var hasColumn bool
	if err := admin.QueryRow(ctx, `
		SELECT count(*) > 0 FROM information_schema.columns
		WHERE table_name = 'incidents' AND column_name = 'source_ips'`).Scan(&hasColumn); err != nil {
		t.Fatal(err)
	}
	if !hasColumn {
		t.Fatal("incidents.source_ips column is missing")
	}
}

func TestPostgresIncidentSourceIPsRoundTrip(t *testing.T) {
	store, _, ctx := requireTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	inc := &incidents.Incident{
		ID: "inc_test1", Title: "t", Summary: "s",
		Severity: model.SeverityHigh, Status: incidents.StatusNew,
		Hosts: []string{"web-01"}, Actors: []string{"root"}, SourceIPs: []string{"203.0.113.7"},
		AlertIDs: []string{"alt_1"}, EventIDs: []string{"evt_1"},
		Stages:    []incidents.Stage{{Name: incidents.StageCredentialAccess, AlertID: "alt_1", RuleID: "ssh-bruteforce", At: now, Severity: model.SeverityHigh}},
		FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.SaveIncident(ctx, inc); err != nil {
		t.Fatalf("save incident: %v", err)
	}
	got, err := store.GetIncident(ctx, "inc_test1")
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if len(got.SourceIPs) != 1 || got.SourceIPs[0] != "203.0.113.7" {
		t.Fatalf("source_ips = %v, want [203.0.113.7]", got.SourceIPs)
	}
}

func TestPostgresListUsers(t *testing.T) {
	store, _, ctx := requireTestStore(t)
	now := time.Now().UTC()

	for _, u := range []auth.User{
		{ID: "usr_b", Username: "bob", PasswordHash: "x", Role: authorization.RoleAnalyst, CreatedAt: now},
		{ID: "usr_a", Username: "admin", PasswordHash: "x", Role: authorization.RoleAdmin, CreatedAt: now},
	} {
		u := u
		if err := store.SaveUser(ctx, &u); err != nil {
			t.Fatalf("save user: %v", err)
		}
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 2 || users[0].Username != "admin" || users[1].Username != "bob" {
		t.Fatalf("users not ordered by username: %+v", users)
	}
}
