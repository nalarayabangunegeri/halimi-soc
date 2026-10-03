package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// appTables are the tables the end-to-end test writes to.
//
// The order matters only for readability: TRUNCATE ... CASCADE handles the
// foreign keys, so the list does not need to be dependency-sorted.
var appTables = []string{
	"audit_logs",
	"incidents",
	"alerts",
	"events",
	"agent_tokens",
	"agents",
	"sessions",
	"users",
}

// resetDatabase empties the application tables so each end-to-end run starts
// from a known state.
//
// Without this the test is order-dependent: alerts from a previous run share an
// actor and source address with the current run, so correlation correctly merges
// them into the existing incident and the "a new incident was created" assertion
// fails. The failure would be in the test, not the product, which is exactly the
// kind of noise that teaches people to ignore a suite.
//
// The function refuses to run unless the database name ends in "_test". A
// truncate against the wrong connection string would destroy real telemetry, and
// a name check is the cheapest guard that cannot be defeated by a typo in a
// different variable.
func resetDatabase(t *testing.T, dsn string) {
	t.Helper()

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test dsn: %v", err)
	}
	if !strings.HasSuffix(cfg.Database, "_test") {
		t.Fatalf("refusing to truncate database %q: the name must end in _test", cfg.Database)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	defer conn.Close(ctx)

	stmt := fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", strings.Join(appTables, ", "))
	if _, err := conn.Exec(ctx, stmt); err != nil {
		// A missing table means migrations have not run yet, which is not a
		// failure of this helper: the API applies them at startup.
		if strings.Contains(err.Error(), "does not exist") {
			t.Logf("skipping reset, schema not present yet: %v", err)
			return
		}
		t.Fatalf("truncate test tables: %v", err)
	}
}
