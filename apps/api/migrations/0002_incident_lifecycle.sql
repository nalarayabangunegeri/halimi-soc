-- Align the incident lifecycle with the contract in internal/incidents.
--
-- Why a separate migration rather than an edit to 0001: an applied migration is
-- immutable. Editing it would silently leave every existing database on the old
-- schema while a fresh install got the new one, which is the classic way a
-- deployment ends up running a schema nobody can reproduce.
--
-- The original constraint allowed OPEN and rejected NEW, ACKNOWLEDGED and
-- FALSE_POSITIVE. The new lifecycle adds those and keeps CONTAINED, RESOLVED and
-- CLOSED. Existing rows are migrated forward before the new constraint is added,
-- so the ALTER cannot fail on data written under the old vocabulary.

ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_status_check;

UPDATE incidents SET status = 'NEW' WHERE status = 'OPEN';

ALTER TABLE incidents ADD CONSTRAINT incidents_status_check
    CHECK (status IN ('NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'));

CREATE INDEX IF NOT EXISTS incidents_open_idx
    ON incidents (last_seen DESC)
    WHERE status NOT IN ('RESOLVED', 'CLOSED', 'FALSE_POSITIVE');
