-- Track attacker source addresses on incidents.
--
-- Correlation joins alerts that share a concrete entity (host, actor or source
-- address), but incidents only stored hosts and actors, so an IP-only match
-- could never join: two alerts from different hosts under one attacker address
-- always became two incidents. This column closes that gap.
--
-- One logical change per file: only this column is added here. Existing rows
-- keep working because the default covers them; backfilling history is
-- deliberately out of scope, since rewriting past investigations would falsify
-- their timelines.

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS source_ips JSONB NOT NULL DEFAULT '[]'::jsonb;
