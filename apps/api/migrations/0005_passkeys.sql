-- Passkey (WebAuthn) credentials.
--
-- One row per registered authenticator. public_key holds the raw COSE_Key
-- bytes (base64url); x/y are not stored separately because the COSE blob is
-- the canonical form verified at registration. sign_count implements clone
-- detection; last_used_at tracks activity.
CREATE TABLE IF NOT EXISTS passkeys (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id  TEXT NOT NULL,
    public_key     TEXT NOT NULL,
    sign_count     BIGINT NOT NULL DEFAULT 0,
    transports     JSONB NOT NULL DEFAULT '[]'::jsonb,
    name           TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL,
    last_used_at   TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS passkeys_credential_idx ON passkeys (credential_id);
CREATE INDEX IF NOT EXISTS passkeys_user_idx ON passkeys (user_id);
