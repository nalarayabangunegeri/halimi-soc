-- MFA columns on operators.
--
-- totp_secret holds the sealed TOTP secret: "v1:<nonce>:<ct>" when
-- HALIMISOC_MFA_KEY is set (AES-256-GCM), else "plain:<base32>".
-- totp_enabled gates login enforcement; setup writes the secret with
-- enabled=FALSE and enable flips it after a valid code.
-- backup_codes holds SHA-256 hex hashes of single-use recovery codes.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret TEXT,
    ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS totp_enrolled_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS backup_codes JSONB NOT NULL DEFAULT '[]'::jsonb;
