-- Add TOTP/2FA support for users
CREATE TABLE IF NOT EXISTS user_totp_secrets (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    backup_codes TEXT NOT NULL, -- JSON array of backup codes
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_totp_secrets_user_id ON user_totp_secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_user_totp_secrets_enabled ON user_totp_secrets(enabled);

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_totp_secrets_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_user_totp_secrets_updated_at ON user_totp_secrets;
CREATE TRIGGER update_user_totp_secrets_updated_at
    BEFORE UPDATE ON user_totp_secrets
    FOR EACH ROW
    EXECUTE FUNCTION update_totp_secrets_updated_at();