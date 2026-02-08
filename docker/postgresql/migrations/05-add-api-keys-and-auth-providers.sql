-- Migration: 05-add-api-keys-and-auth-providers.sql
-- Description: Add support for API Keys and External Auth Provider persistence

-- Table for API Keys / Personal Access Tokens
CREATE TABLE IF NOT EXISTS auth.api_keys (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,
    scopes      JSONB DEFAULT '[]',
    expires_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_api_keys_user
        FOREIGN KEY (user_id)
        REFERENCES auth.users(id)
        ON DELETE CASCADE
);

CREATE INDEX ix_api_keys_user ON auth.api_keys (user_id);

-- Table for Persisting Auth Provider Configurations (moving from .conf to DB for runtime updates)
CREATE TABLE IF NOT EXISTS auth.providers (
    slug        TEXT PRIMARY KEY, -- 'azure', 'google', 'github'
    name        TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    client_id   TEXT,
    client_secret TEXT,
    redirect_url TEXT,
    tenant_id    TEXT, -- For Microsoft Entra ID
    metadata     JSONB DEFAULT '{}',
    updated_at   TIMESTAMPTZ DEFAULT now()
);

-- Insert initial providers based on current supported list
INSERT INTO auth.providers (slug, name, enabled) VALUES 
('azure', 'Microsoft Entra ID', false),
('google', 'Google Cloud', false),
('github', 'GitHub', false),
('apple', 'Sign in with Apple', false),
('x', 'X (Twitter)', false),
('oidc', 'Generic OpenID Connect', false)
ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name;
