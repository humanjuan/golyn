-- Migration: 07-add-external-sessions.sql
-- Description: Add support for storing external provider tokens securely

CREATE TABLE IF NOT EXISTS auth.external_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      BIGINT NOT NULL, -- FK to auth.refresh_tokens.id
    provider        TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    access_token    TEXT, -- Encrypted
    refresh_token   TEXT, -- Encrypted
    id_token        TEXT, -- Encrypted (for OIDC SLO)
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_external_sessions_refresh_token
        FOREIGN KEY (session_id)
        REFERENCES auth.refresh_tokens(id)
        ON DELETE CASCADE
);

CREATE INDEX ix_external_sessions_session_id ON auth.external_sessions (session_id);
