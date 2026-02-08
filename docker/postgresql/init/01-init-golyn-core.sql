-- =========================================================
-- Golyn Core Database Initialization
-- PostgreSQL
-- =========================================================

-- ---------------------------------------------------------
-- 1. Create database
-- ---------------------------------------------------------

CREATE DATABASE golyn
    WITH
    OWNER = golyn_user
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.utf8'
    LC_CTYPE = 'en_US.utf8'
    TEMPLATE = template0;

\connect golyn;

-- ---------------------------------------------------------
-- 2. Schemas
-- ---------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS core AUTHORIZATION golyn_user;
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION golyn_user;
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION golyn_user;

-- ---------------------------------------------------------
-- 3. Extensions
-- ---------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =========================================================
-- SCHEMA: core
-- =========================================================

CREATE TABLE core.sites (
                            id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                            key         TEXT NOT NULL UNIQUE,
                            host        TEXT NOT NULL UNIQUE,
                            status      TEXT NOT NULL DEFAULT 'active',
                            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================
-- SCHEMA: auth
-- =========================================================

CREATE TABLE auth.users (
                            id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                            site_id         UUID, -- NULL means Global User
                            username        TEXT NOT NULL,
                            password_hash   TEXT NOT NULL,
                            role            TEXT NOT NULL DEFAULT 'user', -- 'SuperAdmin', 'Admin', 'user'
                            status          TEXT NOT NULL DEFAULT 'active',
                            is_global       BOOLEAN NOT NULL DEFAULT true,
                            is_external     BOOLEAN NOT NULL DEFAULT false,
                            theme           JSONB,
                            permissions     JSONB,
                            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                            updated_at      TIMESTAMPTZ,

                            CONSTRAINT fk_users_site
                                FOREIGN KEY (site_id)
                                    REFERENCES core.sites(id)
                                    ON DELETE CASCADE
);

-- Unique index for restricted users (site_id, username)
CREATE UNIQUE INDEX ux_users_site_username
    ON auth.users (site_id, username)
    WHERE site_id IS NOT NULL;

-- Unique index for global users (username)
CREATE UNIQUE INDEX ux_users_global_username
    ON auth.users (username)
    WHERE site_id IS NULL;

CREATE TABLE auth.refresh_tokens (
                                     id          BIGSERIAL PRIMARY KEY,
                                     user_id     UUID NOT NULL,
                                     token       TEXT NOT NULL,
                                     issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                                     expires_at  TIMESTAMPTZ NOT NULL,
                                     revoked     BOOLEAN NOT NULL DEFAULT false,
                                     ip_address  INET,
                                     user_agent  TEXT,

                                     CONSTRAINT fk_refresh_tokens_user
                                         FOREIGN KEY (user_id)
                                             REFERENCES auth.users(id)
                                             ON DELETE CASCADE
);

CREATE TABLE auth.external_identities (
                                          id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                          user_id         UUID NOT NULL,
                                          provider        TEXT NOT NULL, -- 'azure', 'google', 'github', etc.
                                          external_id     TEXT NOT NULL, -- ID unique from the provider
                                          email           TEXT,
                                          metadata        JSONB,
                                          created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                                          updated_at      TIMESTAMPTZ,

                                          CONSTRAINT fk_external_identities_user
                                              FOREIGN KEY (user_id)
                                                  REFERENCES auth.users(id)
                                                  ON DELETE CASCADE,

                                          CONSTRAINT ux_external_provider_id
                                              UNIQUE (provider, external_id)
);

CREATE TABLE IF NOT EXISTS auth.admin_sites (
                                                user_id     UUID NOT NULL,
                                                site_id     UUID NOT NULL,
                                                created_at  TIMESTAMPTZ DEFAULT now(),

                                                PRIMARY KEY (user_id, site_id),
                                                CONSTRAINT fk_admin_sites_user FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE,
                                                CONSTRAINT fk_admin_sites_site FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth.user_allowed_sites (
                                                      user_id     UUID NOT NULL,
                                                      site_id     UUID NOT NULL,
                                                      created_at  TIMESTAMPTZ DEFAULT now(),

                                                      PRIMARY KEY (user_id, site_id),
                                                      CONSTRAINT fk_user_allowed_sites_user FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE,
                                                      CONSTRAINT fk_user_allowed_sites_site FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE
);

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

-- Insert initial providers
INSERT INTO auth.providers (slug, name, enabled) VALUES
                                                     ('azure', 'Microsoft Entra ID', false),
                                                     ('google', 'Google Cloud', false),
                                                     ('github', 'GitHub', false),
                                                     ('apple', 'Sign in with Apple', false),
                                                     ('linkedin', 'LinkedIn', false),
                                                     ('facebook', 'Facebook (Meta)', false),
                                                     ('amazon', 'Amazon', false),
                                                     ('salesforce', 'SalesForce', false),
                                                     ('x', 'X (Twitter)', false),
                                                     ('oidc', 'Generic OpenID Connect', false)
ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name;

CREATE INDEX ix_external_identities_user
    ON auth.external_identities (user_id);

CREATE INDEX ix_refresh_tokens_user
    ON auth.refresh_tokens (user_id);

CREATE INDEX ix_refresh_tokens_token
    ON auth.refresh_tokens (token);

CREATE INDEX ix_api_keys_user ON auth.api_keys (user_id);

-- =========================================================
-- SCHEMA: audit
-- =========================================================

CREATE TABLE audit.auth_events (
                                   id          BIGSERIAL PRIMARY KEY,
                                   user_id     UUID,
                                   site_id     UUID,
                                   event       TEXT NOT NULL,
                                   ip_address  INET,
                                   user_agent  TEXT,
                                   created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------
-- 4. Permissions
-- ---------------------------------------------------------

GRANT CONNECT ON DATABASE golyn TO golyn_user;
GRANT USAGE ON SCHEMA core, auth, audit TO golyn_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core, auth, audit TO golyn_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA core, auth, audit TO golyn_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA core, auth, audit
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO golyn_user;
