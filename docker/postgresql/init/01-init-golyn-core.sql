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
                            site_id         UUID NOT NULL,
                            username        TEXT NOT NULL,
                            password_hash   TEXT NOT NULL,
                            status          TEXT NOT NULL DEFAULT 'active',
                            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                            updated_at      TIMESTAMPTZ,

                            CONSTRAINT fk_users_site
                                FOREIGN KEY (site_id)
                                    REFERENCES core.sites(id)
                                    ON DELETE CASCADE
);

CREATE UNIQUE INDEX ux_users_site_username
    ON auth.users (site_id, username);

CREATE TABLE auth.refresh_tokens (
                                     id          BIGSERIAL PRIMARY KEY,
                                     user_id     UUID NOT NULL,
                                     token       TEXT NOT NULL,
                                     issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                                     expires_at  TIMESTAMPTZ NOT NULL,
                                     revoked     BOOLEAN NOT NULL DEFAULT false,

                                     CONSTRAINT fk_refresh_tokens_user
                                         FOREIGN KEY (user_id)
                                             REFERENCES auth.users(id)
                                             ON DELETE CASCADE
);

CREATE INDEX ix_refresh_tokens_user
    ON auth.refresh_tokens (user_id);

CREATE INDEX ix_refresh_tokens_token
    ON auth.refresh_tokens (token);

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
