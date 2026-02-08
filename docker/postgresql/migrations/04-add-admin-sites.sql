-- =========================================================
-- Migration: Add Admin Sites Relationship
-- Allows an Admin to manage multiple sites
-- =========================================================

CREATE TABLE IF NOT EXISTS auth.admin_sites (
    user_id     UUID NOT NULL,
    site_id     UUID NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now(),
    
    PRIMARY KEY (user_id, site_id),
    CONSTRAINT fk_admin_sites_user FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE,
    CONSTRAINT fk_admin_sites_site FOREIGN KEY (site_id) REFERENCES core.sites(id) ON DELETE CASCADE
);

-- Grant permissions
GRANT SELECT, INSERT, DELETE ON TABLE auth.admin_sites TO golyn_user;
