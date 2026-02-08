package database

import "time"

var Queries = map[string]string{
	"login": `SELECT id, site_id, username, password_hash, role, status, is_global, created_at, updated_at FROM auth.users WHERE lower(username) = lower($1)`,

	// External Auth
	"get_external_identity": `SELECT id, user_id, provider, external_id, email, metadata, created_at, updated_at 
                               FROM auth.external_identities 
                               WHERE lower(provider) = lower($1) AND external_id = $2`,
	"get_user_by_email": `SELECT id, site_id, username, password_hash, status, is_global, created_at, updated_at 
                          FROM auth.users 
                          WHERE lower(username) = lower($1)`,
	"link_external_identity": `INSERT INTO auth.external_identities (user_id, provider, external_id, email, metadata, created_at) 
                               VALUES ($1, lower($2), $3, $4, $5, NOW()) 
                               ON CONFLICT (provider, external_id) DO UPDATE SET 
                                   email = EXCLUDED.email, 
                                   metadata = EXCLUDED.metadata, 
                                   updated_at = NOW()`,
	"register_auth_event": `INSERT INTO audit.auth_events (user_id, site_id, event, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5)`,

	// Admin - Sites
	"get_all_sites":      `SELECT id, key, host, status, created_at FROM core.sites ORDER BY created_at DESC`,
	"get_site_by_key":    `SELECT id, key, host, status, created_at FROM core.sites WHERE key = $1`,
	"create_site":        `INSERT INTO core.sites (key, host) VALUES ($1, $2)`,
	"delete_site":        `DELETE FROM core.sites WHERE key = $1`,
	"update_site_status": `UPDATE core.sites SET status = $1 WHERE key = $2`,
	"get_site_by_host":   `SELECT id FROM core.sites WHERE lower(host) = lower($1)`,

	// Admin - Users
	"get_all_users":     `SELECT u.id, u.site_id, s.key as site_key, u.username, u.password_hash, u.role, u.status, u.is_global, u.created_at, u.updated_at, (u.is_external OR EXISTS(SELECT 1 FROM auth.external_identities ei WHERE ei.user_id = u.id)) as is_external FROM auth.users u LEFT JOIN core.sites s ON u.site_id = s.id ORDER BY u.created_at DESC`,
	"get_users_by_site": `SELECT DISTINCT u.id, u.site_id, s.key as site_key, u.username, u.password_hash, u.role, u.status, u.is_global, u.created_at, u.updated_at, (u.is_external OR EXISTS(SELECT 1 FROM auth.external_identities ei WHERE ei.user_id = u.id)) as is_external FROM auth.users u LEFT JOIN core.sites s ON u.site_id = s.id LEFT JOIN auth.user_allowed_sites uas ON u.id = uas.user_id WHERE u.site_id = $1 OR uas.site_id = $1 ORDER BY u.username ASC`,
	"create_user":       `INSERT INTO auth.users (site_id, username, password_hash, role, is_global, is_external) VALUES ($1, $2, $3, $4, $5, $6)`,
	"update_user_role":  `UPDATE auth.users SET role = $1, updated_at = NOW() WHERE lower(username) = lower($2)`,
	"delete_user":       `DELETE FROM auth.users WHERE lower(username) = lower($1)`,

	// Tokens
	"store_refresh_token":     `INSERT INTO auth.refresh_tokens (token, user_id, issued_at, expires_at, revoked) VALUES ($1, $2, NOW(), $3, false)`,
	"get_refresh_token":       `SELECT id, token, user_id, revoked, expires_at FROM auth.refresh_tokens WHERE token = $1`,
	"revoke_user_tokens":      `UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1`,
	"revoke_refresh_token_id": `UPDATE auth.refresh_tokens SET revoked = true WHERE id = $1`,

	// Others
	"get_db_version":          `SELECT version()`,
	"get_user_role":           `SELECT role FROM auth.users WHERE lower(username) = lower($1)`,
	"get_user_by_username":    `SELECT id, site_id, username, role, status, is_global, theme, permissions, created_at, updated_at FROM auth.users WHERE lower(username) = lower($1)`,
	"get_user_theme":          `SELECT theme FROM auth.users WHERE lower(username) = lower($1)`,
	"update_user_theme":       `UPDATE auth.users SET theme = $1, updated_at = NOW() WHERE lower(username) = lower($2)`,
	"get_user_permissions":    `SELECT permissions FROM auth.users WHERE lower(username) = lower($1)`,
	"update_user_permissions": `UPDATE auth.users SET permissions = $1, updated_at = NOW() WHERE lower(username) = lower($2)`,
	"update_user_status":      `UPDATE auth.users SET status = $1, updated_at = NOW() WHERE lower(username) = lower($2)`,

	// Stats
	"count_total_users":  `SELECT count(*) FROM auth.users`,
	"count_active_sites": `SELECT count(*) FROM core.sites WHERE status = 'active'`,

	// Admin - Admin Sites (Multi-tenancy)
	"assign_site_to_admin":   `INSERT INTO auth.admin_sites (user_id, site_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
	"revoke_site_from_admin": `DELETE FROM auth.admin_sites WHERE user_id = $1 AND site_id = $2`,
	"get_admin_sites":        `SELECT s.id, s.key, s.host, s.status, s.created_at FROM core.sites s JOIN auth.admin_sites asit ON s.id = asit.site_id WHERE asit.user_id = $1`,

	// API Keys
	"get_api_keys":     `SELECT id, user_id, name, scopes, expires_at, last_used_at, created_at FROM auth.api_keys WHERE user_id = $1 ORDER BY created_at DESC`,
	"create_api_key":   `INSERT INTO auth.api_keys (user_id, name, key_hash, scopes, expires_at) VALUES ($1, $2, $3, $4, $5)`,
	"delete_api_key":   `DELETE FROM auth.api_keys WHERE id = $1`,
	"get_all_api_keys": `SELECT ak.id, ak.user_id, u.username, ak.name, ak.scopes, ak.expires_at, ak.last_used_at, ak.created_at FROM auth.api_keys ak JOIN auth.users u ON ak.user_id = u.id ORDER BY ak.created_at DESC`,

	// Sessions (Refresh Tokens as proxy for sessions)
	"get_active_sessions": `SELECT rt.id, rt.user_id, u.username, rt.issued_at, rt.expires_at, rt.ip_address::TEXT, rt.user_agent FROM auth.refresh_tokens rt JOIN auth.users u ON rt.user_id = u.id WHERE rt.revoked = false AND rt.expires_at > NOW() ORDER BY rt.issued_at DESC`,
	"get_user_sessions":   `SELECT id, user_id, issued_at, expires_at, ip_address::TEXT, user_agent FROM auth.refresh_tokens WHERE user_id = $1 AND revoked = false AND expires_at > NOW() ORDER BY issued_at DESC`,

	// Auth Providers
	"get_auth_providers":        `SELECT slug, name, enabled, client_id, client_secret, redirect_url, tenant_id, metadata::TEXT, updated_at FROM auth.providers ORDER BY name ASC`,
	"update_auth_provider":      `UPDATE auth.providers SET client_id = $1, client_secret = $2, redirect_url = $3, tenant_id = $4, updated_at = NOW() WHERE slug = $5`,
	"update_provider_status":    `UPDATE auth.providers SET enabled = $1, updated_at = NOW() WHERE slug = $2`,
	"get_auth_provider_by_slug": `SELECT slug, name, enabled, client_id, client_secret, redirect_url, tenant_id, metadata::TEXT, updated_at FROM auth.providers WHERE slug = $1`,

	// User Allowed Sites
	"get_user_allowed_sites":        `SELECT s.id, s.key, s.host, s.status, s.created_at FROM core.sites s JOIN auth.user_allowed_sites uas ON s.id = uas.site_id WHERE uas.user_id = $1`,
	"add_allowed_site_to_user":      `INSERT INTO auth.user_allowed_sites (user_id, site_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
	"remove_allowed_site_from_user": `DELETE FROM auth.user_allowed_sites WHERE user_id = $1 AND site_id = $2`,
	"is_site_allowed_for_user":      `SELECT EXISTS(SELECT 1 FROM auth.user_allowed_sites WHERE user_id = $1 AND site_id = $2)`,
	"update_user_global_status":     `UPDATE auth.users SET is_global = $1, updated_at = NOW() WHERE lower(username) = lower($2)`,
}

type LoginUser struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type User struct {
	Id           string     `db:"id"`
	SiteID       *string    `db:"site_id"`
	SiteKey      *string    `db:"site_key"`
	Username     string     `db:"username"`
	PasswordHash string     `db:"password_hash"`
	Role         string     `db:"role"`
	Status       string     `db:"status"`
	IsGlobal     bool       `db:"is_global"`
	IsExternal   bool       `db:"is_external"`
	Theme        []byte     `db:"theme"`
	Permissions  []byte     `db:"permissions"`
	CreatedAt    *time.Time `db:"created_at"`
	UpdatedAt    *time.Time `db:"updated_at"`
}

type ExternalIdentity struct {
	Id         string     `db:"id"`
	UserId     string     `db:"user_id"`
	Provider   string     `db:"provider"`
	ExternalId string     `db:"external_id"`
	Email      string     `db:"email"`
	Metadata   []byte     `db:"metadata"`
	CreatedAt  *time.Time `db:"created_at"`
	UpdatedAt  *time.Time `db:"updated_at"`
}

type Site struct {
	Id        string     `db:"id"`
	Key       string     `db:"key"`
	Host      string     `db:"host"`
	Status    string     `db:"status"`
	CreatedAt *time.Time `db:"created_at"`
}

type APIKey struct {
	ID         string     `db:"id"`
	UserID     string     `db:"user_id"`
	Username   string     `db:"username"`
	Name       string     `db:"name"`
	Scopes     []byte     `db:"scopes"`
	ExpiresAt  *time.Time `db:"expires_at"`
	LastUsedAt *time.Time `db:"last_used_at"`
	CreatedAt  *time.Time `db:"created_at"`
}

type AuthSession struct {
	ID        int64      `db:"id"`
	UserID    string     `db:"user_id"`
	Username  string     `db:"username"`
	IPAddress string     `db:"ip_address"`
	UserAgent string     `db:"user_agent"`
	IssuedAt  *time.Time `db:"issued_at"`
	ExpiresAt *time.Time `db:"expires_at"`
}

type AuthProvider struct {
	Slug         string     `db:"slug"`
	Name         string     `db:"name"`
	Enabled      bool       `db:"enabled"`
	ClientID     *string    `db:"client_id"`
	ClientSecret *string    `db:"client_secret"`
	RedirectURL  *string    `db:"redirect_url"`
	TenantID     *string    `db:"tenant_id"`
	Metadata     *string    `db:"metadata"`
	UpdatedAt    *time.Time `db:"updated_at"`
}
