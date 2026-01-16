package database

import "time"

var Queries = map[string]string{
	"login": `SELECT id, site_id, username, password_hash, role, status, created_at, updated_at FROM auth.users WHERE lower(username) = lower($1)`,

	// External Auth
	"get_external_identity": `SELECT id, user_id, provider, external_id, email, metadata, created_at, updated_at 
                               FROM auth.external_identities 
                               WHERE lower(provider) = lower($1) AND external_id = $2`,
	"get_user_by_email": `SELECT id, site_id, username, password_hash, status, created_at, updated_at 
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
	"get_all_users":     `SELECT id, site_id, username, password_hash, role, status, created_at, updated_at FROM auth.users ORDER BY created_at DESC`,
	"get_users_by_site": `SELECT id, site_id, username, password_hash, role, status, created_at, updated_at FROM auth.users WHERE site_id = $1 ORDER BY username ASC`,
	"create_user":       `INSERT INTO auth.users (site_id, username, password_hash, role) VALUES ($1, $2, $3, $4)`,
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
	"get_user_by_username":    `SELECT id, site_id, username, role, status, theme, permissions, created_at, updated_at FROM auth.users WHERE lower(username) = lower($1)`,
	"get_user_theme":          `SELECT theme FROM auth.users WHERE lower(username) = lower($1)`,
	"update_user_theme":       `UPDATE auth.users SET theme = $1, updated_at = NOW() WHERE lower(username) = lower($2)`,
	"get_user_permissions":    `SELECT permissions FROM auth.users WHERE lower(username) = lower($1)`,
	"update_user_permissions": `UPDATE auth.users SET permissions = $1, updated_at = NOW() WHERE lower(username) = lower($2)`,
	"update_user_status":      `UPDATE auth.users SET status = $1, updated_at = NOW() WHERE lower(username) = lower($2)`,

	// Stats
	"count_total_users":  `SELECT count(*) FROM auth.users`,
	"count_active_sites": `SELECT count(*) FROM core.sites WHERE status = 'active'`,
}

type LoginUser struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type User struct {
	Id           string     `db:"id"`
	SiteID       string     `db:"site_id"`
	Username     string     `db:"username"`
	PasswordHash string     `db:"password_hash"`
	Role         string     `db:"role"`
	Status       string     `db:"status"`
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
