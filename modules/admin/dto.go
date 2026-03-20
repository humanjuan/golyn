package admin

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
)

// SiteDTO represents site information for administration
type SiteDTO struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Host      string    `json:"host"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// AdminUserDTO represents user information for administration
type AdminUserDTO struct {
	ID         string     `json:"id"`
	SiteID     *string    `json:"site_id"`
	SiteKey    *string    `json:"site_key"`
	Username   string     `json:"username"`
	Role       string     `json:"role"`
	Status     string     `json:"status"`
	IsGlobal   bool       `json:"is_global"`
	IsExternal bool       `json:"is_external"`
	CreatedAt  *time.Time `json:"created_at"`
	UpdatedAt  *time.Time `json:"updated_at"`
}

// MapSiteToDTO converts a Site entity to SiteDTO
func MapSiteToDTO(s database.Site) SiteDTO {
	createdAt := time.Time{}
	if s.CreatedAt != nil {
		createdAt = *s.CreatedAt
	}
	return SiteDTO{
		ID:        s.Id,
		Key:       s.Key,
		Host:      s.Host,
		Status:    s.Status,
		CreatedAt: createdAt,
	}
}

// MapAdminUserToDTO converts a User entity to AdminUserDTO
func MapAdminUserToDTO(u database.User) AdminUserDTO {
	return AdminUserDTO{
		ID:         u.Id,
		SiteID:     u.SiteID,
		SiteKey:    u.SiteKey,
		Username:   u.Username,
		Role:       u.Role,
		Status:     u.Status,
		IsGlobal:   u.IsGlobal,
		IsExternal: u.IsExternal,
		CreatedAt:  u.CreatedAt,
		UpdatedAt:  u.UpdatedAt,
	}
}

// SiteConfigDTO represents detailed site configuration for administration
type SiteConfigDTO struct {
	Enabled               bool     `json:"enabled"`
	Directory             string   `json:"directory"`
	Domains               []string `json:"domains"`
	Proxy                 bool     `json:"proxy"`
	ProxyTarget           string   `json:"proxy_target"`
	AllowOrigin           []string `json:"allow_origin"`
	ContentSecurityPolicy string   `json:"content_security_policy"`
	AutoJWT               bool     `json:"auto_jwt"`
	SMTPHost              string   `json:"smtp_host"`
	SMTPPort              int      `json:"smtp_port"`
}

// MapSiteConfigToDTO converts a loaders.SiteConfig to SiteConfigDTO
func MapSiteConfigToDTO(s loaders.SiteConfig) SiteConfigDTO {
	return SiteConfigDTO{
		Enabled:               s.Enabled,
		Directory:             s.Directory,
		Domains:               s.Domains,
		Proxy:                 s.Proxy,
		ProxyTarget:           s.ProxyTarget,
		AllowOrigin:           s.Security.AllowOrigin,
		ContentSecurityPolicy: s.Security.ContentSecurityPolicy,
		AutoJWT:               s.Security.AutoJWT,
		SMTPHost:              s.SMTP.Host,
		SMTPPort:              s.SMTP.Port,
	}
}

// ServerConfigDTO represents global server configuration for SuperAdmin
type ServerConfigDTO struct {
	MainDomain                 string   `json:"main_domain"`
	HTTPPort                   int      `json:"http_port"`
	TLSPort                    int      `json:"tls_port"`
	DevMode                    bool     `json:"dev_mode"`
	TokenExpirationTime        int      `json:"token_expiration_time"`
	TokenExpirationRefreshTime int      `json:"token_expiration_refresh_time"`
	RateLimitRequests          int      `json:"rate_limit_requests"`
	CookieSameSite             string   `json:"cookie_same_site"`
	CookieHttpOnly             bool     `json:"cookie_http_only"`
	CookieSecure               bool     `json:"cookie_secure"`
	CookieDomain               string   `json:"cookie_domain"`
	GlobalWhitelist            []string `json:"global_whitelist"`
	LogLevel                   string   `json:"log_level"`
	LogPath                    string   `json:"log_path"`
	DatabaseHost               string   `json:"database_host"`
	DatabasePort               int      `json:"database_port"`
	DatabaseName               string   `json:"database_name"`
	DatabaseSchema             string   `json:"database_schema"`
}

// ApiKeyDTO represents an API Key for administration
type ApiKeyDTO struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Username   string     `json:"username,omitempty"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  *time.Time `json:"created_at"`
}

// SessionDTO represents an active session
type SessionDTO struct {
	ID        int64      `json:"id"`
	UserID    string     `json:"user_id"`
	Username  string     `json:"username,omitempty"`
	IPAddress string     `json:"ip_address,omitempty"`
	UserAgent string     `json:"user_agent,omitempty"`
	IssuedAt  *time.Time `json:"issued_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// AuthProviderDTO represents an external authentication provider
type AuthProviderDTO struct {
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	ClientID    string    `json:"client_id"`
	RedirectURL string    `json:"redirect_url"`
	TenantID    string    `json:"tenant_id,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SecurityPolicyDTO represents global security policies
type SecurityPolicyDTO struct {
	MainDomain            string   `json:"main_domain"`
	ContentSecurityPolicy string   `json:"content_security_policy"`
	PermissionsPolicy     string   `json:"permissions_policy"`
	RateLimitRequests     int      `json:"rate_limit_requests"`
	GlobalWhitelist       []string `json:"global_whitelist"`
	CookieSettings        gin.H    `json:"cookie_settings"`
}

// MapApiKeyToDTO converts a database.APIKey to ApiKeyDTO
func MapApiKeyToDTO(ak database.APIKey) ApiKeyDTO {
	var scopes []string
	if ak.Scopes != nil {
		_ = json.Unmarshal(ak.Scopes, &scopes)
	}
	return ApiKeyDTO{
		ID:         ak.ID,
		UserID:     ak.UserID,
		Username:   ak.Username,
		Name:       ak.Name,
		Scopes:     scopes,
		ExpiresAt:  ak.ExpiresAt,
		LastUsedAt: ak.LastUsedAt,
		CreatedAt:  ak.CreatedAt,
	}
}

// MapSessionToDTO converts a database.AuthSession to SessionDTO
func MapSessionToDTO(s database.AuthSession) SessionDTO {
	return SessionDTO{
		ID:        s.ID,
		UserID:    s.UserID,
		Username:  s.Username,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		IssuedAt:  s.IssuedAt,
		ExpiresAt: s.ExpiresAt,
	}
}

// MapAuthProviderToDTO converts a database.AuthProvider to AuthProviderDTO
func MapAuthProviderToDTO(p database.AuthProvider) AuthProviderDTO {
	updatedAt := time.Time{}
	if p.UpdatedAt != nil {
		updatedAt = *p.UpdatedAt
	}

	getString := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}

	return AuthProviderDTO{
		Slug:        p.Slug,
		Name:        p.Name,
		Enabled:     p.Enabled,
		ClientID:    getString(p.ClientID),
		RedirectURL: getString(p.RedirectURL),
		TenantID:    getString(p.TenantID),
		UpdatedAt:   updatedAt,
	}
}

// MapServerConfigToDTO converts loaders.Config to ServerConfigDTO
func MapServerConfigToDTO(c *loaders.Config) ServerConfigDTO {
	return ServerConfigDTO{
		MainDomain:                 c.Server.MainDomain,
		HTTPPort:                   c.Server.HTTPPort,
		TLSPort:                    c.Server.TLSPort,
		DevMode:                    c.Server.Dev,
		TokenExpirationTime:        c.Server.TokenExpirationTime,
		TokenExpirationRefreshTime: c.Server.TokenExpirationRefreshTime,
		RateLimitRequests:          c.Server.RateLimitRequests,
		CookieSameSite:             c.Server.CookieSameSite,
		CookieHttpOnly:             c.Server.CookieHttpOnly,
		CookieSecure:               c.Server.CookieSecure,
		CookieDomain:               c.Server.CookieDomain,
		GlobalWhitelist:            c.Server.GlobalWhitelist,
		LogLevel:                   c.Log.Level,
		LogPath:                    c.Log.Path,
		DatabaseHost:               c.Database.Host,
		DatabasePort:               c.Database.Port,
		DatabaseName:               c.Database.Database,
		DatabaseSchema:             c.Database.Schema,
	}
}
