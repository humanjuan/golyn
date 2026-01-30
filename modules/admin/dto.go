package admin

import (
	"time"

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
	ID        string     `json:"id"`
	SiteID    string     `json:"site_id"`
	SiteKey   string     `json:"site_key"`
	Username  string     `json:"username"`
	Role      string     `json:"role"`
	Status    string     `json:"status"`
	CreatedAt *time.Time `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`
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
		ID:        u.Id,
		SiteID:    u.SiteID,
		SiteKey:   u.SiteKey,
		Username:  u.Username,
		Role:      u.Role,
		Status:    u.Status,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
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
	Port                       int      `json:"port"`
	DevMode                    bool     `json:"dev_mode"`
	TokenExpirationTime        int      `json:"token_expiration_time"`
	TokenExpirationRefreshTime int      `json:"token_expiration_refresh_time"`
	RateLimitRequests          int      `json:"rate_limit_requests"`
	CookieSameSite             string   `json:"cookie_same_site"`
	CookieHttpOnly             bool     `json:"cookie_http_only"`
	CookieSecure               bool     `json:"cookie_secure"`
	GlobalWhitelist            []string `json:"global_whitelist"`
	LogLevel                   string   `json:"log_level"`
	LogPath                    string   `json:"log_path"`
	DatabaseHost               string   `json:"database_host"`
	DatabasePort               int      `json:"database_port"`
	DatabaseName               string   `json:"database_name"`
	DatabaseSchema             string   `json:"database_schema"`
}

// MapServerConfigToDTO converts loaders.Config to ServerConfigDTO
func MapServerConfigToDTO(c *loaders.Config) ServerConfigDTO {
	return ServerConfigDTO{
		Port:                       c.Server.Port,
		DevMode:                    c.Server.Dev,
		TokenExpirationTime:        c.Server.TokenExpirationTime,
		TokenExpirationRefreshTime: c.Server.TokenExpirationRefreshTime,
		RateLimitRequests:          c.Server.RateLimitRequests,
		CookieSameSite:             c.Server.CookieSameSite,
		CookieHttpOnly:             c.Server.CookieHttpOnly,
		CookieSecure:               c.Server.CookieSecure,
		GlobalWhitelist:            c.Server.GlobalWhitelist,
		LogLevel:                   c.Log.Level,
		LogPath:                    c.Log.Path,
		DatabaseHost:               c.Database.Host,
		DatabasePort:               c.Database.Port,
		DatabaseName:               c.Database.Database,
		DatabaseSchema:             c.Database.Schema,
	}
}
