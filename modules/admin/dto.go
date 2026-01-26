package admin

import (
	"time"

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
