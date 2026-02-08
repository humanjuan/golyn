package auth

import (
	"encoding/json"
	"time"

	"github.com/humanjuan/golyn/database"
)

// UserDTO represents the public user information
type UserDTO struct {
	ID          string      `json:"id"`
	Username    string      `json:"username"`
	Role        string      `json:"role"`
	Status      string      `json:"status"`
	SiteID      *string     `json:"site_id"`
	SiteKey     *string     `json:"site_key,omitempty"`
	Theme       interface{} `json:"theme,omitempty"`
	Permissions interface{} `json:"permissions,omitempty"`
	CreatedAt   *time.Time  `json:"created_at,omitempty"`
	UpdatedAt   *time.Time  `json:"updated_at,omitempty"`
}

// LoginResponse defines the structure for a successful login
type LoginResponse struct {
	Message  string  `json:"message"`
	User     UserDTO `json:"user"`
	Provider string  `json:"provider,omitempty"`
}

// MapUserToDTO converts a database user entity to a DTO
func MapUserToDTO(u database.User) UserDTO {
	var theme interface{}
	if u.Theme != nil {
		_ = json.Unmarshal(u.Theme, &theme)
	}

	var permissions interface{}
	if u.Permissions != nil {
		_ = json.Unmarshal(u.Permissions, &permissions)
	}

	return UserDTO{
		ID:          u.Id,
		Username:    u.Username,
		Role:        u.Role,
		Status:      u.Status,
		SiteID:      u.SiteID,
		SiteKey:     u.SiteKey,
		Theme:       theme,
		Permissions: permissions,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// BuildLoginResponse creates a standardized login response
func BuildLoginResponse(user database.User, provider string) LoginResponse {
	return LoginResponse{
		Message:  "Authentication successful",
		User:     MapUserToDTO(user),
		Provider: provider,
	}
}
