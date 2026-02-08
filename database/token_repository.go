package database

import (
	"context"
	"fmt"
	"time"
)

type Token struct {
	ID        int64
	UserID    string
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Revoked   bool
	IPAddress string
	UserAgent string
}

func (dbi *DBInstance) StoreRefreshToken(refreshToken, userID string, expiresAt time.Time, ip, ua string) (int64, error) {
	query := `INSERT INTO auth.refresh_tokens (token, user_id, issued_at, expires_at, revoked, ip_address, user_agent) VALUES ($1, $2, NOW(), $3, false, $4, $5) RETURNING id`

	var id int64
	err := dbi.QueryRow(context.Background(), query, refreshToken, userID, expiresAt, ip, ua).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("unable to store refresh token: %w", err)
	}

	return id, nil
}

func (dbi *DBInstance) GetRefreshToken(tokenValue string) (*Token, error) {
	var token Token

	query := `SELECT id, token, user_id, revoked, expires_at, COALESCE(ip_address::text, ''), COALESCE(user_agent, '') FROM auth.refresh_tokens WHERE token = $1`

	row := dbi.QueryRow(context.Background(), query, tokenValue)
	err := row.Scan(&token.ID, &token.Token, &token.UserID, &token.Revoked, &token.ExpiresAt, &token.IPAddress, &token.UserAgent)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, fmt.Errorf("token not found: %w", err)
		}
		return nil, fmt.Errorf("unable to get refresh token: %w", err)
	}

	return &token, nil
}

func (dbi *DBInstance) RevokeAllUserRefreshTokens(userID string) error {
	query := `UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1`

	_, err := dbi.Exec(context.Background(), query, userID)
	if err != nil {
		return fmt.Errorf("unable to revoke refresh tokens for user: %v", err)
	}

	return nil
}

func (dbi *DBInstance) RevokeRefreshTokenByID(id int64) error {
	query := `UPDATE auth.refresh_tokens SET revoked = true WHERE id = $1`

	_, err := dbi.Exec(context.Background(), query, id)
	if err != nil {
		return fmt.Errorf("unable to revoke refresh token by id: %v", err)
	}

	return nil
}

// API Keys

func (dbi *DBInstance) GetAllAPIKeys() ([]APIKey, error) {
	var keys []APIKey
	err := dbi.Select(Queries["get_all_api_keys"], &keys)
	return keys, err
}

func (dbi *DBInstance) GetAPIKeysByUser(userID string) ([]APIKey, error) {
	var keys []APIKey
	err := dbi.Select(Queries["get_api_keys"], &keys, userID)
	return keys, err
}

func (dbi *DBInstance) CreateAPIKey(userID, name, keyHash string, scopes []byte, expiresAt *time.Time) error {
	_, err := dbi.Exec(context.Background(), Queries["create_api_key"], userID, name, keyHash, scopes, expiresAt)
	return err
}

func (dbi *DBInstance) DeleteAPIKey(id string) error {
	_, err := dbi.Exec(context.Background(), Queries["delete_api_key"], id)
	return err
}

// Sessions

func (dbi *DBInstance) GetActiveSessions() ([]AuthSession, error) {
	var sessions []AuthSession
	err := dbi.Select(Queries["get_active_sessions"], &sessions)
	return sessions, err
}

func (dbi *DBInstance) GetUserSessions(userID string) ([]AuthSession, error) {
	var sessions []AuthSession
	err := dbi.Select(Queries["get_user_sessions"], &sessions, userID)
	return sessions, err
}

// Auth Providers

func (dbi *DBInstance) GetAuthProviders() ([]AuthProvider, error) {
	var providers []AuthProvider
	err := dbi.Select(Queries["get_auth_providers"], &providers)
	return providers, err
}

func (dbi *DBInstance) UpdateAuthProvider(slug, clientID, clientSecret, redirectURL, tenantID string) error {
	_, err := dbi.Exec(context.Background(), Queries["update_auth_provider"], clientID, clientSecret, redirectURL, tenantID, slug)
	return err
}

func (dbi *DBInstance) UpdateAuthProviderStatus(slug string, enabled bool) error {
	_, err := dbi.Exec(context.Background(), Queries["update_provider_status"], enabled, slug)
	return err
}

func (dbi *DBInstance) GetAuthProviderBySlug(slug string) (*AuthProvider, error) {
	var providers []AuthProvider
	err := dbi.Select(Queries["get_auth_provider_by_slug"], &providers, slug)
	if err != nil {
		return nil, err
	}
	if len(providers) == 0 {
		return nil, nil
	}
	return &providers[0], nil
}
