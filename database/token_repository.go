package database

import (
	"context"
	"fmt"
	"time"
)

type Token struct {
	ID        string
	Token     string
	Username  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Status    bool
}

func (dbi *DBInstance) StoreRefreshToken(refreshToken, username string, expiresAt time.Time) error {
	query := `INSERT INTO golyn.refresh_tokens (token, username, issued_at, expires_at, status) VALUES ($1, $2, NOW(), $3, true)`

	_, err := dbi.db.Exec(context.Background(), query, refreshToken, username, expiresAt)
	if err != nil {
		return fmt.Errorf("unable to store refresh token: %w", err)
	}

	return nil
}

func (dbi *DBInstance) GetRefreshToken(tokenValue string) (*Token, error) {
	var token Token

	query := `SELECT id, token, status, expires_at FROM golyn.refresh_tokens WHERE token = $1`

	row := dbi.db.QueryRow(context.Background(), query, tokenValue)
	err := row.Scan(&token.ID, &token.Username, &token.Status, &token.ExpiresAt)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, fmt.Errorf("token not found: %w", err)
		}
		return nil, fmt.Errorf("unable to get refresh token: %w", err)
	}

	return &token, nil
}

func (dbi *DBInstance) RevokeRefreshToken(username string) error {
	query := `UPDATE golyn.refresh_tokens SET status = false WHERE username = $1`

	_, err := dbi.db.Exec(context.Background(), query, username)
	if err != nil {
		return fmt.Errorf("unable to revoke refresh token: %v", err)
	}

	return nil
}
