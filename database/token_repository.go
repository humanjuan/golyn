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
}

func (dbi *DBInstance) StoreRefreshToken(refreshToken, userID string, expiresAt time.Time) error {
	query := Queries["store_refresh_token"]

	_, err := dbi.db.Exec(context.Background(), query, refreshToken, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("unable to store refresh token: %w", err)
	}

	return nil
}

func (dbi *DBInstance) GetRefreshToken(tokenValue string) (*Token, error) {
	var token Token

	query := Queries["get_refresh_token"]

	row := dbi.db.QueryRow(context.Background(), query, tokenValue)
	err := row.Scan(&token.ID, &token.Token, &token.UserID, &token.Revoked, &token.ExpiresAt)

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

	_, err := dbi.db.Exec(context.Background(), query, userID)
	if err != nil {
		return fmt.Errorf("unable to revoke refresh tokens for user: %v", err)
	}

	return nil
}

func (dbi *DBInstance) RevokeRefreshTokenByID(id int64) error {
	query := `UPDATE auth.refresh_tokens SET revoked = true WHERE id = $1`

	_, err := dbi.db.Exec(context.Background(), query, id)
	if err != nil {
		return fmt.Errorf("unable to revoke refresh token by id: %v", err)
	}

	return nil
}
