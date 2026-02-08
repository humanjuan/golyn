package database

import (
	"context"
	"time"
)

type ExternalSession struct {
	ID             string     `db:"id"`
	SessionID      int64      `db:"session_id"`
	Provider       string     `db:"provider"`
	ProviderUserID string     `db:"provider_user_id"`
	AccessToken    string     `db:"access_token"`
	RefreshToken   string     `db:"refresh_token"`
	IDToken        string     `db:"id_token"`
	ExpiresAt      *time.Time `db:"expires_at"`
	CreatedAt      *time.Time `db:"created_at"`
	UpdatedAt      *time.Time `db:"updated_at"`
}

// StoreExternalSession saves or updates an external session bound to a Golyn session (refresh_token id)
func (dbi *DBInstance) StoreExternalSession(sessionID int64, provider, providerUserID, accessTokenEnc, refreshTokenEnc, idTokenEnc string, expiresAt *time.Time) error {
	// Upsert by (session_id, provider)
	_, _ = dbi.Exec(context.Background(), "DELETE FROM auth.external_sessions WHERE session_id = $1 AND lower(provider) = lower($2)", sessionID, provider)
	_, err := dbi.Exec(context.Background(),
		"INSERT INTO auth.external_sessions (session_id, provider, provider_user_id, access_token, refresh_token, id_token, expires_at) VALUES ($1, lower($2), $3, $4, $5, $6, $7)",
		sessionID, provider, providerUserID, accessTokenEnc, refreshTokenEnc, idTokenEnc, expiresAt,
	)
	return err
}

// GetExternalSessionBySessionID returns the external session associated with a Golyn session id (if any)
func (dbi *DBInstance) GetExternalSessionBySessionID(sessionID int64) (*ExternalSession, error) {
	var rows []ExternalSession
	err := dbi.Select("SELECT id, session_id, provider, provider_user_id, access_token, refresh_token, id_token, expires_at, created_at, updated_at FROM auth.external_sessions WHERE session_id = $1 ORDER BY created_at DESC LIMIT 1", &rows, sessionID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}
