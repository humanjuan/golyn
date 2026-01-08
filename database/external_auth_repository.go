package database

import (
	"context"
	"fmt"
)

func (dbi *DBInstance) GetExternalIdentity(provider, externalID string) (*ExternalIdentity, error) {
	var identity ExternalIdentity
	query := Queries["get_external_identity"]

	row := dbi.db.QueryRow(context.Background(), query, provider, externalID)
	err := row.Scan(
		&identity.Id,
		&identity.UserId,
		&identity.Provider,
		&identity.ExternalId,
		&identity.Email,
		&identity.Metadata,
		&identity.CreatedAt,
		&identity.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("unable to get external identity: %w", err)
	}

	return &identity, nil
}

func (dbi *DBInstance) GetUserByEmail(email string) (*User, error) {
	var users []User
	query := Queries["get_user_by_email"]

	err := dbi.Select(query, &users, email)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return &users[0], nil
}

func (dbi *DBInstance) LinkExternalIdentity(userID, provider, externalID, email string, metadata []byte) error {
	query := Queries["link_external_identity"]

	_, err := dbi.db.Exec(context.Background(), query, userID, provider, externalID, email, metadata)
	if err != nil {
		return fmt.Errorf("unable to link external identity: %w", err)
	}

	return nil
}

func (dbi *DBInstance) RegisterAuthEvent(userID, siteID *string, event, ip, userAgent string) error {
	query := Queries["register_auth_event"]
	_, err := dbi.db.Exec(context.Background(), query, userID, siteID, event, ip, userAgent)
	return err
}
