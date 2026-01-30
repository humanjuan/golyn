package database

import (
	"context"
)

func (dbi *DBInstance) GetAllSites() ([]Site, error) {
	var sites []Site
	query := Queries["get_all_sites"]
	err := dbi.Select(query, &sites)
	return sites, err
}

func (dbi *DBInstance) GetSiteByKey(key string) (*Site, error) {
	var sites []Site
	query := Queries["get_site_by_key"]
	err := dbi.Select(query, &sites, key)
	if err != nil {
		return nil, err
	}
	if len(sites) == 0 {
		return nil, nil
	}
	return &sites[0], nil
}

func (dbi *DBInstance) CreateSite(key, host string) error {
	query := Queries["create_site"]
	_, err := dbi.db.Exec(context.Background(), query, key, host)
	return err
}

func (dbi *DBInstance) DeleteSite(key string) error {
	query := Queries["delete_site"]
	_, err := dbi.db.Exec(context.Background(), query, key)
	return err
}

func (dbi *DBInstance) UpdateSiteStatus(key, status string) error {
	query := Queries["update_site_status"]
	_, err := dbi.db.Exec(context.Background(), query, status, key)
	return err
}

func (dbi *DBInstance) GetUserByUsername(username string) (*User, error) {
	var users []User
	query := Queries["get_user_by_username"]
	err := dbi.Select(query, &users, username)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, nil
	}
	return &users[0], nil
}

func (dbi *DBInstance) GetAllUsers() ([]User, error) {
	var users []User
	query := Queries["get_all_users"]
	err := dbi.Select(query, &users)
	return users, err
}

func (dbi *DBInstance) GetUsersBySite(siteID string) ([]User, error) {
	var users []User
	query := Queries["get_users_by_site"]
	err := dbi.Select(query, &users, siteID)
	return users, err
}

func (dbi *DBInstance) CreateUser(siteID, username, passwordHash, role string) error {
	query := Queries["create_user"]
	_, err := dbi.db.Exec(context.Background(), query, siteID, username, passwordHash, role)
	return err
}

func (dbi *DBInstance) UpdateUserRole(username, role string) error {
	query := Queries["update_user_role"]
	_, err := dbi.db.Exec(context.Background(), query, role, username)
	return err
}

func (dbi *DBInstance) DeleteUser(username string) error {
	query := Queries["delete_user"]
	_, err := dbi.db.Exec(context.Background(), query, username)
	return err
}

func (dbi *DBInstance) UpdateUserStatus(username, status string) error {
	query := Queries["update_user_status"]
	_, err := dbi.db.Exec(context.Background(), query, status, username)
	return err
}

func (dbi *DBInstance) GetUserPermissions(username string) ([]byte, error) {
	var results []struct {
		Permissions []byte `db:"permissions"`
	}
	query := Queries["get_user_permissions"]
	err := dbi.Select(query, &results, username)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results[0].Permissions, nil
}

func (dbi *DBInstance) UpdateUserPermissions(username string, permissions []byte) error {
	query := Queries["update_user_permissions"]
	_, err := dbi.db.Exec(context.Background(), query, permissions, username)
	return err
}

func (dbi *DBInstance) AssignSiteToAdmin(userID, siteID string) error {
	query := Queries["assign_site_to_admin"]
	_, err := dbi.db.Exec(context.Background(), query, userID, siteID)
	return err
}

func (dbi *DBInstance) RevokeSiteFromAdmin(userID, siteID string) error {
	query := Queries["revoke_site_from_admin"]
	_, err := dbi.db.Exec(context.Background(), query, userID, siteID)
	return err
}

func (dbi *DBInstance) GetAdminSites(userID string) ([]Site, error) {
	var sites []Site
	query := Queries["get_admin_sites"]
	err := dbi.Select(query, &sites, userID)
	return sites, err
}
