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
	_, err := dbi.Exec(context.Background(), query, key, host)
	return err
}

func (dbi *DBInstance) DeleteSite(key string) error {
	query := Queries["delete_site"]
	_, err := dbi.Exec(context.Background(), query, key)
	return err
}

func (dbi *DBInstance) UpdateSiteStatus(key, status string) error {
	query := Queries["update_site_status"]
	_, err := dbi.Exec(context.Background(), query, status, key)
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

func (dbi *DBInstance) CreateUser(siteID *string, username, passwordHash, role string, isGlobal, isExternal bool) error {
	query := Queries["create_user"]
	_, err := dbi.Exec(context.Background(), query, siteID, username, passwordHash, role, isGlobal, isExternal)
	return err
}

func (dbi *DBInstance) UpdateUserRole(username, role string) error {
	query := Queries["update_user_role"]
	_, err := dbi.Exec(context.Background(), query, role, username)
	return err
}

func (dbi *DBInstance) DeleteUser(username string) error {
	query := Queries["delete_user"]
	_, err := dbi.Exec(context.Background(), query, username)
	return err
}

func (dbi *DBInstance) UpdateUserStatus(username, status string) error {
	query := Queries["update_user_status"]
	_, err := dbi.Exec(context.Background(), query, status, username)
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
	_, err := dbi.Exec(context.Background(), query, permissions, username)
	return err
}

func (dbi *DBInstance) AssignSiteToAdmin(userID, siteID string) error {
	query := Queries["assign_site_to_admin"]
	_, err := dbi.Exec(context.Background(), query, userID, siteID)
	return err
}

func (dbi *DBInstance) RevokeSiteFromAdmin(userID, siteID string) error {
	query := Queries["revoke_site_from_admin"]
	_, err := dbi.Exec(context.Background(), query, userID, siteID)
	return err
}

func (dbi *DBInstance) GetAdminSites(userID string) ([]Site, error) {
	var sites []Site
	query := Queries["get_admin_sites"]
	err := dbi.Select(query, &sites, userID)
	return sites, err
}

func (dbi *DBInstance) GetUserAllowedSites(userID string) ([]Site, error) {
	var sites []Site
	query := Queries["get_user_allowed_sites"]
	err := dbi.Select(query, &sites, userID)
	return sites, err
}

func (dbi *DBInstance) AddAllowedSiteToUser(userID, siteID string) error {
	query := Queries["add_allowed_site_to_user"]
	_, err := dbi.Exec(context.Background(), query, userID, siteID)
	return err
}

func (dbi *DBInstance) RemoveAllowedSiteFromUser(userID, siteID string) error {
	query := Queries["remove_allowed_site_from_user"]
	_, err := dbi.Exec(context.Background(), query, userID, siteID)
	return err
}

func (dbi *DBInstance) IsSiteAllowedForUser(userID, siteID string) (bool, error) {
	query := Queries["is_site_allowed_for_user"]
	var allowed bool
	err := dbi.QueryRow(context.Background(), query, userID, siteID).Scan(&allowed)
	return allowed, err
}

func (dbi *DBInstance) UpdateUserGlobalStatus(username string, isGlobal bool) error {
	query := Queries["update_user_global_status"]
	_, err := dbi.Exec(context.Background(), query, isGlobal, username)
	return err
}
