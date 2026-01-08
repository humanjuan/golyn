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
