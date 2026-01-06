package database

import "time"

var Queries = map[string]string{
	"login": `SELECT id, site_id, username, password_hash, status, created_at, updated_at FROM auth.users WHERE lower(username) = lower($1)`,
}

type LoginUser struct {
	Name     string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	Id           string     `db:"id"`
	SiteID       string     `db:"site_id"`
	Username     string     `db:"username"`
	PasswordHash string     `db:"password_hash"`
	Status       string     `db:"status"`
	CreatedAt    *time.Time `db:"created_at"`
	UpdatedAt    *time.Time `db:"updated_at"`
}
