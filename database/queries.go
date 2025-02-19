package database

import "time"

var Queries = map[string]string{
	"login":         `SELECT id, first_name, last_name, alias, age, email, password, city, country, country_code, player_status, galleta_status, developer, last_update, created FROM golyn.users INNER JOIN golyn.countries ON country_name = country WHERE lower(email) = lower($1)`,
	"get_countries": `SELECT country_code, country_name FROM golyn.countries;`,
}

type LoginUser struct {
	Name     string `json:"username"`
	Password string `json:"password"`
}

type Country struct {
	Code string `db:"country_code"`
	Name string `db:"country_name"`
}

type User struct {
	Id            string     `db:"id"`
	FirstName     string     `db:"first_name"`
	LastName      string     `db:"last_name"`
	Alias         string     `db:"alias"`
	Age           int        `db:"age"`
	Email         string     `db:"email"`
	Password      string     `db:"password"`
	City          string     `db:"city"`
	Country       string     `db:"country"`
	CountryCode   string     `db:"country_code"`
	PlayerStatus  bool       `db:"player_status"`
	GalletaStatus bool       `db:"galleta_status"`
	Developer     bool       `db:"developer"`
	LastUpdate    *time.Time `db:"last_update"`
	Created       *time.Time `db:"created"`
}
