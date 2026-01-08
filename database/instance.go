package database

import (
	"context"
	"fmt"
	"github.com/humanjuan/acacia/v2"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DBInstance struct {
	db *pgxpool.Pool
}

func (dbi *DBInstance) InitDB(config *loaders.Database, log *acacia.Log) error {
	var err error
	log.Info("DB user: %s | DB name: %s | DB schema: %s | DB host: %s | DB port: %d",
		config.Username, config.Database, config.Schema, config.Host, config.Port)

	dbString := fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s sslmode=disable search_path=%s",
		config.Username, config.Password, config.Host, config.Port, config.Database, config.Schema) // SSL disabled for now

	log.Debug("Postgres connection string: %s", dbString)

	// Setup connection pool
	dbi.db, err = pgxpool.New(context.Background(), dbString)

	if err != nil {
		log.Error("Unable to connect to database. %w", err.Error())
		log.Sync()
		return err
	}

	err = dbi.db.Ping(context.Background())
	if err != nil {
		log.Error("The Database it doesn't available. %w", err.Error())
		log.Sync()
		return err
	}

	var version string
	sqlStatement := Queries["get_db_version"]
	err = dbi.db.QueryRow(context.Background(), sqlStatement).Scan(&version)
	if err != nil {
		log.Error("Failed to fetch database version: %w", err.Error())
		log.Sync()
		return err
	}

	log.Info("Database connection established")
	log.Info(version)
	return nil
}

func (dbi *DBInstance) Close() {
	if dbi.db != nil {
		dbi.db.Close()
	}
}

func NewDBInstance() *DBInstance {
	return &DBInstance{}
}

func (dbi *DBInstance) GetPool() *pgxpool.Pool {
	return dbi.db
}
