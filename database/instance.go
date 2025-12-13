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
		config.Username, config.Password, config.Host, config.Port, config.Database, config.Schema) // SSL disabled to DEV

	log.Debug("Postgres connection string: %s", dbString)

	// Create pool
	dbi.db, err = pgxpool.New(context.Background(), dbString)

	if err != nil {
		log.Error("Unable to connect to database. %w", err.Error())
		return err
	}

	err = dbi.db.Ping(context.Background())
	if err != nil {
		log.Error("The Database it doesn't available. %w", err.Error())
		return err
	}

	var version string
	sqlStatement := "Select version()"
	err = dbi.db.QueryRow(context.Background(), sqlStatement).Scan(&version)
	if err != nil {
		log.Error("An error occurred while trying to get the version from the database: %w", err.Error())
		return err
	}

	log.Info("Open Connection Database")
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
