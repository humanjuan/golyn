package database

import (
	"Back/config/loaders"
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jpengineer/logger"
)

type DBInstance struct {
	db *pgxpool.Pool
}

func (dbi *DBInstance) InitDB(conf *loaders.Config, logDB *logger.Log) error {
	var err error
	logDB.Info("DB user: %s | DB name: %s | DB schema: %s | DB host: %s | DB port: %d",
		conf.Database.Username, conf.Database.Database, conf.Database.Schema, conf.Database.Host, conf.Database.Port)

	dbData := conf.Database
	dbString := fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s sslmode=disable search_path=%s",
		dbData.Username, dbData.Password, dbData.Host, dbData.Port, dbData.Database, dbData.Schema) // SSL disabled to DEV

	logDB.Debug("Postgres connection string: %s", dbString)

	// Create pool
	dbi.db, err = pgxpool.New(context.Background(), dbString)

	if err != nil {
		logDB.Error("Unable to connect to database. %w", err.Error())
		return err
	}

	err = dbi.db.Ping(context.Background())
	if err != nil {
		logDB.Error("The Database it doesn't available. %w", err.Error())
		return err
	}

	var version string
	sqlStatement := "Select version()"
	err = dbi.db.QueryRow(context.Background(), sqlStatement).Scan(&version)
	if err != nil {
		logDB.Error("An error occurred while trying to get the version from the database: %w", err.Error())
		return err
	}

	logDB.Info("Open Connection Database")
	logDB.Info(version)
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
