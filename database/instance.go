package database

import (
	"context"
	"fmt"

	"github.com/humanjuan/acacia/v2"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DBInstance struct {
	db     *pgxpool.Pool
	logger *acacia.Log
}

func (dbi *DBInstance) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	if dbi.logger != nil {
		dbi.logger.Debug("Exec() | sql: %s | args: %v", sql, arguments)
	}
	return dbi.db.Exec(ctx, sql, arguments...)
}

func (dbi *DBInstance) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if dbi.logger != nil {
		dbi.logger.Debug("Query() | sql: %s | args: %v", sql, args)
	}
	return dbi.db.Query(ctx, sql, args...)
}

func (dbi *DBInstance) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if dbi.logger != nil {
		dbi.logger.Debug("QueryRow() | sql: %s | args: %v", sql, args)
	}
	return dbi.db.QueryRow(ctx, sql, args...)
}

func (dbi *DBInstance) InitDB(config *loaders.Database, log *acacia.Log) error {
	dbi.logger = log
	var err error
	log.Info("DB user: %s | DB name: %s | DB schema: %s | DB host: %s | DB port: %d",
		config.Username, config.Database, config.Schema, config.Host, config.Port)

	sslMode := "disable"
	if config.SSL {
		sslMode = "verify-ca"
		if config.SSLRootCert != "" {
			sslMode = fmt.Sprintf("verify-ca sslrootcert=%s", config.SSLRootCert)
		}
	}

	dbString := fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s sslmode=%s search_path=%s",
		config.Username, config.Password, config.Host, config.Port, config.Database, sslMode, config.Schema)

	log.Debug("Postgres connection string: user=%s password=************ host=%s port=%d dbname=%s sslmode=%s search_path=%s",
		config.Username, config.Host, config.Port, config.Database, sslMode, config.Schema)

	dbi.db, err = pgxpool.New(context.Background(), dbString)

	if err != nil {
		log.Error("Unable to connect to database. %v", err.Error())
		log.Sync()
		return err
	}

	err = dbi.db.Ping(context.Background())
	if err != nil {
		log.Error("The Database it doesn't available. %v", err.Error())
		log.Sync()
		return err
	}

	var version string
	sqlStatement := Queries["get_db_version"]
	err = dbi.db.QueryRow(context.Background(), sqlStatement).Scan(&version)
	if err != nil {
		log.Error("Failed to fetch database version: %v", err.Error())
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
