package loaders

import (
	"fmt"
	"os"
	"strings"

	"github.com/humanjuan/logger"
)

func InitLogDB(name string, path string, level string, maxSizeMb int, maxBackup int) (*logger.Log, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(path, 0755)
		if mkdirErr != nil {
			return nil, fmt.Errorf("failed to create db log directory: %w", mkdirErr)
		}
	}
	LogDB, err := logger.Start(name+"_db.log", path, strings.ToUpper(level))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Log: %w", err)
	}
	LogDB.TimestampFormat(logger.TS.Special)
	LogDB.Rotation(maxSizeMb, maxBackup)
	return LogDB, nil
}

func InitLog(name string, path string, level string, maxSizeMb int, maxBackup int) (*logger.Log, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(path, 0755)
		if mkdirErr != nil {
			return nil, fmt.Errorf("failed to create db log directory: %w", mkdirErr)
		}
	}
	Log, err := logger.Start(name+"_server.log", path, strings.ToUpper(level))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Log: %w", err)
	}
	Log.TimestampFormat(logger.TS.Special)
	Log.Rotation(maxSizeMb, maxBackup)
	return Log, nil
}
