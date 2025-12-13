package loaders

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/humanjuan/acacia/v2"
)

func InitLogDB(name string, path string, level string, maxSizeMb int, maxBackup int) (*acacia.Log, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(path, 0755)
		if mkdirErr != nil {
			return nil, fmt.Errorf("failed to create db log directory: %w", mkdirErr)
		}
	}
	LogDB, err := acacia.Start(
		name+"_db.log",
		path,
		strings.ToUpper(level),
		acacia.WithBufferSize(50_000), // suficiente para consultas concurrentes
		acacia.WithBufferCap(64<<10),  // 64 KB, DB no genera bursts gigantes
		acacia.WithDrainBurst(256),    // conservador
		acacia.WithFlushInterval(100*time.Millisecond))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Log: %w", err)
	}
	LogDB.TimestampFormat(acacia.TS.Special)
	LogDB.Rotation(maxSizeMb, maxBackup)
	LogDB.DailyRotation(true)
	return LogDB, nil
}

func InitLog(name string, path string, level string, maxSizeMb int, maxBackup int) (*acacia.Log, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(path, 0755)
		if mkdirErr != nil {
			return nil, fmt.Errorf("failed to create db log directory: %w", mkdirErr)
		}
	}
	Log, err := acacia.Start(
		name+"_server.log",
		path,
		strings.ToUpper(level),
		acacia.WithBufferSize(250_000), // suficiente para bursts, sin consumir 100MB
		acacia.WithBufferCap(128<<10),  // 128 KB por búfer interno
		acacia.WithDrainBurst(512),     // suficiente batching para un server
		acacia.WithFlushInterval(50*time.Millisecond)) // bajo overhead y latencia equilibrada
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Log: %w", err)
	}
	Log.TimestampFormat(acacia.TS.Special)
	Log.Rotation(maxSizeMb, maxBackup)
	Log.DailyRotation(true)
	return Log, nil
}
