package loaders

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/humanjuan/acacia/v2"
)

func InitLogDB(name string, path string, level string, maxSizeMb int, maxBackup int, dailyRotation bool) (*acacia.Log, error) {
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
		acacia.WithBufferSize(50_000), // Should be enough for concurrent queries
		acacia.WithBufferCap(64<<10),  // 64 KB, DB won't generate massive bursts
		acacia.WithDrainBurst(256),    // Conservative drain rate
		acacia.WithFlushInterval(100*time.Millisecond))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Log: %w", err)
	}
	LogDB.TimestampFormat(acacia.TS.Special)
	LogDB.Rotation(maxSizeMb, maxBackup)
	LogDB.DailyRotation(dailyRotation)
	return LogDB, nil
}

func InitLog(name string, path string, level string, maxSizeMb int, maxBackup int, dailyRotation bool) (*acacia.Log, error) {
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
		acacia.WithBufferSize(250_000), // Handle bursts without excessive memory usage
		acacia.WithBufferCap(128<<10),  // 128 KB internal buffer
		acacia.WithDrainBurst(512),     // Batching for standard server load
		acacia.WithFlushInterval(50*time.Millisecond)) // Balanced latency and overhead
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Log: %w", err)
	}
	Log.TimestampFormat(acacia.TS.Special)
	Log.Rotation(maxSizeMb, maxBackup)
	Log.DailyRotation(dailyRotation)
	return Log, nil
}
