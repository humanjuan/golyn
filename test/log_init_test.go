package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/humanjuan/golyn/config/loaders"
)

func TestInitLogCreatesFiles(t *testing.T) {
	tmpDir := t.TempDir()

	log, err := loaders.InitLog("app", tmpDir, "info", 5, 2)
	if err != nil {
		t.Fatalf("InitLog returned error: %v", err)
	}
	if log == nil {
		t.Fatalf("InitLog returned nil logger")
	}
	// server log file should exist
	serverLog := filepath.Join(tmpDir, "app_server.log")
	if _, err := os.Stat(serverLog); err != nil {
		t.Fatalf("expected server log file to exist at %s: %v", serverLog, err)
	}
}

func TestInitLogDBCreatesFiles(t *testing.T) {
	tmpDir := t.TempDir()

	log, err := loaders.InitLogDB("app", tmpDir, "debug", 10, 3)
	if err != nil {
		t.Fatalf("InitLogDB returned error: %v", err)
	}
	if log == nil {
		t.Fatalf("InitLogDB returned nil logger")
	}
	// db log file should exist
	dbLog := filepath.Join(tmpDir, "app_db.log")
	if _, err := os.Stat(dbLog); err != nil {
		t.Fatalf("expected db log file to exist at %s: %v", dbLog, err)
	}
}
