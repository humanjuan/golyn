package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/humanjuan/golyn/internal/utils"
)

func TestFileOrDirectoryExists(t *testing.T) {
	tmpDir := t.TempDir()
	if !utils.FileOrDirectoryExists(tmpDir) {
		t.Fatalf("expected existing temp dir to be detected")
	}

	// Create a temp file and check
	file := filepath.Join(tmpDir, "sample.txt")
	if err := os.WriteFile(file, []byte("hi"), 0644); err != nil {
		t.Fatalf("failed creating temp file: %v", err)
	}
	if !utils.FileOrDirectoryExists(file) {
		t.Fatalf("expected existing temp file to be detected")
	}

	// Non-existing path
	non := filepath.Join(tmpDir, "does-not-exist")
	if utils.FileOrDirectoryExists(non) {
		t.Fatalf("expected non-existing path to return false")
	}
}
