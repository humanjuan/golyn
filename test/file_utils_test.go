/*
Package test provides integration and regression tests for the Golyn project.

file_utils_test.go: File System Utility Tests

This test verifies the basic file system utilities used by the server to
detect the presence of files and directories.

1. Test Objectives:
  - Directory Detection: Confirm that existing directories are detected.
  - File Detection: Confirm that created files are recognized.
  - Negative Detection: Ensure that non-existent paths are correctly reported.

2. Expected Results:
  - utils.FileOrDirectoryExists returns true for valid temporary paths.
  - utils.FileOrDirectoryExists returns false for invalid paths.

3. Execution:
  - Command: go test -v test/file_utils_test.go
*/
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
