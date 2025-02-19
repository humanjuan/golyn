package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GetBasePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	basePath := filepath.Dir(exePath)
	if strings.Contains(basePath, "Library/Caches") || strings.Contains(basePath, "go-build") {
		workingDir, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
		return filepath.Abs(workingDir)
	}
	return basePath, nil
}

func FileOrDirectoryExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
