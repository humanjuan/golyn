package test

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestReadiness performs a general readiness check by ensuring the whole module builds.
// It does NOT start external services nor the HTTP server; it only validates that the
// repository compiles successfully across all packages (including cmd/).
func TestReadiness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "build", "./...")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Include both stdout and stderr to ease troubleshooting in CI.
		t.Fatalf("go build failed: %v\nSTDOUT:\n%s\nSTDERR:\n%s", err, stdout.String(), stderr.String())
	}
}
