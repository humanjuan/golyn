/*
Package test provides integration and regression tests for the Golyn project.

readiness_test.go: Build and Compilation Sanity Check

This is a "smoke test" designed to ensure that the project is always in a
compilable state. It doesn't test logic or database connectivity, but
rather the integrity of the Go modules, imports, and syntax across the
entire repository.

1. Setup:
  - Uses the 'go' toolchain available on the system.
  - Sets a 5-minute timeout for the compilation process.

2. Test Objectives:
  - Full Build: Run 'go build ./...' to compile every package, handler, and
    utility, including the main command in 'cmd/'.
  - Dependency Check: Implicitly verify that all external dependencies
    (go.mod/go.sum) are resolvable and compatible.

3. Expected Results:
  - The command must exit with code 0 (success).
  - No syntax errors, unused imports, or type mismatches should exist in the
    codebase.
  - If the build fails, the test provides the full STDOUT and STDERR output
    to help developers identify the breaking change.

4. Execution:
  - Command: go test -v test/readiness_test.go
*/
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
