/*
Package test provides integration and regression tests for the Golyn project.

token_fix_test.go: Token Revocation and Security Regression Test

This test focuses on the backend logic of token management, specifically ensuring that
old refresh tokens are properly revoked during new logins and token rotations. It
prevents "zombie" sessions and protects against token reuse attacks.

1. Setup:
  - Connects to the local PostgreSQL database.
  - Sets up a temporary test user and cleans up any existing tokens for that user.
  - Configures global security settings (JWTSecret).

2. Test Objectives:
  - Global Revocation: Ensure that when a user logs in again (CreateToken), ALL
    previous refresh tokens for that user are marked as revoked.
  - Specific Revocation: Ensure that during a token refresh (IssueNewTokens),
    only the specific token used is revoked, and the new one remains active.
  - Type Safety: Validate that internal UUIDs and IDs are handled correctly
    between Go and PostgreSQL.

3. Expected Results:
  - Manual tokens stored before a login should show 'Revoked = true' after CreateToken.
  - The token used to call IssueNewTokens must be 'Revoked = true' afterward.
  - New tokens generated in either flow must be 'Revoked = false'.
  - All database constraints (Foreign Keys to auth.users) must be respected.

4. Execution:
  - Command: export $(grep -v '^#' .env | xargs) && go test -v test/token_fix_test.go
  - Requirements: A running PostgreSQL instance and a valid .env file.
*/
package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	platjwt "github.com/humanjuan/golyn/internal/security/jwt"
	"golang.org/x/crypto/bcrypt"
)

func TestTokenRevocationFix(t *testing.T) {
	if os.Getenv("GOLYN_BASE_PATH") == "" {
		cwd, _ := os.Getwd()
		base := cwd
		if filepath.Base(base) == "test" {
			base = filepath.Dir(base)
		}
		os.Setenv("GOLYN_BASE_PATH", base)
	}

	var err error

	logDir := t.TempDir()
	log, err := loaders.InitLog("test_token_fix", logDir, "debug", 5, 1, false)
	if err != nil {
		t.Fatalf("failed to init logger: %v", err)
	}
	globals.SetAppLogger(log)
	globals.SetDBLogger(log)
	t.Cleanup(func() { log.Close() })

	db := database.NewDBInstance()
	env := os.Getenv("GOLYN_DB_PASSWORD")
	cfg := &loaders.Database{
		Username: "golyn_user",
		Password: env,
		Database: "golyn",
		Schema:   "auth,core,audit",
		Host:     "localhost",
		Port:     5432,
	}

	err = db.InitDB(cfg, log)
	if err != nil {
		t.Skip("Skipping test because DB is not accessible:", err)
		return
	}
	defer db.Close()

	// Set the required config for CreateToken
	globals.SetConfig(&loaders.Config{
		Server: loaders.Server{
			JWTSecret:                  "supersecret",
			TokenExpirationTime:        1,
			TokenExpirationRefreshTime: 1440,
		},
	})

	subject := "cafest@humanjuan.com"
	// We'll get the real UUID from the DB after creating the user
	host := "golyn.humanjuan.local"
	siteID := host

	// Find a valid site_id
	var siteUUID string
	err = db.GetPool().QueryRow(context.Background(), "SELECT id FROM core.sites WHERE host = $1 OR host = $2", host, "humanjuan.local").Scan(&siteUUID)
	if err != nil {
		err = db.GetPool().QueryRow(context.Background(), "SELECT id FROM core.sites LIMIT 1").Scan(&siteUUID)
		if err != nil {
			t.Fatalf("Failed to retrieve any site id: %v", err)
		}
	}

	// Create test user
	db.GetPool().Exec(context.Background(), "DELETE FROM auth.users WHERE username = $1", subject)
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte("Caf3st!"), 10)
	_, err = db.GetPool().Exec(context.Background(), "INSERT INTO auth.users (site_id, username, password_hash) VALUES ($1, $2, $3)", siteUUID, subject, string(hashedPass))
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	// Get the created user UUID
	var userUUID string
	err = db.GetPool().QueryRow(context.Background(), "SELECT id FROM auth.users WHERE username = $1", subject).Scan(&userUUID)
	if err != nil {
		t.Fatalf("Failed to get user uuid: %v", err)
	}

	// Cleanup user after tests
	defer func() {
		db.GetPool().Exec(context.Background(), "DELETE FROM auth.users WHERE username = $1", subject)
	}()

	globals.SetDBInstance(db)

	// Cleanup previous tokens for this user to avoid collision/flakiness
	_, _ = db.GetPool().Exec(context.Background(), "DELETE FROM auth.refresh_tokens WHERE user_id = $1", userUUID)

	t.Run("CreateToken Revokes Previous Tokens", func(t *testing.T) {
		err := db.StoreRefreshToken("manual_token_1", userUUID, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("Failed to store manual token: %v", err)
		}

		_, rt, err := platjwt.CreateToken(subject, siteID)
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}

		oldToken, err := db.GetRefreshToken("manual_token_1")
		if err != nil {
			t.Fatalf("GetRefreshToken failed: %v", err)
		}
		if oldToken.Revoked != true {
			t.Errorf("Expected manual_token_1 to be revoked (revoked true), got %v", oldToken.Revoked)
		}

		newToken, err := db.GetRefreshToken(rt)
		if err != nil {
			t.Fatalf("GetRefreshToken for new token failed: %v", err)
		}
		if newToken.Revoked != false {
			t.Errorf("Expected new token to be active (revoked false), got %v", newToken.Revoked)
		}
	})

	t.Run("IssueNewTokens Revokes Specific Token", func(t *testing.T) {
		// Cleanup again to be sure
		_, _ = db.GetPool().Exec(context.Background(), "DELETE FROM auth.refresh_tokens WHERE user_id = $1", userUUID)

		_, rt1, err := platjwt.CreateTokenWithRevocation(subject, siteID, false)
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}

		claims, err := platjwt.ValidateRefreshToken(rt1)
		if err != nil {
			t.Fatalf("ValidateRefreshToken failed: %v", err)
		}

		// Sleep more to avoid same-second JWT signature collision
		time.Sleep(2100 * time.Millisecond)

		_, rt2, err := platjwt.IssueNewTokens(rt1, claims)
		if err != nil {
			t.Fatalf("IssueNewTokens failed: %v", err)
		}

		oldToken, err := db.GetRefreshToken(rt1)
		if err != nil {
			t.Fatalf("GetRefreshToken for rt1 failed: %v", err)
		}
		if oldToken.Revoked != true {
			t.Errorf("Expected rt1 to be revoked, got %v", oldToken.Revoked)
		}

		newToken, err := db.GetRefreshToken(rt2)
		if err != nil {
			t.Fatalf("GetRefreshToken for rt2 failed: %v", err)
		}
		if newToken.Revoked != false {
			t.Errorf("Expected rt2 to be active (revoked false), got %v", newToken.Revoked)
		}
	})
}
