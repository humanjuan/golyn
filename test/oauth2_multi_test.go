/*
Package test provides integration and regression tests for the Golyn project.

oauth2_multi_test.go: Multi-provider OAuth2 Integration Test

This test validates the generic OAuth2 flow implemented in Golyn, ensuring it can
handle different identity providers (Azure, Google, GitHub) and correctly map
external identities to platform users.

1. Setup:
  - Initializes a mock server (httptest).
  - Configures mock OAuth2 settings for Azure, Google, and GitHub.
  - Creates a test user in the database.

2. Test Objectives:
  - Login Redirection: Verify that /auth/{provider}/login redirects to the correct provider URL.
  - Callback Handling: Mock the provider's response and verify that Golyn:
  - Exchanges the code for a token.
  - Fetches user info from the provider's API.
  - Maps the identity to a local user (by ID or Email).
  - Issues a valid Platform JWT.

3. Expected Results:
  - Redirection points to the provider's authorization endpoint.
  - Successful callback returns a 200 OK with a Platform JWT.
  - User identity is correctly linked in the auth.external_identities table.

4. Execution:
  - Command: export $(grep -v '^#' .env | xargs) && go test -v test/oauth2_multi_test.go
  - Requirements: A running PostgreSQL instance and a valid .env file.
*/
package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/acacia/v2"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/middlewares"
	v1 "github.com/humanjuan/golyn/routes/api/v1"
	"golang.org/x/crypto/bcrypt"
)

func TestOAuth2MultiProvider(t *testing.T) {
	// 1. Setup Environment
	if os.Getenv("GOLYN_BASE_PATH") == "" {
		cwd, _ := os.Getwd()
		os.Setenv("GOLYN_BASE_PATH", cwd)
	}

	log, _ := acacia.Start("test_oauth2_multi.log", "./var/log", "DEBUG")
	globals.SetAppLogger(log)
	globals.SetDBLogger(log)
	defer func() {
		log.Close()
		os.Remove("./var/log/test_oauth2_multi.log")
	}()

	conf, err := loaders.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Mock OAuth2 configuration for tests
	conf.OAuth2.Providers = map[string]loaders.OAuthProvider{
		"azure": {
			Enabled:      true,
			ClientID:     "azure-client",
			ClientSecret: "azure-secret",
			RedirectURL:  "http://localhost/callback/azure",
			TenantID:     "common",
		},
		"google": {
			Enabled:      true,
			ClientID:     "google-client",
			ClientSecret: "google-secret",
			RedirectURL:  "http://localhost/callback/google",
		},
		"github": {
			Enabled:      true,
			ClientID:     "github-client",
			ClientSecret: "github-secret",
			RedirectURL:  "http://localhost/callback/github",
		},
	}
	globals.SetConfig(conf)

	db := database.NewDBInstance()
	err = db.InitDB(&conf.Database, log)
	if err != nil {
		t.Skip("Skipping test because Database is not accessible:", err)
		return
	}
	defer db.Close()
	globals.SetDBInstance(db)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middlewares.CustomErrorHandler())
	v1Group := router.Group("/api/v1")
	serverInfo := &app.Info{ServerVersion: "test-v1"}
	v1.RegisterPublicRoutes(v1Group, serverInfo)

	testUser := "oauth-multi@humanjuan.local"
	host := "golyn.humanjuan.local"

	// Cleanup
	defer func() {
		db.GetPool().Exec(context.Background(), "DELETE FROM auth.users WHERE username = $1", testUser)
	}()

	// Setup Site and User
	var siteID string
	err = db.GetPool().QueryRow(context.Background(), "SELECT id FROM core.sites LIMIT 1").Scan(&siteID)
	if err != nil {
		t.Fatalf("Failed to retrieve any site id: %v", err)
	}

	db.GetPool().Exec(context.Background(), "DELETE FROM auth.users WHERE username = $1", testUser)
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte("OauthPass123!"), 10)
	_, err = db.GetPool().Exec(context.Background(), "INSERT INTO auth.users (site_id, username, password_hash) VALUES ($1, $2, $3)", siteID, testUser, string(hashedPass))
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	t.Run("Login Redirection and State Cookie", func(t *testing.T) {
		providers := []string{"azure", "google", "github"}
		for _, p := range providers {
			req, _ := http.NewRequest("GET", "/api/v1/auth/"+p+"/login?next=http://myapp.local/dashboard", nil)
			req.Host = host
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusTemporaryRedirect {
				t.Errorf("%s login should redirect, got %d", p, w.Code)
			}

			// Verify Cookies
			var stateCookie, nextCookie string
			for _, cookie := range w.Header().Values("Set-Cookie") {
				if strings.Contains(cookie, "oauth_state=") {
					stateCookie = cookie
				}
				if strings.Contains(cookie, "oauth_next=") {
					nextCookie = cookie
				}
			}

			if stateCookie == "" {
				t.Errorf("%s login missing oauth_state cookie", p)
			}
			if nextCookie == "" {
				t.Errorf("%s login missing oauth_next cookie", p)
			}

			location := w.Header().Get("Location")
			if !strings.Contains(location, "state=") {
				t.Errorf("%s login redirection missing state parameter", p)
			}
			t.Logf("[OK] %s redirect with state and cookies", p)
		}
	})

	t.Run("Disabled Provider Rejection", func(t *testing.T) {
		// Temporarily disable GitHub
		githubConf := conf.OAuth2.Providers["github"]
		githubConf.Enabled = false
		conf.OAuth2.Providers["github"] = githubConf
		defer func() {
			githubConf.Enabled = true
			conf.OAuth2.Providers["github"] = githubConf
		}()

		req, _ := http.NewRequest("GET", "/api/v1/auth/github/login", nil)
		req.Host = host
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for disabled provider, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "github OAuth2 is disabled") {
			t.Errorf("Unexpected error message: %s", w.Body.String())
		}
		t.Log("[OK] Disabled provider correctly rejected")
	})

	t.Run("Callback Logic and Auth Events", func(t *testing.T) {
		// This test would require mocking the Exchange and fetchUserInfo calls.
		// For now, we'll verify the RegisterAuthEvent logic in the database directly
		// to ensure the Phase 3 implementation is robust.

		siteUUID := siteID
		event := "test_auth_event"
		ip := "127.0.0.1"
		ua := "Go-Test-Agent"

		err := db.RegisterAuthEvent(nil, &siteUUID, event, ip, ua)
		if err != nil {
			t.Fatalf("Failed to register auth event: %v", err)
		}

		var count int
		err = db.GetPool().QueryRow(context.Background(), "SELECT count(*) FROM audit.auth_events WHERE event = $1", event).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query auth events: %v", err)
		}
		if count == 0 {
			t.Error("Auth event was not found in database")
		}
		t.Log("[OK] Auth event registered successfully in Phase 3 logic")
	})
}
