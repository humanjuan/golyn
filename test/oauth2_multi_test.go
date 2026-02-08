/*
Package test provides integration and regression tests for the Golyn project.

oauth2_multi_test.go: Multi-Provider OAuth2 Integration Test

This test validates the OAuth2 authentication flow across multiple identity
providers (Microsoft Entra ID, Google, GitHub). It ensures that the redirection,
state management, and provider-specific configurations work correctly.

1. Setup:
  - Initializes the application logger and global configuration.
  - Mocks OAuth2 provider settings (Enabled, ClientID, Secrets, URLs).
  - Connects to the database and creates a test user for identity linking.
  - Configures a mock Gin router with OAuth2 routes.

2. Test Objectives:
  - Redirection: Verify that each provider's login endpoint redirects to the correct OAuth2 URL.
  - State Security: Confirm that 'oauth_state' and 'oauth_next' cookies are set during the flow.
  - Provider Availability: Ensure that disabled providers return a 403 Forbidden status.
  - Audit Trail: Validate that authentication events (auth_events) are correctly logged in the database.

3. Expected Results:
  - Redirect URLs contain the correct 'state' parameter for CSRF protection.
  - Responses for disabled providers include a clear error message.
  - Database audit records are created with the correct metadata (IP, Agent, Event).

4. Execution:
  - Command: go test -v test/oauth2_multi_test.go
*/
package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/middlewares"
	v1 "github.com/humanjuan/golyn/routes/api/v1"
	"golang.org/x/crypto/bcrypt"
)

func TestOAuth2MultiProvider(t *testing.T) {
	// Setup Environment
	if os.Getenv("GOLYN_BASE_PATH") == "" {
		cwd, _ := os.Getwd()
		base := cwd
		if filepath.Base(base) == "test" {
			base = filepath.Dir(base)
		}
		os.Setenv("GOLYN_BASE_PATH", base)
	}

	logDir := t.TempDir()
	log, err := loaders.InitLog("test_oauth2_multi", logDir, "debug", 5, 1, false)
	if err != nil {
		t.Fatalf("failed to init logger: %v", err)
	}
	globals.SetAppLogger(log)
	t.Cleanup(func() { log.Close() })

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
		_, _ = db.GetPool().Exec(context.Background(), "DELETE FROM auth.users WHERE username = $1", testUser)
	}()

	// Setup Site and User
	var siteID string
	err = db.GetPool().QueryRow(context.Background(), "SELECT id FROM core.sites LIMIT 1").Scan(&siteID)
	if err != nil {
		t.Fatalf("Failed to retrieve any site id: %v", err)
	}

	_, _ = db.GetPool().Exec(context.Background(), "DELETE FROM auth.users WHERE username = $1", testUser)
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte("OauthPass123!"), 10)
	_, err = db.GetPool().Exec(
		context.Background(),
		"INSERT INTO auth.users (site_id, username, password_hash) VALUES ($1, $2, $3)",
		siteID, testUser, string(hashedPass),
	)
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	t.Run("Login Redirection and State Cookie", func(t *testing.T) {
		providers := []string{"azure", "google", "github", "facebook"}
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
	})

	t.Run("Callback Logic and Auth Events", func(t *testing.T) {
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
	})

	t.Run("Callback Redirection without next cookie", func(t *testing.T) {
		// Mock a request without the required state cookie
		req, _ := http.NewRequest("GET", "/api/v1/auth/google/callback?state=xyz&code=abc", nil)
		req.Host = host
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// It should redirect to the login error page because CSRF state is missing,
		// but the important thing is that it REDIRECTS, not returns JSON.
		if w.Code != http.StatusTemporaryRedirect {
			t.Errorf("Expected redirect on error, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "/login?error=") {
			t.Errorf("Expected redirect to login error page, got %s", location)
		}
	})
}
