/*
Package test provides integration and regression tests for the Golyn project.

jwt_test.go: Authentication and JWT Lifecycle Integration Test

This test validates the complete lifecycle of a JSON Web Token (JWT) within the Golyn platform.
It ensures that the security contract is respected across the following stages:

1. Setup:
  - Initializes a controlled environment with a mock server (httptest).
  - Dynamically creates a test user (cafest@humanjuan.com) in the database.
  - Configures short expiration times to test timeout scenarios efficiently.

2. Test Objectives:
  - Login: Verify that valid credentials yield an Access Token and a secure Refresh Token cookie.
  - Authorized Access: Confirm that a valid Access Token allows entry to protected endpoints.
  - Unauthorized Access: Ensure that expired tokens are correctly rejected with a 401 status.
  - Token Rotation: Validate that the Refresh Token can be used to obtain a new Access Token without re-logging.
  - Persistence: Confirm that the new Access Token is fully functional.

3. Expected Results:
  - Successful login returns a 200 OK and a JWT.
  - Accessing /api/v1/logs with a valid token returns 200 OK.
  - Accessing after 61 seconds (token expiration) returns 401 Unauthorized.
  - Refreshing the token returns a new valid JWT.
  - Teardown successfully removes the test user from the database.
  - OAuth2 Multi-provider: Supports Azure, Google, and GitHub.
  - Identity Mapping: Automatic linking of external identities to existing users.

4. Execution:
  - Command: export $(grep -v '^#' .env | xargs) && go test -v test/jwt_test.go
  - Requirements: A running PostgreSQL instance and a valid .env file.
*/
package test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/acacia/v2"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/middlewares"
	"github.com/humanjuan/golyn/routes"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
)

/*
TestAuthenticationFlow validates the complete JWT lifecycle:
1. Login and Token Acquisition
2. Resource access with valid token
3. Token expiration handling
4. Token refresh using secure cookie
5. Resource access with new token
*/
func TestAuthenticationFlow(t *testing.T) {
	// Setup Environment
	if os.Getenv("GOLYN_BASE_PATH") == "" {
		cwd, _ := os.Getwd()
		os.Setenv("GOLYN_BASE_PATH", cwd)
	}

	log, _ := acacia.Start("test_jwt_flow.log", "./var/log", "DEBUG")
	globals.SetAppLogger(log)
	globals.SetDBLogger(log)
	defer func() {
		log.Close()
		os.Remove("./var/log/test_jwt_flow.log")
	}()

	// Load real configuration but override specific values for controlled testing
	conf, err := loaders.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	conf.Server.TokenExpirationTime = 1        // 1 minute access token
	conf.Server.TokenExpirationRefreshTime = 5 // 5 minutes refresh token
	conf.Server.Dev = true
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
	router.Use(gin.Recovery())
	router.Use(middlewares.CustomErrorHandler())
	router.Use(middlewares.CacheMiddleware(cache.New(cache.NoExpiration, 0)))

	serverInfo := &app.Info{ServerVersion: "test-v1"}
	routes.ConfigureRoutes(router, serverInfo, "humanjuan.com", true)

	// Test credentials and context
	testUser := "cafest@humanjuan.com"
	testPass := "Caf3st!"
	host := "golyn.humanjuan.local"

	// Cleanup user after tests
	defer func() {
		db.GetPool().Exec(context.Background(), "DELETE FROM auth.users WHERE username = $1", testUser)
	}()

	var siteID string
	err = db.GetPool().QueryRow(context.Background(), "SELECT id FROM core.sites WHERE host = $1 OR host = $2", host, "humanjuan.local").Scan(&siteID)
	if err != nil {
		err = db.GetPool().QueryRow(context.Background(), "SELECT id FROM core.sites LIMIT 1").Scan(&siteID)
		if err != nil {
			t.Fatalf("Failed to retrieve any site id: %v", err)
		}
	}

	// Prepare fresh test user
	db.GetPool().Exec(context.Background(), "DELETE FROM auth.users WHERE username = $1", testUser)
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(testPass), 10)
	_, err = db.GetPool().Exec(context.Background(), "INSERT INTO auth.users (site_id, username, password_hash) VALUES ($1, $2, $3)", siteID, testUser, string(hashedPass))
	if err != nil {
		t.Fatalf("Failed to setup test user: %v", err)
	}

	var accessToken string
	var refreshTokenCookie string

	t.Run("Login and Obtain Tokens", func(t *testing.T) {
		loginBody := map[string]string{"username": testUser, "password": testPass}
		body, _ := json.Marshal(loginBody)
		req, _ := http.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(body))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("[NOK] Login failed: %s", w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		accessToken = resp["access_token"].(string)

		// Extract refresh token from secure cookie
		for _, cookie := range w.Header().Values("Set-Cookie") {
			if strings.Contains(cookie, "refreshToken=") {
				refreshTokenCookie = cookie
				break
			}
		}

		if accessToken == "" || refreshTokenCookie == "" {
			t.Fatal("[NOK] Missing tokens in response")
		}
		t.Log("[OK] Tokens obtained successfully")
	})

	t.Run("Access with Valid Token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/logs", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("[NOK] Valid access rejected: %d", w.Code)
		}
		t.Log("[OK] Access granted with valid token")
	})

	t.Run("Expired Access Token Simulation", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping expiration wait in short mode")
		}
		t.Log("[INFO] Waiting 61 seconds for access token to expire...")
		time.Sleep(61 * time.Second)

		req, _ := http.NewRequest("GET", "/api/v1/logs", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("[NOK] Expected 401 for expired token, got %d", w.Code)
		}
		t.Log("[OK] Expired token correctly rejected")
	})

	t.Run("Refresh Token and Obtain New Access Token", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/v1/refresh_token", nil)
		req.Host = host

		// Reconstruct cookie for the request
		cookieVal := strings.Split(strings.Split(refreshTokenCookie, ";")[0], "=")[1]
		req.AddCookie(&http.Cookie{Name: "refreshToken", Value: cookieVal})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("[NOK] Refresh failed: %s", w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		accessToken = resp["access_token"].(string)

		if accessToken == "" {
			t.Fatal("[NOK] Failed to obtain new access token")
		}
		t.Log("[OK] Token refreshed successfully")
	})

	t.Run("Access with Refreshed Token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/logs", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("[NOK] Access with refreshed token rejected: %d", w.Code)
		}
		t.Log("[OK] Access granted with refreshed token")
	})
}
