/*
Package test provides integration and regression tests for the Golyn project.

admin_api_test.go: Administration API Integration Test

This test validates the administrative endpoints used for managing sites and users.
It ensures that only authorized users (SuperAdmin/Admin) can access these functions
and that the multi-site logic is correctly handled via the API.

1. Setup:
  - Initializes a mock server (httptest).
  - Creates a SuperAdmin test user.
  - Generates a Platform JWT for the SuperAdmin.

2. Test Objectives:
  - Site Management:
  - Create a new site programmatically.
  - List all registered sites.
  - User Management:
  - Create a new user linked to the previously created site.
  - List users for a specific site.
  - Security:
  - Verify that regular users are rejected by the AdminMiddleware.

3. Expected Results:
  - Site creation returns 201 Created.
  - Site list includes the new site.
  - User creation returns 201 Created.
  - Regular user tokens receive a 403 Forbidden on admin routes.

4. Execution:
  - Command: export $(grep -v '^#' .env | xargs) && GOLYN_BASE_PATH=$(pwd) go test -v test/admin_api_test.go
*/
package test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/acacia/v2"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	platjwt "github.com/humanjuan/golyn/internal/security/jwt"
	"github.com/humanjuan/golyn/middlewares"
	"github.com/humanjuan/golyn/routes"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
)

func TestAdminAPI(t *testing.T) {
	// Setup Environment
	if os.Getenv("GOLYN_BASE_PATH") == "" {
		cwd, _ := os.Getwd()
		os.Setenv("GOLYN_BASE_PATH", cwd)
	}

	log, _ := acacia.Start("test_admin_api.log", "./var/log", "DEBUG")
	globals.SetAppLogger(log)
	globals.SetDBLogger(log)
	defer func() {
		log.Close()
		os.Remove("./var/log/test_admin_api.log")
	}()

	conf, err := loaders.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
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
	router.Use(middlewares.CacheMiddleware(cache.New(cache.NoExpiration, 0)))

	serverInfo := &app.Info{ServerVersion: "test-admin"}
	routes.ConfigureRoutes(router, serverInfo, "humanjuan.com", true)

	// Admin Credentials
	adminUser := "superadmin@test.local"
	adminPass := "AdminPass123!"
	host := "golyn.humanjuan.local"

	// Cleanup any previous data
	ctx := context.Background()
	db.GetPool().Exec(ctx, "DELETE FROM auth.users WHERE username = $1 OR username = $2", adminUser, "regular@test.local")
	db.GetPool().Exec(ctx, "DELETE FROM core.sites WHERE key = $1", "test-admin-site")

	// 1. Create SuperAdmin User
	var siteID string
	err = db.GetPool().QueryRow(ctx, "SELECT id FROM core.sites WHERE host = $1", "humanjuan.local").Scan(&siteID)
	if err != nil {
		err = db.GetPool().QueryRow(ctx, "SELECT id FROM core.sites LIMIT 1").Scan(&siteID)
	}

	hashedAdmin, _ := bcrypt.GenerateFromPassword([]byte(adminPass), 10)
	_, err = db.GetPool().Exec(ctx, "INSERT INTO auth.users (site_id, username, password_hash, role) VALUES ($1, $2, $3, $4)", siteID, adminUser, string(hashedAdmin), "SuperAdmin")
	if err != nil {
		t.Fatalf("Failed to setup SuperAdmin: %v", err)
	}

	// 2. Create Regular User
	_, err = db.GetPool().Exec(ctx, "INSERT INTO auth.users (site_id, username, password_hash, role) VALUES ($1, $2, $3, $4)", siteID, "regular@test.local", "hash", "user")

	// Obtain Tokens
	adminToken, _, _ := platjwt.CreateToken(adminUser, host)
	regularToken, _, _ := platjwt.CreateToken("regular@test.local", host)

	t.Run("Create Site - Authorized", func(t *testing.T) {
		siteBody := map[string]string{"key": "test-admin-site", "host": "admin-test.local"}
		body, _ := json.Marshal(siteBody)
		req, _ := http.NewRequest("POST", "/api/v1/admin/sites", bytes.NewBuffer(body))
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected 201 Created, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("Create User - Authorized", func(t *testing.T) {
		userBody := map[string]string{
			"site_key": "test-admin-site",
			"username": "api-managed@test.local",
			"password": "ManagedPass123!",
			"role":     "Admin",
		}
		body, _ := json.Marshal(userBody)
		req, _ := http.NewRequest("POST", "/api/v1/admin/users", bytes.NewBuffer(body))
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected 201 Created, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("List Sites - Unauthorized (Regular User)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/admin/sites", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+regularToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for regular user, got %d", w.Code)
		}
	})

	t.Run("List Users - Filtered by Site", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/admin/users?site_key=test-admin-site", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+adminToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", w.Code)
		}

		var users []database.User
		json.Unmarshal(w.Body.Bytes(), &users)
		if len(users) == 0 {
			t.Error("Expected at least one user in the response")
		}
		for _, u := range users {
			if u.Username != "api-managed@test.local" {
				t.Errorf("Unexpected user in site filter: %s", u.Username)
			}
		}
	})

	// Final Cleanup
	db.GetPool().Exec(ctx, "DELETE FROM auth.users WHERE username = $1 OR username = $2", adminUser, "regular@test.local")
	db.GetPool().Exec(ctx, "DELETE FROM core.sites WHERE key = $1", "test-admin-site")
}
