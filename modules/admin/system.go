package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/handlers"
	"github.com/humanjuan/golyn/internal/security/hierarchy"
	"github.com/humanjuan/golyn/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

// GetSecurityPolicies returns current global security configuration
func GetSecurityPolicies() gin.HandlerFunc {
	return func(c *gin.Context) {
		config := globals.GetConfig()

		policy := SecurityPolicyDTO{
			MainDomain:            config.Server.MainDomain,
			ContentSecurityPolicy: config.Server.ContentSecurityPolicy,
			PermissionsPolicy:     config.Server.PermissionsPolicy,
			RateLimitRequests:     config.Server.RateLimitRequests,
			GlobalWhitelist:       config.Server.GlobalWhitelist,
			CookieSettings: gin.H{
				"same_site": config.Server.CookieSameSite,
				"http_only": config.Server.CookieHttpOnly,
				"secure":    config.Server.CookieSecure,
				"domain":    config.Server.CookieDomain,
			},
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    policy,
		})
	}
}

// GetActiveSessions returns all active sessions (SuperAdmin only)
func GetActiveSessions() gin.HandlerFunc {
	return func(c *gin.Context) {
		db := globals.GetDBInstance()
		sessions, err := db.GetActiveSessions()
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to list active sessions"))
			c.Abort()
			return
		}

		dtos := make([]SessionDTO, len(sessions))
		for i, s := range sessions {
			dtos[i] = MapSessionToDTO(s)
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    dtos,
		})
	}
}

// TerminateSession forces the revocation of a specific session
func TerminateSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		idStr := c.Param("id")
		idValue, err := strconv.ParseInt(idStr, 10, 64)

		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid session id"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		err = db.RevokeRefreshTokenByID(idValue)
		if err != nil {
			log.Error("Admin.TerminateSession() | Failed: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to terminate session"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "session terminated successfully",
		})
	}
}

// GetAuthProviders returns the list of authentication providers
func GetAuthProviders() gin.HandlerFunc {
	return func(c *gin.Context) {
		db := globals.GetDBInstance()
		providers, err := db.GetAuthProviders()
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to list auth providers"))
			c.Abort()
			return
		}

		dtos := make([]AuthProviderDTO, len(providers))
		for i, p := range providers {
			dtos[i] = MapAuthProviderToDTO(p)
			// Enmask ClientSecret (not included in DTO anyway, but being safe)
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    dtos,
		})
	}
}

// UpdateAuthProvider updates credentials for a provider
func UpdateAuthProvider() gin.HandlerFunc {
	return func(c *gin.Context) {
		slug := c.Param("slug")
		var req struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			RedirectURL  string `json:"redirect_url"`
			TenantID     string `json:"tenant_id"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()

		// Get existing provider to preserve fields if not provided in request
		existing, _ := db.GetAuthProviderBySlug(slug)
		if existing != nil {
			if req.ClientID == "" && existing.ClientID != nil {
				req.ClientID = *existing.ClientID
			}
			if req.ClientSecret == "" && existing.ClientSecret != nil {
				req.ClientSecret = *existing.ClientSecret
			}
			if req.RedirectURL == "" && existing.RedirectURL != nil {
				req.RedirectURL = *existing.RedirectURL
			}
			if req.TenantID == "" && existing.TenantID != nil {
				req.TenantID = *existing.TenantID
			}
		}

		err := db.UpdateAuthProvider(slug, req.ClientID, req.ClientSecret, req.RedirectURL, req.TenantID)
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to update auth provider"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "auth provider updated successfully",
		})
	}
}

// UpdateAuthProviderStatus toggles enabled state
func UpdateAuthProviderStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		slug := c.Param("slug")
		var req struct {
			Enabled bool `json:"enabled"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		err := db.UpdateAuthProviderStatus(slug, req.Enabled)
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to update provider status"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "auth provider status updated successfully",
		})
	}
}

// Tokens management

// ListAllAPIKeys returns all API keys for SuperAdmin
func ListAllAPIKeys() gin.HandlerFunc {
	return func(c *gin.Context) {
		db := globals.GetDBInstance()
		keys, err := db.GetAllAPIKeys()
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to list api keys"))
			c.Abort()
			return
		}

		dtos := make([]ApiKeyDTO, len(keys))
		for i, k := range keys {
			dtos[i] = MapApiKeyToDTO(k)
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    dtos,
		})
	}
}

// CreateAPIKey generates a new long-lived token
func CreateAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username string   `json:"username"`
			Name     string   `json:"name" binding:"required"`
			Scopes   []string `json:"scopes"`
			ExpireIn int      `json:"expire_in_days"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		user, err := db.GetUserByUsername(req.Username)
		if err != nil || user == nil {
			c.Error(utils.NewHTTPError(http.StatusNotFound, "user not found"))
			c.Abort()
			return
		}

		// Generate a secure random key
		rawKey := utils.GenerateRandomString(32)
		hashedKey, _ := bcrypt.GenerateFromPassword([]byte(rawKey), 10)

		scopesJSON, _ := json.Marshal(req.Scopes)
		var expiresAt *time.Time
		if req.ExpireIn > 0 {
			t := time.Now().AddDate(0, 0, req.ExpireIn)
			expiresAt = &t
		}

		err = db.CreateAPIKey(user.Id, req.Name, string(hashedKey), scopesJSON, expiresAt)
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to create api key"))
			c.Abort()
			return
		}

		c.JSON(http.StatusCreated, utils.APIResponse{
			Success: true,
			Message: "api key created successfully",
			Data: gin.H{
				"key": rawKey, // ONLY SHOWN ONCE
			},
		})
	}
}

// RevokeAPIKey deletes an API key
func RevokeAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		db := globals.GetDBInstance()
		err := db.DeleteAPIKey(id)
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to revoke api key"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "api key revoked successfully",
		})
	}
}

// GetServerConfiguration returns global server configuration for SuperAdmin
func GetServerConfiguration() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		actorRole := strings.ToLower(fmt.Sprintf("%v", role))

		if actorRole != hierarchy.RoleSuperAdmin {
			c.Error(utils.NewHTTPError(http.StatusForbidden, "only SuperAdmin can access global server configuration"))
			c.Abort()
			return
		}

		config := globals.GetConfig()
		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    MapServerConfigToDTO(config),
		})
	}
}

// GetLogs reuses the existing log handling logic
func GetLogs() gin.HandlerFunc {
	return handlers.GetLogs()
}

// GetStats returns dashboard statistics
func GetStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		db := globals.GetDBInstance()

		var totalUsers int
		var jwtEnabledSites int

		// Get User count
		err := db.QueryRow(context.Background(), database.Queries["count_total_users"]).Scan(&totalUsers)
		if err != nil {
			log.Error("GetStats() | Error counting users: %v", err)
		}

		// Get Active Sites count
		err = db.QueryRow(context.Background(), database.Queries["count_active_sites"]).Scan(&jwtEnabledSites)
		if err != nil {
			log.Error("GetStats() | Error counting active sites: %v", err)
		}

		// Count recent errors in logs (last 1000 lines or last hour)
		recentErrors := countRecentErrors()

		// System Health
		systemHealth := "healthy"
		if err := db.GetPool().Ping(context.Background()); err != nil {
			systemHealth = "unhealthy"
		}

		// Count sites with JWT active in configuration
		active_sites := 0
		config := globals.GetConfig()
		for _, site := range config.Sites {
			if site.Enabled {
				active_sites++
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"total_users":       totalUsers,
			"jwt_enabled_sites": jwtEnabledSites,
			"active_sites":      active_sites,
			"recent_errors":     recentErrors,
			"system_health":     systemHealth,
		})
	}
}

// GetInfo returns detailed environment information
func GetInfo(serverInfo *app.Info) gin.HandlerFunc {
	return func(c *gin.Context) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		db := globals.GetDBInstance()
		var dbVersion string
		_ = db.QueryRow(context.Background(), database.Queries["get_db_version"]).Scan(&dbVersion)

		uptime := time.Since(serverInfo.ServerStartTime).String()

		c.JSON(http.StatusOK, gin.H{
			"version":     serverInfo.ServerVersion,
			"go_version":  runtime.Version(),
			"os":          runtime.GOOS,
			"arch":        runtime.GOARCH,
			"cpu_cores":   runtime.NumCPU(),
			"goroutines":  runtime.NumGoroutine(),
			"memory_used": fmt.Sprintf("%.2f MB", float64(mem.Alloc)/1024/1024),
			"uptime":      uptime,
			"db_version":  dbVersion,
		})
	}
}

func countRecentErrors() int {
	log := globals.GetAppLogger()
	config := globals.GetConfig()
	logPath := filepath.Join(config.Log.Path, "golyn_server.log")

	file, err := os.Open(logPath)
	if err != nil {
		log.Error("countRecentErrors() | Failed to open log file: %v", err)
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)

	// Count [ERROR] or [CRITICAL] from the last hour
	oneHourAgo := time.Now().Add(-1 * time.Hour)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "[ERROR]") || strings.Contains(line, "[CRITICAL]") {
			logTime, err := utils.ParseLogTimestamp(line)
			if err == nil && logTime.After(oneHourAgo) {
				count++
			}
		}
	}

	return count
}
