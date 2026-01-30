package admin

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/handlers"
	"github.com/humanjuan/golyn/internal/security/hierarchy"
	"github.com/humanjuan/golyn/internal/utils"
)

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
		err := db.GetPool().QueryRow(context.Background(), database.Queries["count_total_users"]).Scan(&totalUsers)
		if err != nil {
			log.Error("GetStats() | Error counting users: %v", err)
		}

		// Get Active Sites count
		err = db.GetPool().QueryRow(context.Background(), database.Queries["count_active_sites"]).Scan(&jwtEnabledSites)
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
		_ = db.GetPool().QueryRow(context.Background(), database.Queries["get_db_version"]).Scan(&dbVersion)

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
