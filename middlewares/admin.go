package middlewares

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		roleVal, exists := c.Get("role")
		role := fmt.Sprintf("%v", roleVal)

		if !exists || (strings.ToLower(role) != "superadmin" && strings.ToLower(role) != "admin") {
			log.Warn("AdminMiddleware() | Access denied | User: %s | Role: %v", c.GetString("subject"), role)
			err := fmt.Errorf("insufficient privileges")
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		c.Next()
	}
}

func SuperAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		roleVal, exists := c.Get("role")
		role := fmt.Sprintf("%v", roleVal)

		if !exists || strings.ToLower(role) != "superadmin" {
			log.Warn("SuperAdminMiddleware() | Access denied | User: %s | Role: %v", c.GetString("subject"), role)
			err := fmt.Errorf("insufficient privileges: SuperAdmin only")
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		c.Next()
	}
}

func GrantMiddleware(requiredGrant string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		username := c.GetString("subject")
		roleVal, _ := c.Get("role")
		role := strings.ToLower(fmt.Sprintf("%v", roleVal))

		// SuperAdmin and Admin have all permissions by default
		if role == "superadmin" || role == "admin" {
			c.Next()
			return
		}

		db := globals.GetDBInstance()
		permissionsRaw, err := db.GetUserPermissions(username)
		if err != nil {
			log.Error("GrantMiddleware() | Failed to fetch permissions: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to verify permissions"))
			c.Abort()
			return
		}

		if permissionsRaw != nil {
			var permissions struct {
				Grants []string `json:"grants"`
				Denies []string `json:"denies"`
			}
			if err := json.Unmarshal(permissionsRaw, &permissions); err == nil {
				// Check denies first
				for _, deny := range permissions.Denies {
					if deny == requiredGrant {
						log.Warn("GrantMiddleware() | Access denied by deny rule | User: %s | Permission: %s", username, requiredGrant)
						c.Error(utils.NewHTTPError(http.StatusForbidden, "access denied by permission policy"))
						c.Abort()
						return
					}
				}
				// Check grants
				for _, grant := range permissions.Grants {
					if grant == requiredGrant {
						c.Next()
						return
					}
				}
			}
		}

		log.Warn("GrantMiddleware() | Access denied | User: %s | Required Permission: %s", username, requiredGrant)
		c.Error(utils.NewHTTPError(http.StatusForbidden, "insufficient permissions"))
		c.Abort()
	}
}
