package middlewares

import (
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
