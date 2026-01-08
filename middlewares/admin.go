package middlewares

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		role, exists := c.Get("role")

		if !exists || (role != "SuperAdmin" && role != "Admin") {
			log.Warn("AdminMiddleware() | Access denied | User: %s | Role: %v", c.GetString("subject"), role)
			err := fmt.Errorf("insufficient privileges")
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		c.Next()
	}
}
