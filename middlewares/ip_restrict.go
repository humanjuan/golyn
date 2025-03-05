package middlewares

import (
	"Back/globals"
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// Allow API request just for humanJuan (Golyn it's multisite)

func RestrictAPIRequestMiddleware(allowHost string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		log.Debug("RestrictAPIRequestMiddleware()")
		hostParts := strings.Split(c.Request.Host, ":")
		host := hostParts[0]

		// PRODUCTION
		if !strings.HasSuffix(host, allowHost) {
			err := fmt.Errorf("access denied for host %s", host)
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			log.Warn("RestrictAPIRequestMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
			return
		}
		c.Next()
	}
}
