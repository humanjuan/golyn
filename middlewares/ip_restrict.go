package middlewares

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"net/http"
	"strings"
)

// Allow API request just for humanJuan (Golyn it's multisite)

func RestrictAPIRequestMiddleware(allowHost string, dev bool) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("RestrictAPIRequestMiddleware()")
	return func(c *gin.Context) {
		hostParts := strings.Split(c.Request.Host, ":")
		host := hostParts[0]

		if dev {
			// DEV
			allowDevHost := strings.TrimSuffix(allowHost, ".com") + ".local"
			if !strings.HasSuffix(host, allowHost) && !strings.HasSuffix(host, allowDevHost) {
				err := fmt.Errorf("access denied for host %s", host)
				c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
				c.Abort()
				log.Warn("RestrictAPIRequestMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
				return
			}
		} else {
			// PRODUCTION
			if !strings.HasSuffix(host, allowHost) {
				err := fmt.Errorf("access denied for host %s", host)
				c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
				c.Abort()
				log.Warn("RestrictAPIRequestMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
				return
			}
		}
		c.Next()
	}
}
