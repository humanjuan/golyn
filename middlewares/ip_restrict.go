package middlewares

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// Allow API request just for humanJuan (Golyn it's multisite)

func RestrictAPIRequestMiddleware(allowHost string) gin.HandlerFunc {
	return func(c *gin.Context) {
		hostParts := strings.Split(c.Request.Host, ":")
		host := hostParts[0]

		// PRODUCTION
		if !strings.HasSuffix(host, allowHost) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Access denied"})
			return
		}
	}
}
