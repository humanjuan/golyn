package middlewares

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func ClientCacheMiddleware(isDev bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isDev {
			c.Writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
			c.Writer.Header().Set("Pragma", "no-cache")
			c.Writer.Header().Set("Expires", "0")
		} else {
			if strings.HasPrefix(c.Request.URL.Path, "/assets") ||
				strings.HasPrefix(c.Request.URL.Path, "/js") ||
				strings.HasPrefix(c.Request.URL.Path, "/style") {
				// 31536000 = 1 year
				c.Writer.Header().Set("Cache-Control", "public, max-age=31536000")
			} else if c.Request.Method == "GET" || c.Request.Method == "HEAD" {
				c.Writer.Header().Set("Cache-Control", "no-cache")
				c.Writer.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			} else {
				c.Writer.Header().Set("Cache-Control", "no-store")
			}
		}

		// Cache-Control Vary header
		c.Writer.Header().Set("Vary", "Origin")

		c.Next()
	}
}
