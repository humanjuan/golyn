package middlewares

import (
	"Back/app"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func RedirectOrAllowHostMiddleware(log *logger.Log, virtualHosts map[string]app.VirtualHost) gin.HandlerFunc {
	log.Debug("redirectOrAllowHostMiddleware() initialized")
	return func(c *gin.Context) {
		hostName := c.Request.Host
		hostParts := strings.Split(hostName, ":")
		if len(hostParts) > 0 {
			hostName = hostParts[0]
		}

		log.Debug("redirectOrAllowHostMiddleware() | Request Received | Host: %s | Path: %s | Method: %s",
			hostName, c.Request.URL.Path, c.Request.Method)

		// Skip redirection for API paths
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			log.Debug("redirectOrAllowHostMiddleware() | Skipping for API Path | Host: %s | Path: %s | Method: %s",
				hostName, c.Request.URL.Path)
			c.Next()
			return
		}

		// Check if the host matches a configured Virtual Host
		vh, ok := virtualHosts[hostName]
		if ok {
			sitePath := filepath.Clean(vh.BasePath)
			requestedFile := filepath.Clean(filepath.Join(sitePath, c.Request.URL.Path))

			if !strings.HasPrefix(requestedFile, sitePath) {
				log.Error("redirectOrAllowHostMiddleware() | Path Traversal Attempt | Host: %s | Path: %s | ResolvedPath: %s",
					hostName, c.Request.URL.Path, requestedFile)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			log.Debug("redirectOrAllowHostMiddleware() | Serving Virtual Host Content | Host: %s | RequestedFile: %s",
				hostName, requestedFile)

			allowedExtensions := map[string]string{
				".css":  "text/css",
				".js":   "application/javascript",
				".png":  "image/png",
				".jpg":  "image/jpeg",
				".jpeg": "image/jpeg",
				".ico":  "image/x-icon",
				".svg":  "image/svg+xml",
				".webp": "image/webp",
				".html": "text/html",
			}
			extension := filepath.Ext(requestedFile)
			if _, err := os.Stat(requestedFile); err == nil {
				contentType, _ := allowedExtensions[extension]
				c.Header("Content-Type", contentType)
				c.Header("X-Content-Type-Options", "nosniff")
				c.Header("X-Frame-Options", "DENY")
				c.File(requestedFile)
				c.Abort()
				return
			} else {
				log.Error("redirectOrAllowHostMiddleware() | File Not Found or Inaccessible | Host: %s | RequestedFile: %s | Error: %v", hostName, requestedFile, err.Error())
			}
		}

		log.Warn("redirectOrAllowHostMiddleware() | Host Not Configured | Host: %s | Path: %s", hostName, c.Request.URL.Path)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
}
