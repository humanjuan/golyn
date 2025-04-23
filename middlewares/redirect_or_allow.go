package middlewares

import (
	"Back/globals"
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func RedirectOrAllowHostMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("redirectOrAllowHostMiddleware() initialized")
	virtualHosts := globals.VirtualHosts

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
				hostName, c.Request.URL.Path, c.Request.Method)
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
				err := fmt.Errorf("access to the requested resources is restricted")
				c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
				c.Abort()
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
				log.Warn("redirectOrAllowHostMiddleware() | File Not Found or Inaccessible | Host: %s | RequestedFile: %s | Error: %v", hostName, requestedFile, err.Error())
			}
		}

		log.Warn("redirectOrAllowHostMiddleware() | Host Not Configured | Host: %s | Path: %s", hostName, c.Request.URL.Path)
		err := fmt.Errorf("the requested route does not exist: %s", c.Request.URL.Path)
		c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
		c.Abort()
	}
}
