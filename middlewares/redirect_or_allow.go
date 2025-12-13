package middlewares

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
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
				".css":   "text/css",
				".js":    "application/javascript",
				".png":   "image/png",
				".jpg":   "image/jpeg",
				".jpeg":  "image/jpeg",
				".gif":   "image/gif",
				".ico":   "image/x-icon",
				".svg":   "image/svg+xml",
				".webp":  "image/webp",
				".html":  "text/html; charset=utf-8",
				".json":  "application/json",
				".txt":   "text/plain; charset=utf-8",
				".xml":   "application/xml",
				".map":   "application/octet-stream",
				".woff":  "font/woff",
				".woff2": "font/woff2",
				".wasm":  "application/wasm",
			}

			// Case 1: Physical file exists -> serve it with proper headers
			if fi, err := os.Stat(requestedFile); err == nil && !fi.IsDir() {
				extension := filepath.Ext(requestedFile)
				if contentType, ok := allowedExtensions[extension]; ok {
					c.Header("Content-Type", contentType)
				}
				c.Header("X-Content-Type-Options", "nosniff")
				c.Header("X-Frame-Options", "DENY")
				c.File(requestedFile)
				c.Abort()
				return
			}

			// Case 2: No physical file -> SPA fallback for routes without extension
			spaIndex := filepath.Join(sitePath, "index.html")
			pathHasExt := strings.Contains(c.Request.URL.Path, ".")
			if !pathHasExt {
				if fi, err := os.Stat(spaIndex); err == nil && !fi.IsDir() {
					c.Header("Content-Type", "text/html; charset=utf-8")
					c.File(spaIndex)
					c.Abort()
					return
				}
				// index.html missing -> 404
				err := fmt.Errorf("SPA index not found: %s", spaIndex)
				c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
				c.Abort()
				return
			}

			// Path has extension and file not found -> don't hide asset errors
			log.Warn("redirectOrAllowHostMiddleware() | File Not Found | Host: %s | RequestedFile: %s", hostName, requestedFile)
			err := fmt.Errorf("the requested resource was not found: %s", c.Request.URL.Path)
			c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
			c.Abort()
			return
		}

		// Host not configured
		log.Warn("redirectOrAllowHostMiddleware() | Host Not Configured | Host: %s | Path: %s", hostName, c.Request.URL.Path)
		err := fmt.Errorf("the requested route does not exist: %s", c.Request.URL.Path)
		c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
		c.Abort()
	}
}
