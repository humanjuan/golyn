package middlewares

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

func RedirectOrAllowHostMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("redirectOrAllowHostMiddleware() initialized")
	virtualHosts := globals.VirtualHosts

	return func(c *gin.Context) {
		if c.IsAborted() {
			return
		}

		hostName := c.Request.Host
		hostParts := strings.Split(hostName, ":")
		if len(hostParts) > 0 {
			hostName = hostParts[0]
		}

		log.Debug("redirectOrAllowHostMiddleware() | Request Received | Host: %s | Path: %s | Method: %s",
			hostName, c.Request.URL.Path, c.Request.Method)

		// Check if the host matches a configured Virtual Host
		vh, ok := virtualHosts[hostName]
		if ok {
			// If it's a proxy, we don't handle files here, let the proxy handler do its job
			if vh.Proxy {
				log.Debug("redirectOrAllowHostMiddleware() | Proxy Host Detected | Host: %s | Passing to next handler", hostName)
				c.Next()
				return
			}

			// Skip redirection for API paths for non-proxy hosts
			if strings.HasPrefix(c.Request.URL.Path, "/api") {
				log.Debug("redirectOrAllowHostMiddleware() | Skipping for API Path | Host: %s | Path: %s | Method: %s",
					hostName, c.Request.URL.Path, c.Request.Method)
				c.Next()
				return
			}

			sitePath := filepath.Clean(vh.BasePath)
			urlPath := strings.TrimPrefix(c.Request.URL.Path, "/")
			requestedFile := filepath.Clean(filepath.Join(sitePath, urlPath))

			sitePathWithSep := sitePath
			if !strings.HasSuffix(sitePathWithSep, string(filepath.Separator)) {
				sitePathWithSep += string(filepath.Separator)
			}
			if !strings.HasPrefix(requestedFile+string(filepath.Separator), sitePathWithSep) {
				log.Error("redirectOrAllowHostMiddleware() | Path Traversal Attempt | Host: %s | Path: %s | ResolvedPath: %s",
					hostName, c.Request.URL.Path, requestedFile)
				log.Sync()
				err := fmt.Errorf("access to the requested resources is restricted")
				c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
				c.Abort()
				return
			}

			log.Debug("redirectOrAllowHostMiddleware() | Serving Virtual Host Content | Host: %s | RequestedFile: %s",
				hostName, requestedFile)

			if fi, err := os.Stat(requestedFile); err == nil && !fi.IsDir() {
				if contentType, ok := utils.GetAllowedMime(requestedFile); ok {
					c.Writer.Header().Set("Content-Type", contentType)
				}
				c.File(requestedFile)
				c.Abort()
				return
			}

			spaIndex := filepath.Join(sitePath, "index.html")
			pathHasExt := strings.Contains(c.Request.URL.Path, ".")
			if !pathHasExt {
				if fi, err := os.Stat(spaIndex); err == nil && !fi.IsDir() {
					c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
					c.File(spaIndex)
					c.Abort()
					return
				}

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

		// Host isn't configured
		log.Warn("redirectOrAllowHostMiddleware() | Host Not Configured | Host: %s | Path: %s", hostName, c.Request.URL.Path)
		err := fmt.Errorf("the requested route does not exist: %s", c.Request.URL.Path)
		c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
		c.Abort()
	}
}
