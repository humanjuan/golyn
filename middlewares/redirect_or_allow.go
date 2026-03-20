package middlewares

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
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

		hostParts := strings.Split(c.Request.Host, ":")
		host := strings.ToLower(hostParts[0])

		log.Debug("redirectOrAllowHostMiddleware() | Request Received | Host: %s | Path: %s | Method: %s",
			host, c.Request.URL.Path, c.Request.Method)

		// Check if the host matches a configured Virtual Host
		vhs, ok := virtualHosts[host]
		if ok {
			var vh *app.VirtualHost
			path := c.Request.URL.Path

			// Find matching VH by path prefix (they are already sorted by prefix length descending)
			for i := range vhs {
				if vhs[i].PathPrefix == "/" || strings.HasPrefix(path, vhs[i].PathPrefix) {
					vh = &vhs[i]
					break
				}
			}

			if vh == nil {
				// Should not happen if at least one VH has prefix "/"
				log.Warn("redirectOrAllowHostMiddleware() | No matching VirtualHost for path | Host: %s | Path: %s", host, path)
				c.Next()
				return
			}

			// If it's a proxy, we don't handle files here, let the proxy handler do its job
			if vh.Proxy {
				log.Debug("redirectOrAllowHostMiddleware() | Proxy Host Detected | Host: %s | Prefix: %s | Passing to next handler", host, vh.PathPrefix)
				c.Next()
				return
			}

			// Skip redirection for API paths for non-proxy hosts
			if strings.HasPrefix(path, "/api") {
				log.Debug("redirectOrAllowHostMiddleware() | Skipping for API Path | Host: %s | Path: %s | Method: %s",
					host, path, c.Request.Method)
				c.Next()
				return
			}

			sitePath := filepath.Clean(vh.BasePath)
			urlPath := strings.TrimPrefix(path, "/")

			// If there's a prefix, remove it from the urlPath for file lookup
			if vh.PathPrefix != "/" {
				urlPath = strings.TrimPrefix(path, vh.PathPrefix)
				urlPath = strings.TrimPrefix(urlPath, "/")
			}

			requestedFile := filepath.Clean(filepath.Join(sitePath, urlPath))

			sitePathWithSep := sitePath
			if !strings.HasSuffix(sitePathWithSep, string(filepath.Separator)) {
				sitePathWithSep += string(filepath.Separator)
			}
			if !strings.HasPrefix(requestedFile+string(filepath.Separator), sitePathWithSep) {
				log.Error("redirectOrAllowHostMiddleware() | Path Traversal Attempt | Host: %s | Path: %s | ResolvedPath: %s",
					host, path, requestedFile)
				log.Sync()
				err := fmt.Errorf("access to the requested resources is restricted")
				c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
				c.Abort()
				return
			}

			log.Debug("redirectOrAllowHostMiddleware() | Serving Virtual Host Content | Host: %s | Prefix: %s | RequestedFile: %s",
				host, vh.PathPrefix, requestedFile)

			// Delegate known static paths to Gin's router group handlers
			if strings.HasPrefix(urlPath, "style/") ||
				strings.HasPrefix(urlPath, "js/") ||
				strings.HasPrefix(urlPath, "assets/") {
				log.Debug("redirectOrAllowHostMiddleware() | Delegating static resource to Gin | Path: %s", path)
				c.Next()
				return
			}

			if fi, err := os.Stat(requestedFile); err == nil && !fi.IsDir() {
				if contentType, ok := utils.GetAllowedMime(requestedFile); ok {
					c.Writer.Header().Set("Content-Type", contentType)
				}
				c.File(requestedFile)
				c.Abort()
				return
			}

			spaIndex := filepath.Join(sitePath, "index.html")
			pathHasExt := strings.Contains(path, ".")
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
			log.Warn("redirectOrAllowHostMiddleware() | File Not Found | Host: %s | RequestedFile: %s", host, requestedFile)
			err := fmt.Errorf("the requested resource was not found: %s", path)
			c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
			c.Abort()
			return
		}

		// Host isn't configured
		log.Warn("redirectOrAllowHostMiddleware() | Host Not Configured | Host: %s | Path: %s", host, c.Request.URL.Path)
		err := fmt.Errorf("the requested route does not exist: %s", c.Request.URL.Path)
		c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
		c.Abort()
	}
}
