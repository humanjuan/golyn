package middlewares

import (
	"Back/globals"
	"Back/internal/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func CompressionMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("CompressionMiddleware()")
	virtualHosts := globals.VirtualHosts
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Next()
			return
		}

		host := c.Request.Host
		virtualHost, ok := virtualHosts[host]
		if !ok {
			c.Next()
			return
		}

		requestPath := c.Request.URL.Path
		cleanPath := strings.TrimPrefix(requestPath, "/")
		fullPath := filepath.Join(virtualHost.BasePath, cleanPath)
		if requestPath == "/" {
			fullPath = filepath.Join(virtualHost.BasePath, "index.html")
		}

		contentType := utils.GetMimeTypeFromCompressedFilePath(fullPath)

		acceptEncoding := c.GetHeader("Accept-Encoding")
		c.Header("Vary", "Accept-Encoding")

		// Brotli
		if strings.Contains(acceptEncoding, "br") && fileExists(fullPath+".br") {
			if fileExists(fullPath + ".br") {
				c.Header("Content-Encoding", "br")
				c.Header("Content-Type", contentType)
				c.File(fullPath + ".br")
				c.Abort()
				return
			}
		}

		// Gzip
		if strings.Contains(acceptEncoding, "gzip") && fileExists(fullPath+".gz") {
			if fileExists(fullPath + ".gz") {
				c.Header("Content-Encoding", "gzip")
				c.Header("Content-Type", contentType)
				c.File(fullPath + ".gz")
				c.Abort()
				return
			}
		}

		// Normal file
		if fileExists(fullPath) {
			c.Header("Content-Type", contentType)
			c.File(fullPath)
			c.Abort()
			return
		}

		c.Next()
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
