package middlewares

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"net/http"
	"path/filepath"
	"strings"
)

type CompressionType struct {
	Name      string
	Extension string
}

// CompressionTypes Ordered by priority: Brotli > Zstd > Gzip > Deflate > Normal
var CompressionTypes = []CompressionType{
	{Name: "br", Extension: ".br"},
	{Name: "zstd", Extension: ".zst"},
	{Name: "gzip", Extension: ".gzip"},
	{Name: "deflate", Extension: ".deflate"},
	{Name: "", Extension: ""},
}

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
		siteName := filepath.Base(virtualHost.BasePath)

		// Relative Path
		relativePath := strings.TrimPrefix(cleanPath, siteName)
		relativePath = strings.TrimPrefix(relativePath, "/")
		if relativePath == "" {
			relativePath = "index.html"
		}

		acceptEncoding := c.GetHeader("Accept-Encoding")
		c.Header("Vary", "Accept-Encoding")
		contentType := utils.GetMimeTypeFromCompressedFilePath(relativePath)

		// Priority Order: Brotli > Zstd > Gzip > Deflate > Normal
		for _, compression := range CompressionTypes {
			if strings.Contains(acceptEncoding, compression.Name) && FileExistsCached(c, siteName, relativePath, compression.Name) {
				fullPath := filepath.Join(virtualHost.BasePath, relativePath) + compression.Extension
				if utils.FileOrDirectoryExists(fullPath) {
					c.Header("Content-Type", contentType)
					if compression.Name != "" {
						c.Header("Content-Encoding", compression.Name)
					}
					c.Header("Content-Type", contentType)
					c.File(fullPath)
					c.Abort()
					return
				}
			}
		}

		// Normal file
		if FileExistsCached(c, siteName, relativePath, "normal") {
			fullPath := filepath.Join(virtualHost.BasePath, relativePath)
			if utils.FileOrDirectoryExists(fullPath) {
				contentType := utils.GetMimeTypeFromCompressedFilePath(relativePath)
				c.Header("Content-Type", contentType)
				c.File(fullPath)
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
