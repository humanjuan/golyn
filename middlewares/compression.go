package middlewares

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

type CompressionType struct {
	Name      string
	Extension string
}

// CompressionTypes Ordered by priority: Brotli > Zstd > Gzip > Deflate > Normal
var CompressionTypes = []CompressionType{
	{Name: "br", Extension: ".br"},
	{Name: "zstd", Extension: ".zst"},
	{Name: "gzip", Extension: ".gz"},
	{Name: "deflate", Extension: ".deflate"},
	{Name: "", Extension: ""},
}

func CompressionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.IsAborted() {
			return
		}
		virtualHosts := globals.VirtualHosts
		host := strings.Split(c.Request.Host, ":")[0]

		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Next()
			return
		}

		requestPath := c.Request.URL.Path
		vhs, ok := virtualHosts[host]
		if !ok {
			c.Next()
			return
		}

		var vh *app.VirtualHost
		for i := range vhs {
			if vhs[i].PathPrefix == "/" || strings.HasPrefix(requestPath, vhs[i].PathPrefix) {
				vh = &vhs[i]
				break
			}
		}

		if vh == nil {
			c.Next()
			return
		}

		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Next()
			return
		}

		cleanPath := strings.TrimPrefix(requestPath, "/")

		// Relative Path calculation
		siteName := filepath.Base(vh.BasePath)
		var relativePath string
		if vh.PathPrefix != "/" {
			relativePath = strings.TrimPrefix(requestPath, vh.PathPrefix)
		} else if strings.HasPrefix(cleanPath, siteName+"/") || cleanPath == siteName {
			relativePath = strings.TrimPrefix(cleanPath, siteName)
		} else {
			relativePath = cleanPath
		}
		relativePath = strings.TrimPrefix(relativePath, "/")
		if relativePath == "" {
			relativePath = "index.html"
		}

		acceptEncoding := c.GetHeader("Accept-Encoding")
		{
			existing := c.Writer.Header().Get("Vary")
			if existing == "" {
				c.Writer.Header().Set("Vary", "Accept-Encoding")
			} else if !strings.Contains(strings.ToLower(existing), "accept-encoding") {
				c.Writer.Header().Set("Vary", existing+", Accept-Encoding")
			}
		}
		contentType := utils.GetMimeTypeFromCompressedFilePath(relativePath)

		// Priority Order: Brotli > Zstd > Gzip > Deflate > Normal
		for _, compression := range CompressionTypes {
			if compression.Name != "" && strings.Contains(acceptEncoding, compression.Name) {
				if FileExistsCached(c, siteName, relativePath, compression.Name) {
					fullPath := filepath.Join(vh.BasePath, relativePath) + compression.Extension
					if utils.FileOrDirectoryExists(fullPath) {
						// Set headers and serve compressed file
						c.Writer.Header().Set("Content-Type", contentType)
						c.Writer.Header().Set("Content-Encoding", compression.Name)
						c.File(fullPath)
						c.Abort()
						return
					}
				}
			}
		}

		// Normal file
		if FileExistsCached(c, siteName, relativePath, "normal") {
			fullPath := filepath.Join(vh.BasePath, relativePath)
			if utils.FileOrDirectoryExists(fullPath) {
				contentType := utils.GetMimeTypeFromCompressedFilePath(relativePath)
				c.Writer.Header().Set("Content-Type", contentType)
				c.File(fullPath)
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
