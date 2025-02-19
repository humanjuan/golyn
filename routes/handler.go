package routes

import (
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"net/http"
	"path/filepath"
)

func CreateRouteHandler(basePath, fileType string, log *logger.Log) gin.HandlerFunc {
	log.Debug("CreateRouteHandler() | Creating route handler for %s", fileType)
	return func(c *gin.Context) {
		requestedFile := c.Param("filepath")
		fullPath := filepath.Join(basePath, fileType, requestedFile)

		// Validate the file exists and has an allowed extension
		allowedExtensions := map[string]string{
			".css":  "text/css",
			".js":   "application/javascript",
			".png":  "image/png",
			".jpg":  "image/jpeg",
			".jpeg": "image/jpeg",
			".ico":  "image/x-icon",
			".svg":  "image/svg+xml",
			".webp": "image/webp",
		}

		extension := filepath.Ext(fullPath)
		fmt.Println(extension)
		contentType, ok := allowedExtensions[extension]
		if !utils.FileOrDirectoryExists(fullPath) || !ok {
			log.Warn("Access denied or file not found: %s", fullPath)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Set the Content-Type header
		c.Header("Content-Type", contentType)
		fmt.Println(contentType)

		// Serve the file
		log.Debug("Serving file: %s with Content-Type: %s", fullPath, contentType)
		c.File(fullPath)
	}
}

func CreateStaticFileHandler(filePath string, log *logger.Log) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !utils.FileOrDirectoryExists(filePath) {
			log.Warn("File not found: %s", filePath)
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.File(filePath)
	}
}
