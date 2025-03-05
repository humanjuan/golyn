package routes

import (
	"Back/globals"
	"Back/internal/handlers"
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"path/filepath"
)

func CreateRouteHandler(basePath, fileType string) gin.HandlerFunc {
	log := globals.GetAppLogger()
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
			log.Warn("CreateRouteHandler() | Access denied or file not found | Path: %s", fullPath)
			if err := handlers.RenderError(c.Writer, http.StatusForbidden, utils.GetCodeMessage(http.StatusForbidden)); err != nil {
				c.AbortWithStatus(http.StatusForbidden)
			}
			c.Abort()
			return
		}

		// Set the Content-Type header
		c.Header("Content-Type", contentType)
		fmt.Println(contentType)

		// Serve the file
		log.Debug("CreateRouteHandler() | Serving file: %s with Content-Type: %s", fullPath, contentType)
		c.File(fullPath)
	}
}

func CreateStaticFileHandler(filePath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		if !utils.FileOrDirectoryExists(filePath) {
			log.Warn("CreateRouteHandler() | File not found: %s", filePath)
			err := fmt.Errorf("file not found: %s", filePath)
			c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
			c.Abort()
			return
		}
		c.File(filePath)
	}
}
