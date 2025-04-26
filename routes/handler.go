package routes

import (
	"Back/globals"
	"Back/internal/handlers"
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

func CreateRouteHandler(basePath, fileType string) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("CreateRouteHandler() | Creating route handler for %s", fileType)
	return func(c *gin.Context) {
		requestedFile := c.Param("filepath")
		fullPath := filepath.Join(basePath, fileType, requestedFile)
		originalPath := strings.TrimSuffix(fullPath, ".br")
		originalPath = strings.TrimSuffix(originalPath, ".gz")

		contentType, ok := utils.GetAllowedMime(fullPath)
		if !ok {
			log.Warn("CreateRouteHandler() | Extension not allowed | Path: %s", fullPath)
			if err := handlers.RenderError(c.Writer, http.StatusForbidden, utils.GetCodeMessage(http.StatusForbidden)); err != nil {
				c.AbortWithStatus(http.StatusForbidden)
			}
			c.Abort()
			return
		}

		//contentType := utils.GetMimeTypeFromCompressedFilePath(fullPath)

		if !utils.FileOrDirectoryExists(fullPath) {
			log.Warn("CreateRouteHandler() | File not found | Path: %s", fullPath)
			if err := handlers.RenderError(c.Writer, http.StatusNotFound, utils.GetCodeMessage(http.StatusNotFound)); err != nil {
				c.AbortWithStatus(http.StatusNotFound)
			}
			c.Abort()
			return
		}

		// Set the Content-Type header
		c.Header("Content-Type", contentType)
		log.Debug("CreateRouteHandler() | Serving file: %s with Content-Type: %s", fullPath, contentType)
		c.File(fullPath)
	}
}

func CreateStaticFileHandler(filePath string) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("CreateStaticFileHandler() | Serving file: %s", filePath)
	return func(c *gin.Context) {
		ext := filepath.Ext(filePath)
		contentType := mime.TypeByExtension(ext)
		if !utils.FileOrDirectoryExists(filePath) {
			log.Warn("CreateRouteHandler() | File not found: %s", filePath)
			err := fmt.Errorf("file not found: %s", filePath)
			c.Error(utils.NewHTTPError(http.StatusNotFound, err.Error()))
			c.Abort()
			return
		}
		c.Header("Content-Type", contentType)
		c.File(filePath)
	}
}
