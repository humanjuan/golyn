package routes

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/handlers"
	"github.com/humanjuan/golyn/internal/utils"
	"mime"
	"net/http"
	"path/filepath"
)

func CreateRouteHandler(basePath, fileType string) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("CreateRouteHandler() | Creating route handler for %s", fileType)
	return func(c *gin.Context) {
		requestedFile := c.Param("filepath")
		fullPath := filepath.Join(basePath, fileType, requestedFile)

		contentType, ok := utils.GetAllowedMime(fullPath)
		if !ok {
			log.Warn("CreateRouteHandler() | Extension not allowed | Path: %s", fullPath)
			if err := handlers.RenderError(c, http.StatusForbidden, utils.GetCodeMessage(http.StatusForbidden)); err != nil {
				c.AbortWithStatus(http.StatusForbidden)
			}
			c.Abort()
			return
		}

		if !utils.FileOrDirectoryExists(fullPath) {
			log.Warn("CreateRouteHandler() | File not found | Path: %s", fullPath)
			if err := handlers.RenderError(c, http.StatusNotFound, utils.GetCodeMessage(http.StatusNotFound)); err != nil {
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
		if c.IsAborted() {
			log.Debug("CreateStaticFileHandler() | Request already aborted, skipping for: %s", filePath)
			return
		}

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
