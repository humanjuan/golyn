package handlers

import (
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"net/http"
	"path/filepath"
)

func ServeErrorPage(c *gin.Context, log *logger.Log, statusCode int, customMessage string, basePath string, defaultSite string) {
	var errorFile string
	host := c.Request.Host
	path := c.Request.URL.Path

	if basePath != "" {
		errorFile = filepath.Join(basePath, fmt.Sprintf("%d.html", statusCode))
	}

	// Si no existe, usar el global (en golyn)
	if errorFile == "" || !utils.FileOrDirectoryExists(errorFile) {
		log.Warn("serveErrorPage() | Missing Custom Error File | Host: %s | Path: %s | ErrorCode: %s | ExpectedFile: %s",
			host, path, statusCode, errorFile)

		errorFile = filepath.Join(defaultSite, fmt.Sprintf("%d.html", statusCode))
	}

	log.Debug("serveErrorPage() | Checking if file exists | Path:", errorFile)
	if utils.FileOrDirectoryExists(errorFile) {
		log.Info("serveErrorPage() | Serving Custom Error Page | Host: %s | Path: %s | ErrorCode: %s | File: %s",
			host, path, statusCode, errorFile)
		c.Writer.WriteHeader(statusCode)
		c.File(errorFile)
	} else {
		if customMessage == "" {
			customMessage = http.StatusText(statusCode)
		}
		log.Warn("serveErrorPage() | File does not exist | Host: %s | Path: %s | ErrorCode: %s | Message: %s",
			host, path, statusCode, customMessage)

		c.JSON(statusCode, gin.H{
			"message": customMessage,
			"host":    host,
			"path":    path,
			"status":  statusCode,
		})
	}

	c.Abort()
}
