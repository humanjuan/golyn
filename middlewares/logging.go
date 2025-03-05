package middlewares

import (
	"Back/globals"
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"time"
)

func LoggingMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("LoggingMiddleware()")
	if log == nil {
		panic("[ERROR] LoggingMiddleware received a nil logger instance.")
	}
	return func(c *gin.Context) {
		gin.DefaultWriter = log
		gin.DefaultErrorWriter = log

		start := time.Now()
		id := fmt.Sprintf("%06d", start.Nanosecond()/1e6)
		clientIP := c.ClientIP()
		host := c.Request.Host
		method := c.Request.Method
		path := c.Request.URL.Path
		userAgent := c.Request.UserAgent()

		log.Info("Request | ClientIP: %s | ID: %v | Method: %s | Host: %s | Path: %s | Start: %s | UserAgent: %s",
			clientIP, id, method, host, path, start, userAgent)

		// Process the request
		c.Next()

		// Log request details
		end := time.Now()
		latency := end.Sub(start)
		clientIP = c.ClientIP()
		host = c.Request.Host
		method = c.Request.Method
		path = c.Request.URL.Path
		statusCode := c.Writer.Status()
		userAgent = c.Request.UserAgent()

		log.Info("Respond | ClientIP: %s | ID: %v | Method: %s | Host: %s | Path: %s | StatusCode: %d | Description: %s | Latency: %s | UserAgent: %s",
			clientIP, id, method, host, path, statusCode, utils.GetCodeMessage(statusCode), latency, userAgent)
	}
}
