package middlewares

import (
	"fmt"
	"golyn/globals"
	"golyn/internal/utils"
	"time"

	"github.com/gin-gonic/gin"
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
		// Expose request id for downstream use
		c.Writer.Header().Set("X-Request-Id", id)

		clientIP := c.ClientIP()
		host := c.Request.Host
		method := c.Request.Method
		path := c.Request.URL.Path
		proto := c.Request.Proto
		query := c.Request.URL.RawQuery
		referer := c.Request.Referer()
		xff := c.Request.Header.Get("X-Forwarded-For")
		userAgent := c.Request.UserAgent()

		log.Info("Request | ClientIP: %s | XFF: %s | ID: %v | Proto: %s | Method: %s | Host: %s | Path: %s | Query: %q | Referer: %q | Start: %s | UserAgent: %s",
			clientIP, xff, id, proto, method, host, path, query, referer, start, userAgent)

		// Process the request
		c.Next()

		// Log request details
		end := time.Now()
		latency := end.Sub(start)
		clientIP = c.ClientIP()
		host = c.Request.Host
		method = c.Request.Method
		path = c.Request.URL.Path
		proto = c.Request.Proto
		query = c.Request.URL.RawQuery
		referer = c.Request.Referer()
		xff = c.Request.Header.Get("X-Forwarded-For")
		statusCode := c.Writer.Status()
		bytesWritten := c.Writer.Size()
		userAgent = c.Request.UserAgent()

		log.Info("Respond | ClientIP: %s | XFF: %s | ID: %v | Proto: %s | Method: %s | Host: %s | Path: %s | Query: %q | StatusCode: %d | Description: %s | Bytes: %d | Latency: %s | Referer: %q | UserAgent: %s",
			clientIP, xff, id, proto, method, host, path, query, statusCode, utils.GetCodeMessage(statusCode), bytesWritten, latency, referer, userAgent)
	}
}
