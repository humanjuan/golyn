package middlewares

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

func RateLimitMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	virtualHosts := globals.VirtualHosts
	var err error
	log.Debug("RateLimitMiddleware()")

	return func(c *gin.Context) {
		srvCache := GetCache(c)
		if srvCache == nil {
			log.Error("RateLimitMiddleware() | serverCache is nil")
			return
		}

		host := strings.Split(c.Request.Host, ":")[0]
		vh, exists := virtualHosts[host]
		if !exists {
			log.Warn("RateLimitMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
			err = fmt.Errorf("access denied for host %s", host)
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		ip := c.ClientIP()
		key := fmt.Sprintf("ratelimit:%s:%s", host, ip)

		// Determine limit: VirtualHost specific > Global Config > Default (10)
		limit := 10
		config := globals.GetConfig()
		if config.Server.RateLimitRequests > 0 {
			limit = config.Server.RateLimitRequests
		}
		if vh.SMTP.RateLimitRequests > 0 {
			limit = vh.SMTP.RateLimitRequests
		}

		count, found := srvCache.Get(key)
		var currentCount int
		if !found {
			currentCount = 1
			srvCache.Set(key, currentCount, time.Minute)
		} else {
			currentCount = count.(int) + 1
			srvCache.Set(key, currentCount, time.Minute)
			if currentCount > limit {
				log.Warn("RateLimitMiddleware() | Rate limit exceeded | Host: %s | IP: %s | Count: %d | Limit: %d", host, ip, currentCount, limit)
				c.Header("Retry-After", "60")
				err = fmt.Errorf("rate limit exceeded, please try again later")
				c.Error(utils.NewHTTPError(http.StatusTooManyRequests, err.Error()))
				c.Abort()
				return
			}
		}

		log.Debug("RateLimitMiddleware() | Access granted | Host: %s | IP: %s | Count: %d | Limit: %d", host, ip, currentCount, limit)
		c.Next()
	}
}
