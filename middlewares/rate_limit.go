package middlewares

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"golyn/globals"
	"golyn/internal/utils"
	"net/http"
	"time"
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

		host := c.Request.Host
		if _, exists := virtualHosts[host]; !exists {
			log.Warn("RateLimitMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
			err = fmt.Errorf("access denied for host %s", host)
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		ip := c.ClientIP()
		key := fmt.Sprintf("ratelimit:%s%s", host, ip)
		limit := virtualHosts[host].SMTP.RateLimitRequests
		if limit <= 0 {
			limit = 5
		}

		count, found := srvCache.Get(key)
		var currentCount int
		if !found {
			currentCount = 1
			srvCache.Set(key, currentCount, time.Hour)
		} else {
			currentCount = count.(int) + 1
			srvCache.Set(key, currentCount, cache.DefaultExpiration)
			if currentCount > limit {
				log.Warn("RateLimitMiddleware() | Rate limit exceeded | Host: %s | IP: %s | Count: %d | Limit: %d", host, ip, currentCount, limit)
				err = fmt.Errorf("rate limit exceeded for host %s", host)
				c.Error(utils.NewHTTPError(http.StatusTooManyRequests, err.Error()))
				c.Abort()
				return
			}
		}

		log.Debug("RateLimitMiddleware() | Access granted | Host: %s | IP: %s | Count: %d | Limit: %d", host, ip, currentCount, limit)
		c.Next()
	}
}
