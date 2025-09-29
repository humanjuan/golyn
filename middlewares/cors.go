package middlewares

import (
	"Back/config/loaders"
	"Back/globals"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/logger"
	"net/http"
	"net/url"
)

func CorsMiddleware(sites []loaders.SiteConfig) gin.HandlerFunc {
	log := globals.GetAppLogger()
	allowedOrigins := getAllowedOrigins(sites, log)
	originMap := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		originMap[origin] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// check if origins it's allow
		if _, ok := originMap[origin]; ok {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// handle request pre-flight (OPTIONS)
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

func getAllowedOrigins(sites []loaders.SiteConfig, log *logger.Log) []string {
	originSet := make(map[string]struct{})
	var allowedOrigins []string

	for _, siteConfig := range sites {
		if !siteConfig.Enabled {
			continue
		}
		for _, origin := range siteConfig.Security.AllowOrigin {
			if !isValidURL(origin) {
				log.Warn("getAllowedOrigins() | Origin URL is not valid | Site: %s | Origin URL: %s", siteConfig.Directory, origin)
				continue
			}
			originSet[origin] = struct{}{}
		}
	}
	for origin := range originSet {
		allowedOrigins = append(allowedOrigins, origin)
	}
	// fmt.Print(allowedOrigins)
	return allowedOrigins
}

func isValidURL(u string) bool {
	parsedURL, err := url.ParseRequestURI(u)
	if err != nil {
		return false
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}

	return true
}
