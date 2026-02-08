package middlewares

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
)

func CorsMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			c.Next()
			return
		}

		host := strings.Split(c.Request.Host, ":")[0]

		var security loaders.Security
		if cfg, exists := c.Get("site_config"); exists {
			if siteCfg, ok := cfg.(loaders.SiteConfig); ok {
				security = siteCfg.Security
			}
		}

		if security.AllowOrigin == nil {
			if vh, ok := globals.VirtualHosts[host]; ok {
				security = vh.Security
			}
		}

		if len(security.AllowOrigin) > 0 {
			allowed := false
			isWildcard := false
			for _, allowedOrigin := range security.AllowOrigin {
				allowedOrigin = strings.TrimSpace(allowedOrigin)
				if allowedOrigin == "*" {
					isWildcard = true
					allowed = true
				}

				// Exact match
				if origin == allowedOrigin || (origin == "null" && allowedOrigin != "*") {
					allowed = true
					break
				}

				// Dev mode: Allow same domain with different port
				config := globals.GetConfig()
				if config.Server.Dev && !allowed {
					parsedOrigin, err := url.Parse(origin)
					parsedAllowed, err2 := url.Parse(allowedOrigin)
					if err == nil && err2 == nil {
						if parsedOrigin.Hostname() == parsedAllowed.Hostname() &&
							parsedOrigin.Scheme == parsedAllowed.Scheme {
							log.Debug("CorsMiddleware() | Allowing dev origin by hostname match | Origin: %s | AllowedBase: %s", origin, allowedOrigin)
							allowed = true
							break
						}
					}
				}
			}

			if allowed {
				// Prohibit "*" when Allow-Credentials: true.
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
				c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-CSRF-Token, X-Requested-With")

				if !isWildcard {
					c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
				} else {
					log.Debug("CorsMiddleware() | Credentials disabled for wildcard origin | Host: %s", host)
				}
			} else {
				log.Warn("CorsMiddleware() | Origin not allowed | Host: %s | Origin: %s", host, origin)
			}
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
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
