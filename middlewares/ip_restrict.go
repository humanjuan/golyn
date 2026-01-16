package middlewares

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"net/http"
	"strings"
)

// RestrictAPIRequestMiddleware ensures requests only come from allowed domains
func RestrictAPIRequestMiddleware(dev bool) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("RestrictAPIRequestMiddleware() | dev: %v", dev)
	return func(c *gin.Context) {
		hostParts := strings.Split(c.Request.Host, ":")
		host := hostParts[0]

		log.Debug("RestrictAPIRequestMiddleware() | Request Host: %s", host)

		config := globals.GetConfig()
		allowed := false

		for _, site := range config.Sites {
			for _, domain := range site.Domains {
				domain = strings.TrimSpace(domain)
				if strings.ToLower(host) == strings.ToLower(domain) {
					allowed = true
					break
				}
				if dev {
					// In dev mode, also allow .local version of the domains
					devDomain := strings.Replace(domain, ".com", ".local", 1)
					if !strings.HasSuffix(devDomain, ".local") {
						devDomain = devDomain + ".local"
					}
					if strings.ToLower(host) == strings.ToLower(devDomain) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				break
			}
		}

		if !allowed {
			err := fmt.Errorf("access denied for host %s", host)
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			log.Warn("RestrictAPIRequestMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
			return
		}

		c.Next()
	}
}
