package middlewares

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

func CSRFMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("CSRFMiddleware()")

	return func(c *gin.Context) {
		virtualhosts := globals.VirtualHosts
		if c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		host := c.Request.Host
		if _, exists := virtualhosts[host]; !exists {
			log.Warn("CSRFMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "Host not configured in VirtualHosts"))
			c.Abort()
			return
		}

		cookie, err := c.Cookie("csrf_token")
		if err != nil {
			log.Warn("CSRFMiddleware() | No CSRF token found in cookie | Host: %s | URL: %s", host, c.Request.URL)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "no csrf token found in cookie"))
			c.Abort()
			return
		}

		token := c.Request.Header.Get("X-CSRF-Token")
		if token == "" {
			token = c.PostForm("csrf_token")
		}

		if token == "" || token != cookie {
			log.Warn("CSRFMiddleware() | Invalid CSRF token | Host: %s | URL: %s", host, c.Request.URL)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "invalid csrf token"))
			c.Abort()
			return
		}
		c.Next()
	}
}

func GenerateCSRFToken(c *gin.Context) {
	log := globals.GetAppLogger()
	log.Debug("GenerateCSRFToken()")
	virtualhosts := globals.VirtualHosts
	host := c.Request.Host

	if _, exists := virtualhosts[host]; !exists {
		log.Warn("GenerateCSRFToken() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
		c.Error(utils.NewHTTPError(http.StatusForbidden, "Host not configured in VirtualHosts"))
		c.Abort()
		return
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Error("GenerateCSRFToken() | Unable to generate CSRF token. %s", err.Error())
		c.Error(utils.NewHTTPError(http.StatusInternalServerError, "unable to generate csrf token"))
		c.Abort()
		return
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	c.SetCookie("csrf_token", token, int(time.Hour.Seconds()), "/", "", !globals.GetConfig().Server.Dev, false)
	log.Debug("GenerateCSRFToken() | CSRF token generated for %s", host)
	c.JSON(http.StatusOK, gin.H{
		"csrf_token": token,
	})
}
