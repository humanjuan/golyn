package middlewares

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

func CSRFMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	// Removed redundant Debug log inside handler to avoid noise if needed,
	// but kept it if you want to see every check.

	return func(c *gin.Context) {
		// Only check state-changing methods
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions || method == http.MethodTrace {
			c.Next()
			return
		}

		if log != nil {
			log.Debug("CSRFMiddleware() | Checking CSRF for %s %s", method, c.Request.URL.Path)
		}

		host := strings.Split(c.Request.Host, ":")[0]

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

		if token == "" {
			log.Warn("CSRFMiddleware() | CSRF token missing in request | Host: %s | URL: %s", host, c.Request.URL)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "csrf token missing"))
			c.Abort()
			return
		}

		if token != cookie {
			log.Warn("CSRFMiddleware() | CSRF token mismatch | Host: %s | URL: %s", host, c.Request.URL)
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
	host := strings.Split(c.Request.Host, ":")[0]

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Error("GenerateCSRFToken() | Unable to generate CSRF token. %s", err.Error())
		c.Error(utils.NewHTTPError(http.StatusInternalServerError, "unable to generate csrf token"))
		c.Abort()
		return
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	c.SetSameSite(utils.StringToSameSite(globals.GetConfig().Server.CookieSameSite))
	c.SetCookie("csrf_token", token, int(time.Hour.Seconds()), "/", globals.GetConfig().Server.CookieDomain, globals.GetConfig().Server.CookieSecure, globals.GetConfig().Server.CookieHttpOnly)
	log.Debug("GenerateCSRFToken() | CSRF token generated for %s", host)
	c.JSON(http.StatusOK, gin.H{
		"csrf_token": token,
	})
}
