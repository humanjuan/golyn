package middlewares

import (
	"Back/globals"
	"Back/internal/utils"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func CSRFMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("CSRFMiddleware()")
	virtualhosts := globals.VirtualHosts
	var err error
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		host := c.Request.Host
		if _, exists := virtualhosts[host]; !exists {
			log.Warn("CSRFMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
			err = fmt.Errorf("access denied for host %s", host)
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		cookie, err := c.Cookie("csrf_token")
		if err != nil {
			log.Warn("CSRFMiddleware() | No CSRF token found in cookie | Host: %s | URL: %s", host, c.Request.URL)
			err = fmt.Errorf("no csrf token found in cookie")
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		token := c.Request.Header.Get("X-CSRF-Token")
		if token != "" {
			token = c.PostForm("csrf_token")
		}

		if token == "" || token != cookie {
			log.Warn("CSRFMiddleware() | Invalid CSRF token | Host: %s | URL: %s", host, c.Request.URL)
			err = fmt.Errorf("invalid csrf token")
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
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
	var err error

	if _, exists := virtualhosts[host]; !exists {
		log.Warn("CSRFMiddleware() | Access denied | Host: %s | URL: %s", host, c.Request.URL)
		err = fmt.Errorf("access denied for host %s", host)
		c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
		c.Abort()
		return
	}

	tokenBytes := make([]byte, 32)
	if _, err = rand.Read(tokenBytes); err != nil {
		log.Error("GenerateCSRFToken() | Unable to generate CSRF token. %s", err.Error())
		err = fmt.Errorf("unable to generate csrf token")
		c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
		c.Abort()
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	c.SetCookie("csrf_token", token, int(time.Hour.Seconds()), "/", host, true, true)
	log.Debug("GenerateCSRFToken() | CSRF token generated for %s", host)
	c.JSON(http.StatusOK, gin.H{
		"csrf_token": token,
	})
}
