package middlewares

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"github.com/unrolled/secure"
)

func SecureMiddleware(isDev bool) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("SecureMiddleware()")
	security := secure.New(secure.Options{
		SSLRedirect:          true,
		SSLTemporaryRedirect: false,
		SSLProxyHeaders:      map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:           63072000,
		STSIncludeSubdomains: true,
		STSPreload:           true,
		FrameDeny:            true,
		ContentTypeNosniff:   false,
		BrowserXssFilter:     true,
		IsDevelopment:        isDev,
		ReferrerPolicy:       "strict-origin-when-cross-origin",
		ContentSecurityPolicy: "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdn.tailwindcss.com; " +
			"style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com https://fonts.googleapis.com; " +
			"font-src 'self' https://fonts.gstatic.com; " +
			"connect-src 'self' https://api.iconify.design https://api.simplesvg.com https://api.unisvg.com; " +
			"img-src 'self' https://humanjuan.com https://www.humanjuan.com https://golyn.humanjuan.com;",
	})

	return func(c *gin.Context) {
		hostParts := strings.Split(c.Request.Host, ":")
		host := hostParts[0]

		// Verify valid certificate
		globals.CertMutex.RLock()
		_, hasCert := globals.Certificates[host]
		isInvalid := globals.InvalidCertificates[host]
		globals.CertMutex.RUnlock()
		log.Debug("SecureMiddleware() | Host: %s | HasCert: %t | IsInvalid: %t | TLS: %v | Path: %s", host, hasCert, isInvalid, c.Request.TLS != nil, c.Request.URL.Path)

		if c.Request.TLS == nil && (isInvalid || !hasCert) {
			log.Debug("SecureMiddleware() | Fallback to HTTP only for host %s | Path: %s", host, c.Request.URL.Path)
			c.Next()
			return
		}

		if c.Request.TLS == nil && hasCert && !isInvalid {
			redirURL := fmt.Sprintf("https://%s%s", host, c.Request.URL.Path)
			c.Redirect(http.StatusMovedPermanently, redirURL)
			log.Debug("SecureMiddleware() | Redirecting to HTTPS for host %s | Path: %s", host, c.Request.URL.Path)
			return
		}

		// HTTPS without valid certificate
		if c.Request.TLS != nil && (isInvalid || !hasCert) {
			err := fmt.Sprintf("no valid certificate found | Host: %s", host)
			log.Error("secureMiddleware() | No valid certificate for HTTPS request | Host: %s | Path: %s | Error: %v", host, c.Request.URL.Path, err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err))
			c.Abort()
			return
		}

		// Security Headers
		err := security.Process(c.Writer, c.Request)
		if err != nil {
			log.Error("secureMiddleware() | An internal server error occurred while processing security. | Error: %v", err.Error())
			err = fmt.Errorf("an internal server error occurred while processing security")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		c.Next()
	}
}
