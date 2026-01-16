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

	baseOptions := secure.Options{
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
			// Scripts (OAuth, CDNs, modern frameworks)
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' " +
			"https://code.jquery.com " +
			"https://cdn.jsdelivr.net " +
			"https://cdn.tailwindcss.com " +
			"https://apis.google.com " +
			"https://accounts.google.com " +
			"https://login.microsoftonline.com; " +

			// Styles (Google Fonts, Tailwind CDN, Bootstrap)
			"style-src 'self' 'unsafe-inline' " +
			"https://fonts.googleapis.com " +
			"https://cdn.jsdelivr.net " +
			"https://stackpath.bootstrapcdn.com; " +

			// Fonts
			"font-src 'self' data: " +
			"https://fonts.gstatic.com " +
			"https://cdn.jsdelivr.net; " +

			// Connections (APIs, OAuth, AWS, icons)
			"connect-src 'self' " +
			"https://www.googleapis.com " +
			"https://graph.microsoft.com " +
			"https://login.microsoftonline.com " +
			"https://api.iconify.design " +
			"https://api.simplesvg.com " +
			"https://api.unisvg.com " +
			"https://*.amazonaws.com; " +

			// Images (CDNs, OAuth avatars, multisite)
			"img-src 'self' data: blob: " +
			"https://*.googleusercontent.com " +
			"https://*.amazonaws.com " +
			"https://cdn.jsdelivr.net " +
			"https://*.humanjuan.com; " +

			// Frames (external login)
			"frame-src 'self' " +
			"https://accounts.google.com " +
			"https://login.microsoftonline.com; " +

			// Forms (OAuth callbacks)
			"form-action 'self' " +
			"https://accounts.google.com " +
			"https://login.microsoftonline.com; " +

			// Workers (modern apps)
			"worker-src 'self' blob:; " +

			// Media (videos, audio)
			"media-src 'self' blob:; " +

			// Additional security
			"base-uri 'self'; " +
			"object-src 'none'; " +
			"frame-ancestors 'self';",
	}

	return func(c *gin.Context) {
		hostParts := strings.Split(c.Request.Host, ":")
		host := hostParts[0]

		// Get per-site security config if available
		virtualHosts := globals.VirtualHosts
		var siteCSP string
		if vh, ok := virtualHosts[host]; ok {
			siteCSP = vh.Security.ContentSecurityPolicy
		}

		options := baseOptions
		if siteCSP != "" {
			options.ContentSecurityPolicy = siteCSP
		}
		security := secure.New(options)

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
			// Do not redirect to HTTPS for API paths
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				log.Debug("SecureMiddleware() | Skipping HTTPS redirection for API path | Host: %s | Path: %s", host, c.Request.URL.Path)
				c.Next()
				return
			}

			redirURL := fmt.Sprintf("https://%s%s", host, c.Request.URL.Path)
			c.Redirect(http.StatusMovedPermanently, redirURL)
			log.Debug("SecureMiddleware() | Redirecting to HTTPS for host %s | Path: %s", host, c.Request.URL.Path)
			return
		}

		// HTTPS without valid certificate
		if c.Request.TLS != nil && (isInvalid || !hasCert) {
			err := fmt.Sprintf("no valid certificate found | Host: %s", host)
			log.Error("secureMiddleware() | No valid certificate for HTTPS request | Host: %s | Path: %s | Error: %v", host, c.Request.URL.Path, err)
			log.Sync()
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err))
			c.Abort()
			return
		}

		// Security Headers
		err := security.Process(c.Writer, c.Request)
		if err != nil {
			log.Error("secureMiddleware() | An internal server error occurred while processing security. | Error: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("an internal server error occurred while processing security")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		c.Next()
	}
}
