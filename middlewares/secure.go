package middlewares

import (
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"github.com/unrolled/secure"
	"net/http"
)

func SecureMiddleware(log *logger.Log, isDev bool) gin.HandlerFunc {
	log.Debug("setupSecureMiddleware()")
	security := secure.New(secure.Options{
		SSLRedirect:          true,
		SSLTemporaryRedirect: false,
		SSLProxyHeaders:      map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:           31536000,
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
			"img-src 'self' https://humanjuan.com https://www.humanjuan.com;",
	})

	return func(c *gin.Context) {
		log.Debug("Processing secure middleware")

		// Procesar encabezados de seguridad
		err := security.Process(c.Writer, c.Request)
		if err != nil {
			log.Error("setupSecureMiddleware() | Processing security middleware | Error: %v", err.Error())
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "request forbidden"})
			return
		}

		// Verificar si existen errores de seguridad
		if status := c.Writer.Status(); status > 299 && status < 200 {
			c.Abort()
			return
		}

		c.Next()
	}
}
