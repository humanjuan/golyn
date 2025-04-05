package middlewares

import (
	"Back/globals"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func ReverseProxyMiddleware(target string) gin.HandlerFunc {
	log := globals.GetAppLogger()
	return func(c *gin.Context) {
		proxyURL, err := url.Parse(target)
		if err != nil {
			log.Error("ReverseProxy | Error parsing target %s: %v", target, err)
			c.AbortWithStatus(http.StatusBadGateway)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(proxyURL)
		proxy.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}
