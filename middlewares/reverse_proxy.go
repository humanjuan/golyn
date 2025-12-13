package middlewares

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"golyn/globals"
	"golyn/internal/utils"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func ReverseProxyMiddleware(target string) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("ReverseProxyMiddleware()")
	return func(c *gin.Context) {
		proxyURL, err := url.Parse(target)
		if err != nil {
			log.Error("ReverseProxyMiddleware() | Error parsing target %s | Error: %v", target, err.Error())
			err := fmt.Errorf("error parsing target %s: %v", target, err)
			c.Error(utils.NewHTTPError(http.StatusBadGateway, err.Error()))
			c.Abort()
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(proxyURL)
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Ssl", "on")
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Real-IP", c.ClientIP())
			req.Header.Set("X-Forwarded-For", c.ClientIP())
		}

		proxy.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}
