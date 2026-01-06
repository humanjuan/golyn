package middlewares

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/humanjuan/golyn/globals"
	platjwt "github.com/humanjuan/golyn/internal/security/jwt"
	"github.com/humanjuan/golyn/internal/utils"
	"net/http"
	"strings"
)

func AuthMiddleware() gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("AuthMiddleware()")
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		host := c.Request.Host

		authHeader := c.GetHeader("Authorization")
		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
			log.Error("AuthMiddleware() | Invalid token format | ClientIP: %s | Host: %v | User Agent: %s", clientIP, host, userAgent)
			log.Sync()
			err := fmt.Errorf("invalid Authorization header format. Format is `Authorization: Bearer {token}`")
			c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
			c.Abort()
			return
		}

		tokenString := headerParts[1]

		claims := &platjwt.Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return platjwt.GetJWTKey(), nil
		})

		if err != nil {
			log.Error("AuthMiddleware() | Invalid token | ClientIP: %s | Host: %v | User Agent: %s | Error: %v",
				clientIP, host, userAgent, err.Error())
			log.Sync()
			err = fmt.Errorf("invalid token")
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, err.Error()))
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*platjwt.Claims); ok && token.Valid {
			c.Set("subject", claims.Subject)
			c.Set("site_id", claims.SiteID)
			c.Next()
		} else {
			log.Error("AuthMiddleware() | Invalid token claims | ClientIP: %s | Host: %s | User Agent: %s", clientIP, host, userAgent)
			log.Sync()
			err = fmt.Errorf("invalid token claims")
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, err.Error()))
			c.Abort()
			return
		}
	}
}
