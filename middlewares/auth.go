package middlewares

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jpengineer/logger"
	"net/http"
	"strings"
)

// openssl rand -base64 32
var jwtKey = []byte("x5qFH80ULkKFOBiZnYhW/v2u8sWI5F3ro1wOEE5gm0I=")

func AuthMiddleware(log *logger.Log) gin.HandlerFunc {
	log.Debug("AuthMiddleware()")
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		host := c.Request.Host

		authHeader := c.GetHeader("Authorization")
		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
			log.Error("Authentication | Invalid token format | ClientIP: %s | Host: %v | User Agent: %s", clientIP, host, userAgent)
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Invalid Authorization header format. Format is `Authorization: Bearer {token}`"})
			c.Abort()
			return
		}

		tokenString := headerParts[1]

		token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			log.Error("Authentication | Invalid token | ClientIP: %s | Host: %v | User Agent: %s | Error: %v",
				clientIP, host, userAgent, err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
			c.Set("username", claims.Subject)
			c.Next()
		} else {
			log.Error("Authentication | Invalid token claims | ClientIP: %s | Host: %s | User Agent: %s", clientIP, host, userAgent)
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Invalid token claims"})
			c.Abort()
			return
		}
	}
}
