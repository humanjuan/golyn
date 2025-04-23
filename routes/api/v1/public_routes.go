package v1

import (
	"Back/app"
	"Back/internal/handlers"
	"Back/middlewares"
	"Back/modules/auth"
	"github.com/gin-gonic/gin"
)

func RegisterPublicRoutes(router *gin.RouterGroup, serverInfo *app.Info) {
	router.GET("/version", handlers.Version(serverInfo))
	router.GET("/ping", handlers.Ping)
	router.GET("/csrf-token", middlewares.GenerateCSRFToken)
	router.POST("/login", auth.Login())
	router.POST("/refresh_token", auth.RefreshToken())
	router.POST("/send-mail", middlewares.CSRFMiddleware(), middlewares.RateLimitMiddleware(), handlers.SendmailHandler())
}
