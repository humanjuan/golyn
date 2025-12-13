package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/internal/handlers"
	"github.com/humanjuan/golyn/middlewares"
	"github.com/humanjuan/golyn/modules/auth"
)

func RegisterPublicRoutes(router *gin.RouterGroup, serverInfo *app.Info) {
	router.GET("/version", handlers.Version(serverInfo))
	router.GET("/ping", handlers.Ping)
	router.GET("/csrf-token", middlewares.GenerateCSRFToken)
	router.POST("/login", auth.Login())
	router.POST("/refresh_token", auth.RefreshToken())
	router.POST("/send-mail", middlewares.CSRFMiddleware(), middlewares.RateLimitMiddleware(), handlers.SendmailHandler())
}
