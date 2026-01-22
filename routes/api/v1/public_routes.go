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
	router.POST("/csp-report", handlers.CSPReportHandler)
	router.GET("/csrf-token", middlewares.GenerateCSRFToken)
	router.POST("/send-mail", middlewares.CSRFMiddleware(), middlewares.RateLimitMiddleware(), handlers.SendmailHandler())
	router.POST("/login", auth.Login())
	router.POST("/logout", auth.Logout())
	router.POST("/refresh_token", auth.RefreshToken())
	router.GET("/auth/azure/login", auth.OAuth2Login("azure"))
	router.GET("/auth/azure/callback", auth.OAuth2Callback("azure"))
	router.GET("/auth/google/login", auth.OAuth2Login("google"))
	router.GET("/auth/google/callback", auth.OAuth2Callback("google"))
	router.GET("/auth/github/login", auth.OAuth2Login("github"))
	router.GET("/auth/github/callback", auth.OAuth2Callback("github"))
}
