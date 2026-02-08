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
	router.GET("/auth/providers", auth.ListPublicAuthProviders())
	router.GET("/auth/azure/login", auth.OAuth2Login("azure"))
	router.GET("/auth/azure/callback", auth.OAuth2Callback("azure"))
	router.GET("/auth/google/login", auth.OAuth2Login("google"))
	router.GET("/auth/google/callback", auth.OAuth2Callback("google"))
	router.GET("/auth/facebook/login", auth.OAuth2Login("facebook"))
	router.GET("/auth/facebook/callback", auth.OAuth2Callback("facebook"))
	router.GET("/auth/github/login", auth.OAuth2Login("github"))
	router.GET("/auth/github/callback", auth.OAuth2Callback("github"))
	router.GET("/auth/apple/login", auth.OAuth2Login("apple"))
	router.GET("/auth/apple/callback", auth.OAuth2Callback("apple"))
	router.GET("/auth/amazon/login", auth.OAuth2Login("amazon"))
	router.GET("/auth/amazon/callback", auth.OAuth2Callback("amazon"))
	router.GET("/auth/linkedin/login", auth.OAuth2Login("linkedin"))
	router.GET("/auth/linkedin/callback", auth.OAuth2Callback("linkedin"))
	router.GET("/auth/x/login", auth.OAuth2Login("x"))
	router.GET("/auth/x/callback", auth.OAuth2Callback("x"))
	router.GET("/auth/oidc/login", auth.OAuth2Login("oidc"))
	router.GET("/auth/oidc/callback", auth.OAuth2Callback("oidc"))
	router.GET("/privacy/facebook/deletion", handlers.FacebookDeletionHandler)
	router.POST("/privacy/facebook/deletion", handlers.FacebookDeletionHandler)
}
