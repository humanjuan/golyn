package v1

import (
	"Back/app"
	"Back/internal/handlers"
	"Back/modules/auth"
	"github.com/gin-gonic/gin"
)

func RegisterPublicRoutes(router *gin.RouterGroup, serverInfo *app.Info) {
	router.GET("/version", handlers.Version(serverInfo))
	router.GET("/ping", handlers.Ping)
	router.POST("/login", auth.Login())
	router.POST("/refresh_token", auth.RefreshToken())
}
