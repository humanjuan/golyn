package v1

import (
	"Back/app"
	"Back/internal/handlers"
	"Back/modules/auth"
	"github.com/gin-gonic/gin"
)

func RegisterPublicRoutes(router *gin.RouterGroup, app *app.Application, serverInfo *app.Info) {
	router.GET("/version", handlers.Version(serverInfo, app.LogApp))
	router.GET("/ping", handlers.Ping)
	router.POST("/login", auth.Login(app))
	router.POST("/refresh_token", auth.RefreshToken(app))
}
