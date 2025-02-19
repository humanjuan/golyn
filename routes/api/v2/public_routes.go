package v2

import (
	"Back/app"
	"github.com/gin-gonic/gin"
)

func RegisterPublicRoutes(router *gin.RouterGroup, app *app.Application, serverInfo *app.Info) {
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Pong from API v2!"})
	})

}
