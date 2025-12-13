package v2

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
)

func RegisterPublicRoutes(router *gin.RouterGroup, serverInfo *app.Info) {
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Pong from API v2!"})
	})

}
