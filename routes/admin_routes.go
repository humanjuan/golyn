package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/modules/admin"
)

func RegisterAdminRoutes(router *gin.RouterGroup) {
	// Site management
	router.POST("/sites", admin.CreateSite())
	router.GET("/sites", admin.ListSites())

	// User management
	router.POST("/users", admin.CreateUser())
	router.GET("/users", admin.ListUsers())
}
