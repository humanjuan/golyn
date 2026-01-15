package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/middlewares"
	"github.com/humanjuan/golyn/modules/admin"
)

func RegisterAdminRoutes(router *gin.RouterGroup, serverInfo *app.Info) {
	// Site management
	router.POST("/sites", admin.CreateSite())
	router.GET("/sites", admin.ListSites())
	router.DELETE("/sites/:key", admin.DeleteSite())
	router.PATCH("/sites/:key/status", admin.UpdateSiteStatus())

	// User management
	router.POST("/users", admin.CreateUser())
	router.GET("/users", admin.ListUsers())
	router.DELETE("/users/:username", admin.DeleteUser())
	router.PATCH("/users/:username/status", admin.UpdateUserStatus())
	router.PUT("/users/:username/role", admin.UpdateUserRole())

	// Permissions management
	router.GET("/users/:username/permissions", admin.GetUserPermissions())
	router.PUT("/users/:username/permissions", admin.UpdateUserPermissions())
	router.GET("/permissions/catalog", admin.GetPermissionsCatalog())

	// System & Observability
	router.GET("/logs", middlewares.SuperAdminMiddleware(), admin.GetLogs())
	router.GET("/stats", admin.GetStats())
	router.GET("/info", middlewares.SuperAdminMiddleware(), admin.GetInfo(serverInfo))
}
