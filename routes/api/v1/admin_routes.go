package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/middlewares"
	"github.com/humanjuan/golyn/modules/admin"
)

func RegisterAdminRoutes(router *gin.RouterGroup, serverInfo *app.Info) {
	// Site management
	router.POST("/sites", middlewares.GrantMiddleware("sites.create"), admin.CreateSite())
	router.GET("/sites", middlewares.GrantMiddleware("sites.view"), admin.ListSites())
	router.DELETE("/sites/:key", middlewares.GrantMiddleware("sites.delete"), admin.DeleteSite())
	router.PATCH("/sites/:key/status", middlewares.GrantMiddleware("sites.update"), admin.UpdateSiteStatus())

	// User management
	router.POST("/users", middlewares.GrantMiddleware("users.create"), admin.CreateUser())
	router.GET("/users", middlewares.GrantMiddleware("users.view"), admin.ListUsers())
	router.DELETE("/users/:username", middlewares.GrantMiddleware("users.delete"), admin.DeleteUser())
	router.PATCH("/users/:username/status", middlewares.GrantMiddleware("users.update"), admin.UpdateUserStatus())
	router.PUT("/users/:username/role", middlewares.GrantMiddleware("users.manage"), admin.UpdateUserRole())

	// Permissions management
	router.GET("/users/:username/permissions", middlewares.GrantMiddleware("users.manage"), admin.GetUserPermissions())
	router.PUT("/users/:username/permissions", middlewares.GrantMiddleware("users.manage"), admin.UpdateUserPermissions())
	router.GET("/permissions/catalog", middlewares.GrantMiddleware("users.manage"), admin.GetPermissionsCatalog())

	// System & Observability
	router.GET("/logs", middlewares.GrantMiddleware("system.logs"), admin.GetLogs())
	router.GET("/stats", middlewares.GrantMiddleware("system.stats"), admin.GetStats())
	router.GET("/info", middlewares.GrantMiddleware("system.info"), admin.GetInfo(serverInfo))
}
