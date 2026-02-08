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
	router.GET("/sites/configurations", middlewares.GrantMiddleware("sites.view"), admin.GetSitesConfigurations())
	router.GET("/sites/:key/configuration", middlewares.GrantMiddleware("sites.view"), admin.GetSiteConfiguration())
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

	// Multi-site management
	router.GET("/users/:username/sites", middlewares.GrantMiddleware("users.manage"), admin.GetAdminManagedSites())
	router.POST("/users/:username/sites", middlewares.GrantMiddleware("users.manage"), admin.AssignSiteToAdmin())
	router.DELETE("/users/:username/sites/:key", middlewares.GrantMiddleware("users.manage"), admin.RevokeSiteFromAdmin())

	// Multi-tenant Isolation management
	router.GET("/users/:username/allowed-sites", middlewares.GrantMiddleware("users.manage"), admin.GetUserAllowedSites())
	router.POST("/users/:username/allowed-sites", middlewares.GrantMiddleware("users.manage"), admin.AssignAllowedSiteToUser())
	router.DELETE("/users/:username/allowed-sites/:key", middlewares.GrantMiddleware("users.manage"), admin.RemoveAllowedSiteFromUser())
	router.POST("/users/:username/remove-allowed-sites", middlewares.GrantMiddleware("users.manage"), admin.BulkRemoveSitesFromUser())
	router.POST("/sites/:key/allowed-users", middlewares.GrantMiddleware("users.manage"), admin.BulkAssignUsersToSite())
	router.POST("/sites/:key/remove-allowed-users", middlewares.GrantMiddleware("users.manage"), admin.BulkRemoveUsersFromSite())

	// System & Observability
	router.GET("/logs", middlewares.GrantMiddleware("system.logs"), admin.GetLogs())
	router.GET("/stats", middlewares.GrantMiddleware("system.stats"), admin.GetStats())
	router.GET("/info", middlewares.GrantMiddleware("system.info"), admin.GetInfo(serverInfo))
	router.GET("/server/configuration", middlewares.GrantMiddleware("system.config"), admin.GetServerConfiguration())

	// New Endpoints for Tokens, Sessions, Providers and Security
	router.GET("/tokens", middlewares.GrantMiddleware("tokens.view"), admin.ListAllAPIKeys())
	router.POST("/tokens", middlewares.GrantMiddleware("tokens.create"), admin.CreateAPIKey())
	router.DELETE("/tokens/:id", middlewares.GrantMiddleware("tokens.delete"), admin.RevokeAPIKey())

	router.GET("/sessions/active", middlewares.GrantMiddleware("sessions.view"), admin.GetActiveSessions())
	router.DELETE("/sessions/:id", middlewares.GrantMiddleware("sessions.delete"), admin.TerminateSession())

	router.GET("/auth/providers", middlewares.GrantMiddleware("system.config"), admin.GetAuthProviders())
	router.PUT("/auth/providers/:slug", middlewares.GrantMiddleware("system.config"), admin.UpdateAuthProvider())
	router.PATCH("/auth/providers/:slug/status", middlewares.GrantMiddleware("system.config"), admin.UpdateAuthProviderStatus())

	router.GET("/security/policies", middlewares.GrantMiddleware("system.config"), admin.GetSecurityPolicies())
}
