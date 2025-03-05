package routes

import (
	"Back/app"
	"Back/middlewares"
	v1 "Back/routes/api/v1"
	v2 "Back/routes/api/v2"
	"github.com/gin-gonic/gin"
)

// ConfigureRoutes registra todas las rutas en el servidor
func ConfigureRoutes(router *gin.Engine, serverInfo *app.Info, mainDomain string) {
	//  ====== V1 ======
	v1Group := router.Group("/api/v1", middlewares.RestrictAPIRequestMiddleware(mainDomain))
	v1.RegisterPublicRoutes(v1Group, serverInfo)

	v1PrivateGroup := v1Group.Group("/", middlewares.RestrictAPIRequestMiddleware(mainDomain))
	v1PrivateGroup.Use(middlewares.AuthMiddleware())
	v1.RegisterPrivateRoutes(v1PrivateGroup)

	//  ====== V2 ======
	v2Group := router.Group("/api/v2", middlewares.RestrictAPIRequestMiddleware(mainDomain))
	v2.RegisterPublicRoutes(v2Group, serverInfo)

	v2PrivateGroup := v2Group.Group("/", middlewares.RestrictAPIRequestMiddleware(mainDomain))
	v2PrivateGroup.Use(middlewares.AuthMiddleware())
	v2.RegisterPrivateRoutes(v2PrivateGroup)

	//  ====== V1 ======
	/* v1Group := router.Group("/api/v1")
	v1.RegisterPublicRoutes(v1Group, serverInfo)

	v1PrivateGroup := v1Group.Group("/")
	v1PrivateGroup.Use(middlewares.AuthMiddleware())
	v1.RegisterPrivateRoutes(v1PrivateGroup)

	//  ====== V2 ======
	v2Group := router.Group("/api/v2")
	v2.RegisterPublicRoutes(v2Group, serverInfo)

	v2PrivateGroup := v2Group.Group("/")
	v2PrivateGroup.Use(middlewares.AuthMiddleware())
	v2.RegisterPrivateRoutes(v2PrivateGroup) */
}
