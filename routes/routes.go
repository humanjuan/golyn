package routes

import (
	"github.com/gin-gonic/gin"
	"golyn/app"
	"golyn/middlewares"
	v1 "golyn/routes/api/v1"
	v2 "golyn/routes/api/v2"
)

// ConfigureRoutes registra todas las rutas en el servidor
func ConfigureRoutes(router *gin.Engine, serverInfo *app.Info, mainDomain string, dev bool) {
	//  ====== V1 ======
	v1Group := router.Group("/api/v1", middlewares.RestrictAPIRequestMiddleware(mainDomain, dev))
	v1.RegisterPublicRoutes(v1Group, serverInfo)

	v1PrivateGroup := v1Group.Group("/", middlewares.RestrictAPIRequestMiddleware(mainDomain, dev))
	v1PrivateGroup.Use(middlewares.AuthMiddleware())
	v1.RegisterPrivateRoutes(v1PrivateGroup)

	//  ====== V2 ======
	v2Group := router.Group("/api/v2", middlewares.RestrictAPIRequestMiddleware(mainDomain, dev))
	v2.RegisterPublicRoutes(v2Group, serverInfo)

	v2PrivateGroup := v2Group.Group("/", middlewares.RestrictAPIRequestMiddleware(mainDomain, dev))
	v2PrivateGroup.Use(middlewares.AuthMiddleware())
	v2.RegisterPrivateRoutes(v2PrivateGroup)
}
