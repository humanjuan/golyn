package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/middlewares"
	v1 "github.com/humanjuan/golyn/routes/api/v1"
	v2 "github.com/humanjuan/golyn/routes/api/v2"
)

// ConfigureRoutes sets up all API endpoints
func ConfigureRoutes(router *gin.Engine, serverInfo *app.Info, mainDomain string, dev bool) {
	//  ====== V1 API ======
	v1Group := router.Group("/api/v1", middlewares.RestrictAPIRequestMiddleware(dev))
	{
		// Public
		v1.RegisterPublicRoutes(v1Group, serverInfo)

		// Private
		v1PrivateGroup := v1Group.Group("/", middlewares.AuthMiddleware(), middlewares.CSRFMiddleware())
		{
			v1.RegisterPrivateRoutes(v1PrivateGroup)

			// Admin
			adminGroup := v1PrivateGroup.Group("/admin", middlewares.RestrictAdminHostMiddleware(mainDomain, dev))
			v1.RegisterAdminRoutes(adminGroup, serverInfo)
		}
	}

	//  ====== V2 API ======
	v2Group := router.Group("/api/v2", middlewares.RestrictAPIRequestMiddleware(dev))
	{
		// Public
		v2.RegisterPublicRoutes(v2Group, serverInfo)

		// Private
		v2PrivateGroup := v2Group.Group("/", middlewares.AuthMiddleware(), middlewares.CSRFMiddleware())
		{
			v2.RegisterPrivateRoutes(v2PrivateGroup)
		}
	}
}
