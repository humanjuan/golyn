package v1

import (
	"Back/app"
	"Back/internal/handlers"

	"github.com/gin-gonic/gin"
)

func RegisterPrivateRoutes(router *gin.RouterGroup, app *app.Application) {
	router.GET("/get_countries", handlers.GetCountries(app))
	router.GET("/logs", handlers.GetLogs(app))
}
