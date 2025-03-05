package v1

import (
	"Back/internal/handlers"

	"github.com/gin-gonic/gin"
)

func RegisterPrivateRoutes(router *gin.RouterGroup) {
	router.GET("/get_countries", handlers.GetCountries())
	router.GET("/logs", handlers.GetLogs())
}
