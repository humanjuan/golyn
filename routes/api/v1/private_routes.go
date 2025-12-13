package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/internal/handlers"
)

func RegisterPrivateRoutes(router *gin.RouterGroup) {
	router.GET("/get_countries", handlers.GetCountries())
	router.GET("/logs", handlers.GetLogs())
}
