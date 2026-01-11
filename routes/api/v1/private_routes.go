package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/internal/handlers"
	"github.com/humanjuan/golyn/modules/auth"
)

func RegisterPrivateRoutes(router *gin.RouterGroup) {
	router.GET("/logs", handlers.GetLogs())
	router.GET("/auth/me", auth.GetMe())
}
