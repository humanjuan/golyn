package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/modules/auth"
	"github.com/humanjuan/golyn/modules/user"
)

func RegisterPrivateRoutes(router *gin.RouterGroup) {
	router.GET("/auth/me", auth.GetMe())
	router.GET("/auth/sessions", auth.GetMySessions())
	router.DELETE("/auth/sessions/:id", auth.TerminateMySession())

	// User preferences
	router.GET("/user/theme", user.GetTheme())
	router.PUT("/user/theme", user.UpdateTheme())
}
