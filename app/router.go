package app

import "github.com/gin-gonic/gin"

var router *gin.Engine

// SetRouter sets the main Gin router.
// Called once during server initialization.
func SetRouter(r *gin.Engine) {
	router = r
}

// GetRouter returns the main Gin router if available.
func GetRouter() *gin.Engine {
	return router
}
