package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/internal/utils"
	"net/http"
)

func Ping(c *gin.Context) {
	// TEST API
	c.JSON(http.StatusOK, utils.APIResponse{
		Success: true,
		Message: "pong",
	})
	return
}
