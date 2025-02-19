package handlers

import (
	"Back/internal/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Ping(c *gin.Context) {
	// TEST API
	c.IndentedJSON(http.StatusOK, gin.H{
		"message": utils.GetCodeMessage(http.StatusOK),
		"data":    "pong",
	})
	return
}
