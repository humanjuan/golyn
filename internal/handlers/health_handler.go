package handlers

import (
	"github.com/gin-gonic/gin"
	"golyn/internal/utils"
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
