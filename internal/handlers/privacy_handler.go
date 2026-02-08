package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// FacebookDeletionHandler returns a stub response for Facebook's data deletion request.
// It complies with Facebook's requirement for a 200 OK response at a specific URL.
func FacebookDeletionHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}
