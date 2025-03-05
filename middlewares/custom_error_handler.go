package middlewares

import (
	"Back/globals"
	"Back/internal/handlers"
	"Back/internal/utils"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func CustomErrorHandler() gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("CustomErrorHandler()")
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			lastError := c.Errors.Last()
			status := http.StatusInternalServerError
			message := utils.GetCodeMessage(http.StatusInternalServerError)

			var httpError *utils.HTTPError
			ok := errors.As(lastError.Err, &httpError)
			if ok {
				status = httpError.Code
				message = httpError.Message
			} else {
				message = lastError.Err.Error()
			}

			isAPI := strings.HasPrefix(c.Request.URL.Path, "/api/")

			if isAPI || !globals.RenderTemplate {
				c.IndentedJSON(status, gin.H{
					"message": message,
					"error":   utils.GetCodeMessage(status),
				})
			} else {
				if err := handlers.RenderError(c.Writer, status, message); err != nil {
					c.AbortWithStatus(status)
				}
			}
			c.Abort()
		}
	}
}
