package middlewares

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/handlers"
	"github.com/humanjuan/golyn/internal/utils"
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
				c.JSON(status, utils.APIResponse{
					Success: false,
					Message: message,
					Error:   utils.GetCodeMessage(status),
				})
			} else {
				c.Writer.Header().Set("X-Request-Path", c.Request.URL.Path)
				if err := handlers.RenderError(c.Writer, status, message); err != nil {
					c.AbortWithStatus(status)
				}
			}
			c.Abort()
		}
	}
}
