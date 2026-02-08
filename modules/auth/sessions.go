package auth

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"github.com/humanjuan/golyn/modules/admin"
)

// GetMySessions returns the sessions of the currently authenticated user
func GetMySessions() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		subject, _ := c.Get("subject")
		username := subject.(string)

		db := globals.GetDBInstance()

		// We need to get the user UUID first
		user, err := db.GetUserByUsername(username)
		if err != nil || user == nil {
			c.Error(utils.NewHTTPError(http.StatusNotFound, "user not found"))
			c.Abort()
			return
		}

		sessions, err := db.GetUserSessions(user.Id)
		if err != nil {
			log.Error("auth.GetMySessions() | Failed: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to list sessions"))
			c.Abort()
			return
		}

		dtos := make([]admin.SessionDTO, len(sessions))
		for i, s := range sessions {
			dtos[i] = admin.MapSessionToDTO(s)
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    dtos,
		})
	}
}

// TerminateMySession allows a user to close one of their own sessions
func TerminateMySession() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		subject, _ := c.Get("subject")
		username := subject.(string)

		idStr := c.Param("id")
		idValue, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid session id"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()

		// Security check: Verify the session belongs to the user
		user, err := db.GetUserByUsername(username)
		if err != nil || user == nil {
			c.Error(utils.NewHTTPError(http.StatusNotFound, "user not found"))
			c.Abort()
			return
		}

		// Verify session ownership
		var sessionExists bool
		checkQuery := "SELECT EXISTS(SELECT 1 FROM auth.refresh_tokens WHERE id = $1 AND user_id = $2)"
		err = db.QueryRow(c.Request.Context(), checkQuery, idValue, user.Id).Scan(&sessionExists)

		if err != nil || !sessionExists {
			log.Warn("auth.TerminateMySession() | Unauthorized or non-existent session access attempt | User: %s | SessionID: %d", username, idValue)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "you don't have permission to terminate this session"))
			c.Abort()
			return
		}

		err = db.RevokeRefreshTokenByID(idValue)
		if err != nil {
			log.Error("auth.TerminateMySession() | Failed: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to terminate session"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "session terminated successfully",
		})
	}
}
